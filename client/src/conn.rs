//! 一条 WebSocket 连接：登录（`hello`）、请求 / 回执按编号配对、服务器推送转给处理任务、每 30 秒保活。
//!
//! 读任务从不因为推送阻塞：推送放进有界队列，满了就断开，让上层重连后按序号补拉（与服务器的做法一致），
//! 所以等回执的请求不会被积压的推送卡死。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use friend_im_core::keys::DeviceSecret;
use friend_im_core::limits;
use friend_im_core::wire::{self, ClientFrame, HelloAuth, Push, Request, Response, ServerFrame, Welcome, WireError};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::error::{ClientError, Result};

/// 连上并登录的超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// 一个请求等回执的超时。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// 保活间隔（服务器 90 秒没收到东西就断开）。
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// 发送队列。
const OUTBOX: usize = 256;

type Waiter = oneshot::Sender<std::result::Result<Response, WireError>>;

#[derive(Default)]
struct Pending {
    waiters: HashMap<u64, Waiter>,
    closed: bool,
}

/// 一条已登录的连接。
pub(crate) struct Conn {
    out: mpsc::Sender<String>,
    pending: Arc<Mutex<Pending>>,
    next_id: Arc<AtomicU64>,
    stop: watch::Sender<bool>,
}

/// 连上的结果。
pub(crate) struct Connected {
    pub conn: Arc<Conn>,
    pub welcome: Welcome,
    /// 按第一帧里的服务器时间认下的服务器的钟。
    pub clock: crate::state::ServerClock,
    /// 服务器推送；连接断开时关闭。
    pub pushes: mpsc::Receiver<Push>,
}

fn text_of(message: Message) -> Option<String> {
    match message {
        Message::Text(text) => Some(text.to_string()),
        _ => None,
    }
}

/// 连上服务器并登录。
pub(crate) async fn connect(url: &str, auth: HelloAuth, device: &DeviceSecret, name: &str) -> Result<Connected> {
    tokio::time::timeout(CONNECT_TIMEOUT, connect_inner(url, auth, device, name))
        .await
        .map_err(|_| ClientError::Timeout)?
}

async fn connect_inner(url: &str, auth: HelloAuth, device: &DeviceSecret, name: &str) -> Result<Connected> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(limits::CLIENT_FRAME_MAX_BYTES))
        .max_frame_size(Some(limits::CLIENT_FRAME_MAX_BYTES));
    let (socket, _) = tokio_tungstenite::connect_async_with_config(url, Some(config), true).await.map_err(|error| {
        tracing::info!(%error, "连不上服务器");
        ClientError::Disconnected
    })?;
    let (mut sink, mut stream) = socket.split();

    // 1. 服务器先发一次性随机数。
    let challenge = loop {
        let message = stream.next().await.ok_or(ClientError::Disconnected)?.map_err(|_| ClientError::Disconnected)?;
        if let Some(text) = text_of(message) {
            break serde_json::from_str::<ServerFrame>(&text).map_err(|_| ClientError::protocol("第一帧读不懂"))?;
        }
    };
    let ServerFrame::Challenge { protocol, nonce, server_time_ms } = challenge else {
        return Err(ClientError::protocol("第一帧应是随机数"));
    };
    let clock = crate::state::ServerClock::from_challenge(server_time_ms, crate::state::now_ms());
    if protocol != wire::PROTOCOL_VERSION {
        return Err(ClientError::protocol(format!("服务器接口版本是 {protocol}，客户端是 {}", wire::PROTOCOL_VERSION)));
    }

    // 2. 登录：对随机数签名，证明电脑私钥在手里。
    let hello = ClientFrame {
        id: 1,
        req: Request::Hello {
            protocol: wire::PROTOCOL_VERSION,
            auth,
            device: device.public(),
            name: name.to_owned(),
            sig: wire::sign_hello(device, &nonce),
        },
    };
    let text = serde_json::to_string(&hello).map_err(|_| ClientError::protocol("登录请求写不出"))?;
    sink.send(Message::Text(text.into())).await.map_err(|_| ClientError::Disconnected)?;
    let mut early = Vec::new();
    let welcome = loop {
        let message = stream.next().await.ok_or(ClientError::Disconnected)?.map_err(|_| ClientError::Disconnected)?;
        let Some(text) = text_of(message) else { continue };
        match serde_json::from_str::<ServerFrame>(&text).map_err(|_| ClientError::protocol("登录回执读不懂"))? {
            ServerFrame::Res {
                id: 1,
                res: Response::Welcome { welcome },
            } => break welcome,
            ServerFrame::Err { id: 1, err } => return Err(ClientError::Server(err)),
            ServerFrame::Push { push } => early.push(push),
            _ => return Err(ClientError::protocol("登录回执不对")),
        }
    };

    // 3. 读写分开跑。
    let (out, mut outbox) = mpsc::channel::<String>(OUTBOX);
    let (push_tx, pushes) = mpsc::channel::<Push>(limits::PUSH_QUEUE * 2);
    for push in early {
        let _ = push_tx.try_send(push);
    }
    let pending = Arc::new(Mutex::new(Pending::default()));
    let next_id = Arc::new(AtomicU64::new(2));
    let (stop, mut stop_rx) = watch::channel(false);

    let ping_id = next_id.clone();
    tokio::spawn(async move {
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;
        loop {
            tokio::select! {
                next = outbox.recv() => {
                    let Some(text) = next else { break };
                    if sink.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                _ = ping.tick() => {
                    // 保活的回执没人等，读任务找不到对应的等待者就丢掉。
                    let frame = ClientFrame { id: ping_id.fetch_add(1, Ordering::Relaxed), req: Request::Ping };
                    let Ok(text) = serde_json::to_string(&frame) else { continue };
                    if sink.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                _ = stop_rx.changed() => break,
            }
        }
        let _ = sink.close().await;
    });

    let reader_pending = pending.clone();
    let reader_stop = stop.clone();
    tokio::spawn(async move {
        while let Some(Ok(message)) = stream.next().await {
            let Some(text) = text_of(message) else {
                continue;
            };
            let Ok(frame) = serde_json::from_str::<ServerFrame>(&text) else {
                tracing::warn!("服务器发来读不懂的一帧，断开重连");
                break;
            };
            match frame {
                ServerFrame::Res { id, res } => resolve(&reader_pending, id, Ok(res)),
                ServerFrame::Err { id, err } => resolve(&reader_pending, id, Err(err)),
                ServerFrame::Push { push } => {
                    if push_tx.try_send(push).is_err() {
                        tracing::warn!("推送积压太多，断开重连后按序号补拉");
                        break;
                    }
                }
                ServerFrame::Challenge { .. } => {}
            }
        }
        // 连接结束：等回执的请求一律按“没连上”失败，推送队列随 push_tx 释放而关闭。
        let mut pending = reader_pending.lock().unwrap_or_else(|p| p.into_inner());
        pending.closed = true;
        pending.waiters.clear();
        drop(pending);
        let _ = reader_stop.send(true);
    });

    Ok(Connected {
        clock,
        conn: Arc::new(Conn { out, pending, next_id, stop }),
        welcome,
        pushes,
    })
}

fn resolve(pending: &Mutex<Pending>, id: u64, result: std::result::Result<Response, WireError>) {
    let waiter = pending.lock().unwrap_or_else(|p| p.into_inner()).waiters.remove(&id);
    if let Some(waiter) = waiter {
        let _ = waiter.send(result);
    }
}

impl Conn {
    /// 发一个请求并等回执。
    pub(crate) async fn request(&self, req: Request) -> Result<Response> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            if pending.closed {
                return Err(ClientError::Disconnected);
            }
            pending.waiters.insert(id, tx);
        }
        let text = serde_json::to_string(&ClientFrame { id, req }).map_err(|_| ClientError::protocol("请求写不出"))?;
        if text.len() > limits::FRAME_MAX_BYTES {
            self.forget(id);
            return Err(ClientError::state("请求太大"));
        }
        if self.out.send(text).await.is_err() {
            self.forget(id);
            return Err(ClientError::Disconnected);
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(Ok(response))) => Ok(response),
            Ok(Ok(Err(error))) => Err(ClientError::Server(error)),
            Ok(Err(_)) => Err(ClientError::Disconnected),
            Err(_) => {
                self.forget(id);
                Err(ClientError::Timeout)
            }
        }
    }

    fn forget(&self, id: u64) {
        self.pending.lock().unwrap_or_else(|p| p.into_inner()).waiters.remove(&id);
    }

    /// 主动断开。
    pub(crate) fn close(&self) {
        let _ = self.stop.send(true);
    }

    /// 连接是否已经断了。
    pub(crate) fn is_closed(&self) -> bool {
        self.pending.lock().unwrap_or_else(|p| p.into_inner()).closed || *self.stop.borrow()
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

//! 会话（protocol-v1 §4.2、§6）：用 HHH 交还的凭据连上服务器，在线期间的客户端、名字与会话资料的缓存，退出与下线。
//!
//! 这一版没有登录：没有凭据、凭据失效、换了服务器地址时都回 `needsLogin`，由下一阶段的“用 Cindy 账号自动登录”接上。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use friend_im_client::core::conv::ConvKind;
use friend_im_client::core::ids::{ConvId, Uid};
use friend_im_client::core::wire::{DeviceStatus, ErrorCode};
use friend_im_client::{Client, ClientError, Config};
use hhh_im_protocol::method::{NeedsLoginReason, SessionOpenParams, SessionOpenResult};
use hhh_im_protocol::rpc::{ErrorKind, RpcError};
use hhh_im_protocol::types::{Account, Conversation, ConversationKind};
use serde_json::Value;
use tokio::task::AbortHandle;

use super::declare::{DEFAULT_SERVER, SETTING_SERVER};
use super::translate::Names;
use super::{Server, errors, push};
use crate::credential::{self, Credential};

/// 名字、会话资料缓存的条数上限：满了整个清空、按需重取（1000 个账号的规模下很少发生）。
const CACHE_MAX: usize = 4096;
/// 最近见过的消息（撤回推来时找原来那条的时间与发送人）记多少条。
const RECENT_MAX: usize = 4096;

/// 最近见过的消息：编号 → （发送人，服务器时间），以及记下的先后（满了丢最早的）。
#[derive(Default)]
struct Recent {
    seen: HashMap<String, (Uid, i64)>,
    order: std::collections::VecDeque<String>,
}

/// 在线的账号。
pub(crate) struct Live {
    pub(crate) client: Client,
    pub(crate) me: Uid,
    /// 是否借来的凭据（不能存新的）。
    pub(crate) read_only: bool,
    names: Mutex<Names>,
    convs: Mutex<HashMap<ConvId, Conversation>>,
    recent: Mutex<Recent>,
    /// 推送的两个后台任务（翻译更新、推给宿主），下线时停掉。
    tasks: Mutex<Vec<AbortHandle>>,
}

impl Live {
    /// 这些账号的名字：缓存里没有的一次向服务器取（取不到的就没有，显示时写“有人”）。
    pub(crate) async fn names(&self, uids: impl IntoIterator<Item = Uid>) -> Names {
        let mut wanted: Vec<Uid> = uids.into_iter().collect();
        wanted.sort();
        wanted.dedup();
        let missing: Vec<Uid> = {
            let names = self.names.lock().expect("名字缓存锁中毒");
            wanted.iter().filter(|u| !names.contains_key(*u)).cloned().collect()
        };
        if !missing.is_empty() {
            match self.client.profiles(&missing).await {
                Ok(found) => {
                    let mut names = self.names.lock().expect("名字缓存锁中毒");
                    if names.len() + found.len() > CACHE_MAX {
                        names.clear();
                    }
                    names.extend(found.into_iter().map(|p| (p.uid, p.name)));
                }
                Err(error) => tracing::info!(%error, count = missing.len(), "取名字没成，先不显示名字"),
            }
        }
        let names = self.names.lock().expect("名字缓存锁中毒");
        wanted.into_iter().filter_map(|u| names.get(&u).map(|n| (u, n.clone()))).collect()
    }

    /// 会话资料（缓存过就直接给）：群名是解开的群资料里的名字，私聊用对方的名字。
    pub(crate) async fn conversation(&self, conv: &ConvId) -> Result<Conversation, ClientError> {
        if let Some(found) = self.convs.lock().expect("会话缓存锁中毒").get(conv) {
            return Ok(found.clone());
        }
        let info = self.client.conv_info(conv).await?;
        let built = match info.kind {
            ConvKind::Group => {
                let name = match self.client.group_profile(conv).await {
                    Ok(profile) => profile.map(|p| p.name).filter(|n| !n.trim().is_empty()),
                    Err(error) => {
                        tracing::info!(%conv, %error, "群资料解不开，先叫“群聊”");
                        None
                    }
                };
                Conversation {
                    id: conv.to_string(),
                    kind: ConversationKind::Group,
                    name: name.unwrap_or_else(|| "群聊".into()),
                    avatar: None,
                    peer: None,
                    private: false,
                }
            }
            ConvKind::Dm => {
                let peer = info.members.iter().map(|m| m.uid.clone()).find(|u| *u != self.me);
                let name = match &peer {
                    Some(peer) => self.names([peer.clone()]).await.remove(peer),
                    None => None,
                };
                Conversation {
                    id: conv.to_string(),
                    kind: ConversationKind::Direct,
                    name: name.unwrap_or_else(|| "私聊".into()),
                    avatar: None,
                    peer: peer.map(|p| p.to_string()),
                    private: false,
                }
            }
        };
        let mut convs = self.convs.lock().expect("会话缓存锁中毒");
        if convs.len() >= CACHE_MAX {
            convs.clear();
        }
        convs.insert(conv.clone(), built.clone());
        Ok(built)
    }

    /// 会话变了（建群、进出群、改群资料）：下次重新取。
    pub(crate) fn forget_conversation(&self, conv: &ConvId) {
        self.convs.lock().expect("会话缓存锁中毒").remove(conv);
    }

    /// 是否已经知道这个会话（推送新会话的消息前先推会话本身）。
    pub(crate) fn knows_conversation(&self, conv: &ConvId) -> bool {
        self.convs.lock().expect("会话缓存锁中毒").contains_key(conv)
    }

    /// 记下一条见过的消息。
    pub(crate) fn remember(&self, id: &str, sender: &Uid, ts_ms: i64) {
        let mut recent = self.recent.lock().expect("最近消息锁中毒");
        if recent.seen.insert(id.to_owned(), (sender.clone(), ts_ms)).is_none() {
            recent.order.push_back(id.to_owned());
            if recent.order.len() > RECENT_MAX
                && let Some(old) = recent.order.pop_front()
            {
                recent.seen.remove(&old);
            }
        }
    }

    /// 最近见过的某条消息的发送人与时间。
    pub(crate) fn recalled_from(&self, id: &str) -> Option<(Uid, i64)> {
        self.recent.lock().expect("最近消息锁中毒").seen.get(id).cloned()
    }

    /// 停掉推送任务，断开服务器。
    pub(crate) fn close(&self) {
        for task in self.tasks.lock().expect("任务表锁中毒").drain(..) {
            task.abort();
        }
        self.client.close();
    }
}

/// 读 `session/open` 的服务器地址设置（没给用默认值）。
fn server_setting(params: &SessionOpenParams) -> Result<String, RpcError> {
    let raw = params.settings.get(SETTING_SERVER).map_or(DEFAULT_SERVER, String::as_str);
    credential::server_url(raw).ok_or_else(|| errors::of(ErrorKind::InvalidRequest, format!("服务器地址不对：{raw}（要 https 网址）")))
}

fn needs_login(reason: NeedsLoginReason, message: &str) -> Result<Value, RpcError> {
    Ok(serde_json::to_value(SessionOpenResult::NeedsLogin { reason, message: message.into() }).expect("结果总能写成 JSON"))
}

impl Server {
    /// 在线的账号；没上线时回“还没连上”。
    pub(crate) async fn live(&self) -> Result<Arc<Live>, RpcError> {
        self.state.read().await.clone().ok_or_else(errors::offline)
    }

    /// 下线：停掉推送、断开服务器。
    pub(crate) async fn close_session(&self) {
        if let Some(live) = self.state.write().await.take() {
            live.close();
        }
    }

    /// `session/open`：用凭据连上服务器。
    pub(crate) async fn session_open(self: &Arc<Self>, params: SessionOpenParams) -> Result<Value, RpcError> {
        self.close_session().await;
        let server = server_setting(&params)?;
        let Some(text) = params.credential.as_deref() else {
            return needs_login(NeedsLoginReason::NoCredential, "这一版的 Friend-IM 还不能在 Friend 里登录，下一版用 Cindy 账号自动登录。");
        };
        let Some(saved) = Credential::decode(text) else {
            tracing::warn!("凭据读不懂（格式或版本不对），要重新登录");
            return needs_login(NeedsLoginReason::CredentialInvalid, "Friend-IM 的登录信息读不懂了，要重新登录。");
        };
        if saved.server != server {
            tracing::info!(saved = %saved.server, setting = %server, "服务器地址改了，要重新登录");
            return needs_login(NeedsLoginReason::CredentialInvalid, &format!("服务器地址改成了 {server}，要在新服务器上重新登录。"));
        }
        let position = params.sync_state.as_deref().and_then(|s| s.parse::<u64>().ok());
        let config = Config { server: server.clone(), device_name: saved.device_name.clone() };
        let (client, updates) = match Client::connect(config, saved.device.clone(), None, position).await {
            Ok(connected) => connected,
            Err(error) => {
                return match error.code() {
                    Some(ErrorCode::Unauthorized) => needs_login(NeedsLoginReason::Expired, "Friend-IM 的登录已失效，要重新登录。"),
                    Some(ErrorCode::DeviceRemoved) => needs_login(NeedsLoginReason::Revoked, "这台电脑已被移出你的 Friend-IM 账号，要重新登录。"),
                    Some(ErrorCode::NotApproved) => needs_login(NeedsLoginReason::CredentialInvalid, "这台电脑还没被批准加入 Friend-IM 账号。"),
                    _ => {
                        tracing::info!(%error, "连不上服务器");
                        Err(errors::client(&error))
                    }
                };
            }
        };
        let me = client.uid().clone();
        let status = client.status().await;
        if me.as_str() != saved.uid || status != DeviceStatus::Active {
            tracing::warn!(?status, "凭据的账号对不上，或这台电脑还不能用");
            client.close();
            return needs_login(NeedsLoginReason::CredentialInvalid, "这台电脑还没开通或还没被批准，要重新登录。");
        }
        let account = Account { id: me.to_string(), id_type: None, name: client.name().await, avatar: None, tenant: None };
        let live = Arc::new(Live {
            client,
            me,
            read_only: params.credential_read_only,
            names: Mutex::new(Names::new()),
            convs: Mutex::new(HashMap::new()),
            recent: Mutex::new(Default::default()),
            tasks: Mutex::new(Vec::new()),
        });
        let tasks = push::start(self.clone(), live.clone(), updates, saved);
        live.tasks.lock().expect("任务表锁中毒").extend(tasks);
        *self.state.write().await = Some(live);
        tracing::info!("Friend-IM 已上线");
        Ok(serde_json::to_value(SessionOpenResult::Online { account, adopted_settings: None }).expect("结果总能写成 JSON"))
    }

    /// `session/logout`：这台电脑退出 Friend-IM（从“我的电脑”里移除，契约 S22），再下线。
    pub(crate) async fn session_logout(&self) -> Result<Value, RpcError> {
        if let Ok(live) = self.live().await
            && let Err(error) = live.client.logout().await
        {
            tracing::info!(%error, "退出登录时没连上服务器，只在本机下线");
        }
        self.close_session().await;
        Ok(serde_json::json!({}))
    }
}

//! 示例 IM：HHH IM 插件的最小可用骨架（HHH-IM-Protocol v1，规范见 hhh-im-sdk 的 docs/protocol-v1.md）。
//!
//! 插件是一个子进程：HHH 从标准输入一行一条发 JSON-RPC 请求，插件从标准输出一行一条回；日志走 `log/write` 通知，
//! 不要往标准输出打别的东西。这个示例：
//! - `initialize`：报协议版本、插件信息、平台说明与能力（只推一次的平台：`history = none`，消息全靠推送）；
//! - `session/open`：不用登录，直接在线，账号是“示例账号”；在线后推一个“示例群”和一条欢迎消息；
//! - `messages/send`：你在 HHH 里发的消息照收，再以“示例机器人”引用原话回一句“收到「…」”；
//! - 别的方法回“不支持”。
//!
//! 改成真的 IM 时：把这些换成和你的平台说话、把平台的格式翻成协议的统一格式；聊天记录、凭据、配置都交给 HHH，
//! 插件自己不存（见 AGENTS.md）。

// Windows：按窗口程序编，桌面宿主拉起时不弹控制台窗口；标准输入输出照样走宿主接好的管道。
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::io::{BufRead, Write};

use hhh_im_protocol::types::{Block, Conversation, ConversationKind, Event, Message, SendOutcome, Sender, SenderKind};
use hhh_im_protocol::{ErrorKind, RpcError, RpcId, RpcMessage, codec};
use serde_json::{Value, json};

/// 示例群的会话编号。
const DEMO_CHAT: &str = "demo-chat";
/// 示例账号（你自己）与示例机器人的编号。
const ME: &str = "demo-user";
const BOT: &str = "demo-bot";

struct Plugin {
    /// 发给宿主的请求（推送）的编号，从 1 起。
    next_id: i64,
    /// 同步游标：只推一次的平台每批推送都带上，宿主落库后才确认（这里就是推送的批次数）。
    batches: u64,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 写一行到标准输出（一条消息一行）。
fn send(message: &RpcMessage) {
    let Ok(line) = codec::encode_line(message) else {
        return;
    };
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
}

/// 日志交给宿主（写进 HHH 的日志），不打到标准输出。
fn log(level: &str, message: &str) {
    send(&RpcMessage::notification("log/write", json!({ "level": level, "message": message })));
}

fn text_message(id: String, from: &str, name: &str, kind: SenderKind, text: &str) -> Message {
    Message {
        id,
        conversation_id: DEMO_CHAT.into(),
        sender: Sender {
            id: from.into(),
            kind,
            name: Some(name.into()),
        },
        created_at_ms: now_ms(),
        updated_at_ms: None,
        edited_at_ms: None,
        deleted: false,
        incomplete: false,
        content: vec![Block::Text { text: text.into() }],
        reply_to: None,
        thread: None,
        reactions: None,
        raw: None,
    }
}

impl Plugin {
    /// 推一批事件给宿主（`events/push`），带上同步游标。
    fn push(&mut self, events: Vec<Event>) {
        self.batches += 1;
        let id = RpcId::Number(self.next_id);
        self.next_id += 1;
        let params = json!({ "events": events, "syncState": self.batches.to_string() });
        send(&RpcMessage::request(id, "events/push", params));
    }

    /// 在线后：推示例群与一条欢迎消息。
    fn welcome(&mut self) {
        let chat = Conversation {
            id: DEMO_CHAT.into(),
            kind: ConversationKind::Group,
            name: "示例群".into(),
            avatar: None,
            peer: None,
            private: false,
        };
        let hello = text_message(
            format!("welcome-{}", now_ms()),
            BOT,
            "示例机器人",
            SenderKind::Bot,
            &format!("你好，这是示例 IM {}。在这里发一句话试试。", env!("CARGO_PKG_VERSION")),
        );
        self.push(vec![
            Event::Conversation { conversation: chat },
            Event::Messages {
                conversation_id: DEMO_CHAT.into(),
                messages: vec![hello],
            },
        ]);
    }

    /// 处理一个请求，返回结果；不支持的方法返回错误。
    fn handle(&mut self, method: &str, params: &Value) -> Result<Value, RpcError> {
        match method {
            "initialize" => Ok(json!({
                "protocolVersion": 1,
                "provider": { "id": "demo-im", "name": "示例 IM", "version": env!("CARGO_PKG_VERSION") },
                "platform": {
                    "avatarShape": "rounded",
                    "history": "none",
                    "actions": { "reply": false, "thread": false, "react": false, "recall": null, "edit": null }
                },
                "capabilities": {
                    "conversations": { "list": false },
                    "messages": { "list": false, "get": false },
                    "events": { "messages": true, "conversations": true, "people": false },
                    "resources": { "read": false, "avatars": false }
                },
                "settings": []
            })),
            "session/open" => Ok(json!({ "state": "online", "account": { "id": ME, "name": "示例账号" } })),
            "ping" | "session/logout" | "shutdown" => Ok(json!({})),
            "messages/send" => {
                let text = params
                    .pointer("/content/0/text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let sent = text_message(format!("sent-{}", now_ms()), ME, "示例账号", SenderKind::User, &text);
                let reply = text_message(format!("reply-{}", now_ms()), BOT, "示例机器人", SenderKind::Bot, &format!("收到「{text}」"));
                self.push(vec![Event::Messages {
                    conversation_id: DEMO_CHAT.into(),
                    messages: vec![reply],
                }]);
                serde_json::to_value(SendOutcome::Accepted { message: Box::new(sent) })
                    .map_err(|_| RpcError::from_kind(ErrorKind::ProtocolError, "发送结果写不出"))
            }
            other => Err(RpcError::from_kind(ErrorKind::Unsupported, format!("示例 IM 不支持 {other}"))),
        }
    }
}

fn main() {
    let mut plugin = Plugin { next_id: 1, batches: 0 };
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(message) = codec::decode_line(&line) else {
            log("warn", "读不懂宿主发来的一行");
            continue;
        };
        // 宿主对推送的回执、宿主发来的通知（如取消）：示例不用。
        let (Some(id), Some(method)) = (message.id.clone(), message.method.clone()) else {
            continue;
        };
        if message.is_response() {
            continue;
        }
        let params = message.params.clone().unwrap_or(Value::Null);
        match plugin.handle(&method, &params) {
            Ok(result) => send(&RpcMessage::ok(id, result)),
            Err(error) => send(&RpcMessage::err(id, error)),
        }
        match method.as_str() {
            "session/open" => plugin.welcome(),
            "shutdown" => break,
            _ => {}
        }
    }
}

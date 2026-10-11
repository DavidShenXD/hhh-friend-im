//! 推送（protocol-v1 §11）：客户端库推来的更新翻成协议的事件，排进一条队列，由一个任务一批一批推给宿主。
//!
//! - 同一时间只有一批在途：宿主写进本地库、回复了才算送到，才推下一批；出错或 30 秒没回复就隔一会儿原样重推
//!   （宿主按编号去重）。一批至多 500 个事件。
//! - 同步位置（客户端库处理到的日志序号）只随“把队列推空”的那一批带上：宿主存下的位置之前的事件一定都已经存好，
//!   插件重启后从这里接着补，不会跳过没推出去的。
//! - 新会话先推会话本身再推它的消息；自己退群或被移出时推“会话没有了”（宿主只记下，不删本地记录）。
//! - 连接状态（连上、断开重连）当场发 `status` 通知，不排队。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use friend_im_client::core::ids::{ConvId, MsgId, Uid};
use friend_im_client::core::message::Content;
use friend_im_client::core::wire::DeviceStatus;
use friend_im_client::{ConvNotice, HistoryItem, Message, Notice, Update, Updates};
use hhh_im_protocol::method::{ConnState, CredentialSaveParams, EventsPushParams, SessionExpiredParams, StatusParams};
use hhh_im_protocol::rpc::ReauthReason;
use hhh_im_protocol::types::{Event, Message as Wire};
use tokio::sync::Notify;
use tokio::task::AbortHandle;

use super::Server;
use super::session::Live;
use super::translate;
use crate::credential::Credential;

/// 一批至多几个事件（protocol-v1 §11.1）。
const BATCH_MAX: usize = 500;
/// 撤回推来、原来那条不在最近见过的消息里时，往前翻几页历史找它（每页 100 条）。
const RECALL_SEARCH_PAGES: usize = 5;

/// 等着推给宿主的事件。
#[derive(Default)]
pub(crate) struct Outbox {
    queue: Mutex<(VecDeque<Event>, Option<u64>)>,
    wake: Notify,
}

impl Outbox {
    fn push(&self, event: Event) {
        self.queue.lock().expect("推送队列锁中毒").0.push_back(event);
        self.wake.notify_one();
    }

    fn position(&self, log: u64) {
        let mut queue = self.queue.lock().expect("推送队列锁中毒");
        queue.1 = Some(queue.1.map_or(log, |p| p.max(log)));
        drop(queue);
        self.wake.notify_one();
    }

    /// 取下一批：至多 [`BATCH_MAX`] 个事件；这一批把队列取空时带上同步位置（比上次推过的新才带）。
    fn take(&self, sent: Option<u64>) -> Option<(Vec<Event>, Option<u64>)> {
        let mut queue = self.queue.lock().expect("推送队列锁中毒");
        let n = queue.0.len().min(BATCH_MAX);
        let events: Vec<Event> = queue.0.drain(..n).collect();
        let position = queue.0.is_empty().then_some(queue.1).flatten().filter(|p| sent.is_none_or(|s| *p > s));
        (!events.is_empty() || position.is_some()).then_some((events, position))
    }
}

/// 开始推送：一个任务把更新翻成事件，一个任务推给宿主。返回两个任务，下线时停掉。
pub(crate) fn start(server: Arc<Server>, live: Arc<Live>, updates: Updates, saved: Credential) -> Vec<AbortHandle> {
    let outbox = Arc::new(Outbox::default());
    let translator = tokio::spawn(translate_updates(server.clone(), live, updates, outbox.clone(), saved));
    let sender = tokio::spawn(send_batches(server, outbox));
    vec![translator.abort_handle(), sender.abort_handle()]
}

/// 推给宿主：一批推完（宿主回复了）才推下一批，失败就退避重推同一批。
async fn send_batches(server: Arc<Server>, outbox: Arc<Outbox>) {
    let mut sent: Option<u64> = None;
    loop {
        outbox.wake.notified().await;
        while let Some((events, position)) = outbox.take(sent) {
            let params = EventsPushParams { events, sync_state: position.map(|p| p.to_string()) };
            let mut delay = server.options.push_retry;
            while let Err(error) = server.peer.request("events/push", &params).await {
                tracing::warn!(?error, count = params.events.len(), "宿主没收下这批推送，稍后重推");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
            if position.is_some() {
                sent = position;
            }
        }
    }
}

/// 把客户端库的更新翻成事件，直到客户端停了。
async fn translate_updates(server: Arc<Server>, live: Arc<Live>, mut updates: Updates, outbox: Arc<Outbox>, saved: Credential) {
    while let Some(update) = updates.recv().await {
        match update {
            Update::Connected { status } => {
                server.peer.notify("status", StatusParams { state: ConnState::Online, reason: None });
                if status != DeviceStatus::Active {
                    tracing::warn!(?status, "重连后这台电脑不能用了");
                }
            }
            Update::Disconnected => {
                server.peer.notify("status", StatusParams { state: ConnState::Connecting, reason: Some("和 Friend-IM 服务器断开了，正在重连".into()) });
            }
            Update::Position(log) => outbox.position(log),
            Update::Message(message) => on_message(&live, &outbox, message).await,
            Update::MessageRejected { conv, id, ts_ms, sender, .. } => {
                ensure_conversation(&live, &outbox, &conv).await;
                let names = live.names([sender.clone()]).await;
                let wire = translate::unreadable(conv.as_str(), &id, &sender, ts_ms, &names);
                outbox.push(Event::Messages { conversation_id: conv.to_string(), messages: vec![wire] });
            }
            Update::Conv(notice) => on_notice(&live, &outbox, notice).await,
            Update::ConvRejected { conv, log, reason } => {
                tracing::warn!(%conv, log, %reason, "会话签名链有一环没通过核对，已拒绝");
                let at = crate::server::now_ms();
                outbox.push(Event::Messages { conversation_id: conv.to_string(), messages: vec![translate::conv_rejected(conv.as_str(), log, at)] });
            }
            Update::CredentialsChanged => save_credentials(&server, &live, &saved).await,
            Update::DeviceRemoved => {
                expire(&server, ReauthReason::Revoked, "这台电脑已被移出你的 Friend-IM 账号，要重新登录。").await;
                return;
            }
            Update::LoggedOut => {
                expire(&server, ReauthReason::Expired, "Friend-IM 的登录已失效，要重新登录。").await;
                return;
            }
            // 账号与电脑的提醒、新电脑批准在下一阶段接（要协议 v13 的插件操作）。
            Update::Activated | Update::Account { .. } => {}
            Update::JoinRequested(_) | Update::JoinRetry { .. } | Update::JoinWrongCode { .. } | Update::JoinClosed { .. } => {
                tracing::debug!("新电脑批准的推送，这一版不处理");
            }
        }
    }
    tracing::info!("客户端停了，推送结束");
}

/// 新会话：先把会话本身推给宿主（宿主据此加进会话列表）。
async fn ensure_conversation(live: &Live, outbox: &Outbox, conv: &ConvId) {
    if live.knows_conversation(conv) {
        return;
    }
    push_conversation(live, outbox, conv).await;
}

async fn push_conversation(live: &Live, outbox: &Outbox, conv: &ConvId) {
    match live.conversation(conv).await {
        Ok(conversation) => outbox.push(Event::Conversation { conversation }),
        Err(error) => tracing::info!(%conv, %error, "会话资料取不到，先不推会话"),
    }
}

async fn on_message(live: &Live, outbox: &Outbox, message: Message) {
    ensure_conversation(live, outbox, &message.conv).await;
    if let Some(Content::Recall { target }) = &message.content {
        if let Some(wire) = recalled(live, &message, target).await {
            outbox.push(Event::Messages { conversation_id: message.conv.to_string(), messages: vec![wire] });
        }
        return;
    }
    let names = live.names(mentioned(&message)).await;
    let Some(wire) = translate::message(&message, &names) else {
        return;
    };
    live.remember(&wire.id, &message.sender, message.ts_ms);
    outbox.push(Event::Messages { conversation_id: message.conv.to_string(), messages: vec![wire] });
}

/// 一条消息里要显示名字的人：发送人与被提及的人。
pub(crate) fn mentioned(message: &Message) -> Vec<Uid> {
    let mut uids = vec![message.sender.clone()];
    if let Some(Content::Post { parts, .. }) = &message.content {
        uids.extend(parts.iter().filter_map(|p| match p {
            friend_im_client::core::message::Part::Mention { uid: Some(uid), .. } => Some(uid.clone()),
            _ => None,
        }));
    }
    uids
}

/// 撤回推来：报原来那条变成“已撤回”（时间与发送人照原来那条，宿主按编号覆盖）。最近没见过就往前翻几页找。
async fn recalled(live: &Live, recall: &Message, target: &MsgId) -> Option<Wire> {
    let found = match live.recalled_from(target.as_str()) {
        Some(found) => Some(found),
        None => search(live, recall, target).await,
    };
    let Some((sender, ts_ms)) = found else {
        tracing::info!(conv = %recall.conv, "撤回的那条往前翻也没找到，等宿主下次读历史时更新");
        return None;
    };
    let names = live.names([sender.clone()]).await;
    Some(translate::recalled(recall.conv.as_str(), target, &sender, ts_ms, &names))
}

async fn search(live: &Live, recall: &Message, target: &MsgId) -> Option<(Uid, i64)> {
    let mut before = Some(recall.log);
    for _ in 0..RECALL_SEARCH_PAGES {
        let page = live.client.history(&recall.conv, before, 100).await.ok()?;
        for item in &page.items {
            match item {
                HistoryItem::Message(m) if &m.id == target => return Some((m.sender.clone(), m.ts_ms)),
                HistoryItem::Rejected { id, sender, ts_ms, .. } if id == target => return Some((sender.clone(), *ts_ms)),
                _ => {}
            }
        }
        if !page.more {
            return None;
        }
        before = page.items.iter().map(HistoryItem::log).min();
    }
    None
}

/// 会话里的系统提示：会话本身变了就重新推会话（自己离开了就推“会话没有了”），再推这条提示。
async fn on_notice(live: &Live, outbox: &Outbox, notice: Notice) {
    let conv = notice.conv.clone();
    let i_left = match &notice.change {
        ConvNotice::Left => notice.author == live.me,
        ConvNotice::Removed { uid, .. } => *uid == live.me,
        _ => false,
    };
    let changed = matches!(
        notice.change,
        ConvNotice::Created { .. } | ConvNotice::Added { .. } | ConvNotice::JoinedByInvite | ConvNotice::ProfileChanged | ConvNotice::Left | ConvNotice::Removed { .. }
    );
    if changed {
        live.forget_conversation(&conv);
        if !i_left {
            push_conversation(live, outbox, &conv).await;
        }
    } else {
        ensure_conversation(live, outbox, &conv).await;
    }
    let names = live.names(translate::notice_people(&notice)).await;
    if let Some(wire) = translate::notice(&notice, &names) {
        outbox.push(Event::Messages { conversation_id: conv.to_string(), messages: vec![wire] });
    }
    if i_left {
        outbox.push(Event::ConversationRemoved { conversation_id: conv.to_string() });
    }
}

/// 服务器换发了登录凭证：交给宿主存（借来的凭据不存，到期再说）。
async fn save_credentials(server: &Server, live: &Live, saved: &Credential) {
    if live.read_only {
        tracing::info!("凭据是借来的，不存新的登录凭证");
        return;
    }
    let credential = Credential::new(&saved.server, &saved.uid, &saved.device_name, live.client.credentials().await);
    let params = CredentialSaveParams { credential: credential.encode(), renew_at_ms: None };
    if let Err(error) = server.peer.request("credential/save", &params).await {
        tracing::error!(?error, "宿主没存下新的登录凭证，下次启动可能要重新登录");
    }
}

/// 这台电脑不能再用了：告诉宿主要重新登录，下线。
async fn expire(server: &Server, reason: ReauthReason, message: &str) {
    tracing::warn!(?reason, "授权失效，下线");
    server.peer.notify("session/expired", SessionExpiredParams { reason, message: message.into() });
    server.close_session().await;
}


#[cfg(test)]
mod tests {
    use super::*;

    fn event(n: usize) -> Event {
        Event::ConversationRemoved { conversation_id: format!("c{n}") }
    }

    #[test]
    fn batches_carry_the_position_only_when_they_empty_the_queue() {
        let outbox = Outbox::default();
        for n in 0..(BATCH_MAX + 3) {
            outbox.push(event(n));
        }
        outbox.position(40);
        let (first, position) = outbox.take(None).unwrap();
        assert_eq!((first.len(), position), (BATCH_MAX, None), "队列没推空：不带位置");
        let (rest, position) = outbox.take(None).unwrap();
        assert_eq!((rest.len(), position), (3, Some(40)));
        assert!(outbox.take(Some(40)).is_none(), "推过的位置不再推");
        outbox.position(41);
        assert_eq!(outbox.take(Some(40)).map(|(e, p)| (e.len(), p)), Some((0, Some(41))), "只有位置往前走了也推一次");
        outbox.position(39);
        assert!(outbox.take(Some(41)).is_none(), "位置不往回退");
    }
}

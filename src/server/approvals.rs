//! 旧电脑这边：新电脑等你批准（契约 S2、S20、S21）与电脑增减的提醒（S4），经 `session/notice` 的待处理行与插件操作。
//!
//! - 每台在等的新电脑一条提醒：“新电脑「名」等你批准”，按钮“查看”（操作 `approve:<请求>`），`prompt` 为真（Friend 在前台就
//!   直接弹出）。请求结束（哪台电脑处理了、作废了）时拿掉。
//! - 电脑增减（自己账号的签名链上加了、移除了电脑）一条：“你的账号新增了电脑「名」”/“已移除电脑「名」”，按钮“查看”打开
//!   “我的电脑”，看过就拿掉；至多留 [`DEVICE_NOTES_MAX`] 条。
//! - 批准的流程：输入新电脑上的 4 个词；输错按客户端库的 `JoinRetry` 带“还能试 N 次”再推；对上了客户端库自动批准。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use friend_im_client::core::ids::RequestId;
use friend_im_client::core::limits::JOIN_MAX_ATTEMPTS;
use friend_im_client::core::wire::{JoinCloseReason, JoinRequestInfo};
use friend_im_client::core::words::JoinCode;
use hhh_im_protocol::method::{Notice, NoticeAction, SessionNoticeParams};
use serde_json::json;
use tokio::sync::mpsc;

use super::Server;
use super::flow::{Input, JoinEvent, Ui, compact, note};
use super::session::{DEVICE_NOTES_MAX, Live};

/// 批准操作的编号前缀。
pub(crate) const APPROVE_PREFIX: &str = "approve:";

/// 电脑增减提醒的编号。
static NEXT_NOTE: AtomicU64 = AtomicU64::new(1);

/// 一个时间（毫秒）写成“今天 10:42”/“10 月 12 日 10:42”（本机时区不可知，用 UTC+8，和服务器所在一致）。
pub(crate) fn when(ms: i64) -> String {
    const OFFSET: i64 = 8 * 3600 * 1000;
    let local = ms + OFFSET;
    let days = local.div_euclid(86_400_000);
    let minutes = local.rem_euclid(86_400_000) / 60_000;
    let today = (super::now_ms() + OFFSET).div_euclid(86_400_000);
    let (_, month, day) = civil(days);
    let clock = format!("{:02}:{:02}", minutes / 60, minutes % 60);
    if days == today { format!("今天 {clock}") } else { format!("{month} 月 {day} 日 {clock}") }
}

/// 一个时间（毫秒）在 UTC+8 的年月日。
pub(crate) fn civil_date(ms: i64) -> (i64, u32, u32) {
    civil((ms + 8 * 3600 * 1000).div_euclid(86_400_000))
}

/// 从 1970-01-01 起的天数 → 年月日（Howard Hinnant 的算法）。
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// 此刻的全部提醒（每次给全）。
pub(crate) fn notices_of(live: &Live) -> Vec<Notice> {
    let mut notices: Vec<Notice> = live
        .requests
        .lock()
        .expect("批准请求锁中毒")
        .values()
        .map(|info| Notice {
            id: format!("join-{}", info.request),
            text: format!("新电脑「{}」等你批准", info.name),
            relogin: false,
            action: Some(NoticeAction { id: format!("{APPROVE_PREFIX}{}", info.request), label: "查看".into() }),
            prompt: true,
        })
        .collect();
    notices.extend(live.device_notes.lock().expect("电脑提醒锁中毒").iter().map(|(id, text)| Notice {
        id: format!("device-{id}"),
        text: text.clone(),
        relogin: false,
        action: Some(NoticeAction { id: super::actions::DEVICES.into(), label: "查看".into() }),
        prompt: false,
    }));
    notices
}

impl Server {
    /// 把此刻的全部提醒告诉宿主。
    pub(crate) fn send_notices(&self, live: &Live) {
        self.peer.notify("session/notice", SessionNoticeParams { notices: notices_of(live) });
    }

    /// 上线后补上已经在等的批准请求（离线时来的）。取不到只记日志。
    pub(crate) async fn refresh_requests(&self, live: &Live) {
        match live.client.join_requests().await {
            Ok(requests) => {
                *live.requests.lock().expect("批准请求锁中毒") = requests.into_iter().map(|r| (r.request.to_string(), r)).collect();
                self.send_notices(live);
            }
            Err(error) => tracing::info!(%error, "待批准的新电脑取不到，等推送"),
        }
    }

    /// 有新电脑请求加入。
    pub(crate) fn join_requested(&self, live: &Live, info: JoinRequestInfo) {
        tracing::info!(name = %info.name, "新电脑等批准");
        live.requests.lock().expect("批准请求锁中毒").insert(info.request.to_string(), info);
        self.send_notices(live);
    }

    /// 批准请求结束：拿掉提醒，正在批准它的流程收到结果。
    pub(crate) fn join_closed(&self, live: &Live, request: RequestId, reason: JoinCloseReason) {
        live.requests.lock().expect("批准请求锁中毒").remove(&request.to_string());
        self.send_notices(live);
        self.flows.send_to_action(Input::Join(JoinEvent::Closed { request, reason }));
    }

    /// 电脑增减（契约 S4）：记一条提醒。
    pub(crate) fn device_changed(&self, live: &Live, text: String) {
        {
            let mut notes = live.device_notes.lock().expect("电脑提醒锁中毒");
            notes.push((NEXT_NOTE.fetch_add(1, Ordering::Relaxed), text));
            let extra = notes.len().saturating_sub(DEVICE_NOTES_MAX);
            notes.drain(..extra);
        }
        self.send_notices(live);
    }

    /// 看过“我的电脑”：电脑增减的提醒拿掉。
    pub(crate) fn devices_seen(&self, live: &Live) {
        let had = !std::mem::take(&mut *live.device_notes.lock().expect("电脑提醒锁中毒")).is_empty();
        if had {
            self.send_notices(live);
        }
    }

    /// 批准新电脑（操作 `approve:<请求>`）。
    pub(crate) async fn approve(self: Arc<Self>, live: Arc<Live>, ui: Ui<'_>, request: &str, mut rx: mpsc::UnboundedReceiver<Input>) {
        let Some(info) = live.requests.lock().expect("批准请求锁中毒").get(request).cloned() else {
            ui.fail(Some("请求已结束"), "这次请求已经处理过或作废了。", None);
            return;
        };
        let name = info.name.clone();
        let input_step = |warn: Option<String>| {
            compact(json!({
                "kind": "input",
                "caption": format!("新电脑「{name}」想登录你的 Friend-IM 账号（{}）。如果是你本人在操作，输入那台电脑上显示的 4 个词。", when(info.created_ms)),
                "fields": [{ "id": "words", "label": "新电脑上的 4 个词", "secret": false, "placeholder": "用空格隔开" }],
                "submitLabel": "批准", "cancelLabel": "拒绝", "cancelChoice": "reject",
                "note": match &warn {
                    Some(text) => note(text, true),
                    None => note("不是你本人在操作就点“拒绝”：批准后，那台电脑能读你的全部消息。", false),
                },
            }))
        };
        ui.step(input_step(None));
        while let Some(input) = rx.recv().await {
            match input {
                Input::Cancel => return,
                Input::Choose { choice, .. } if choice == "reject" => {
                    if let Err(error) = live.client.join_reject(&info.request).await {
                        tracing::info!(%error, "拒绝新电脑没成");
                    }
                    ui.fail(Some("已拒绝"), "那台电脑不会加入。如果不是你本人在操作，建议尽快修改 Cindy 密码。", None);
                    return;
                }
                Input::Choose { .. } => {}
                Input::Submit(values) => {
                    let words = values.get("words").map(String::as_str).unwrap_or_default();
                    if JoinCode::parse(words).is_err() {
                        ui.step(input_step(Some("要输 4 个词，用空格隔开。".into())));
                        continue;
                    }
                    ui.step(json!({ "kind": "message", "text": "正在核对…", "tone": "info" }));
                    if let Err(error) = live.client.join_respond(&info.request, words).await {
                        tracing::info!(%error, "批准新电脑没交上去");
                        ui.fail(Some("请求已结束"), &format!("这次请求已经处理过或作废了（{error}）。"), None);
                        return;
                    }
                }
                Input::Join(JoinEvent::Retry { request, attempt }) if request == info.request => {
                    let left = (JOIN_MAX_ATTEMPTS + 1).saturating_sub(attempt);
                    ui.step(input_step(Some(format!("和新电脑上的不一致，再看一下（还能试 {left} 次）。"))));
                }
                Input::Join(JoinEvent::Closed { request, reason }) if request == info.request => {
                    match reason {
                        JoinCloseReason::Approved => {
                            ui.done(Some(&format!("已批准「{name}」")), Some("那台电脑正在补齐聊天记录。你的其它电脑也会收到提醒。"));
                        }
                        JoinCloseReason::TooManyAttempts => ui.fail(
                            Some("请求已作废"),
                            "连续 5 次和新电脑上的不一致，这次请求已作废。需要的话，在新电脑上重新请求。",
                            None,
                        ),
                        JoinCloseReason::Expired => ui.fail(Some("请求已作废"), "这次请求已经过了 10 分钟。需要的话，在新电脑上重新请求。", None),
                        JoinCloseReason::Cancelled => ui.fail(Some("请求已结束"), "新电脑不等了，这次请求已结束。", None),
                        JoinCloseReason::Rejected => ui.fail(Some("已拒绝"), "这次请求已被拒绝。", None),
                    }
                    return;
                }
                Input::Join(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_read_like_people_write_them() {
        // 2026-10-12 02:42 UTC = 10:42（UTC+8）。
        let ms = 1_791_686_520_000;
        assert!(when(ms).ends_with("10:42"), "{}", when(ms));
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_738), (2026, 10, 12));
    }
}

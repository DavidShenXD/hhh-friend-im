//! 用 Cindy 账号登录（provider-protocol v13 §3.1，契约 S1、S2、S3、S7、S18、S20–S23）：宿主在 `login/start` 里给 Cindy 令牌与
//! 账号，插件生成这台电脑的钥匙、用令牌连服务器，然后按账号的情况走：
//!
//! - 账号还没开通（第一台电脑）：开通 → 存凭据 → 出示恢复密钥（不能跳过）→ 完成（“Friend-IM 已开通”）。先存再出示：开通后
//!   这台电脑已在账号里，即使没点完成也不会留下一个没人能进的账号；恢复密钥之后在“我的电脑”里能重新生成。
//! - 开通过、这台是新电脑：出示 4 个词等旧电脑批准；可改用恢复密钥，或都没有了只能重置。批准、加入、重置完成后存凭据、
//!   完成。拒绝、超时、输错 5 次以失败结束（能重试：重新请求）。
//!
//! 令牌只在这一次连服务器时用，不进日志、不存；之后用服务器发的登录凭证（存在凭据里）。

use std::sync::Arc;

use friend_im_client::core::wire::{DeviceStatus, JoinCloseReason};
use friend_im_client::{Client, Config, Credentials, Update, Updates};
use hhh_im_protocol::method::{HostAccount, LoginKind, LoginStartParams, LoginStartResult, login_value};
use hhh_im_protocol::rpc::{ErrorKind, RpcError, RpcId};
use hhh_im_protocol::types::Account;
use serde_json::json;
use tokio::sync::mpsc;

use super::flow::{Input, Kind, Ui, compact, link, note, recovery_key, wait_confirm, waiting};
use super::{Server, errors};
use crate::credential::Credential;

/// 声明的登录方式编号。
pub(crate) const HOST_METHOD: &str = "cindy";

/// 这台电脑的名字（“我的电脑”里显示）：系统给的电脑名；拿不到时用“<名字>的电脑”。至多 64 个字。
pub(crate) fn device_name(account_name: &str) -> String {
    let system = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).ok().filter(|n| !n.trim().is_empty());
    let name = system.unwrap_or_else(|| format!("{account_name}的电脑"));
    name.chars().take(64).collect()
}

/// 这次登录要用的：令牌、账号、服务器。
struct Start {
    token: String,
    account: HostAccount,
    server: String,
}

impl Server {
    /// `login/start`：只认“用 Cindy 账号登录”；开一个登录流程，先回流程编号再推第一步（回 `None`：已经回过了）。
    pub(crate) fn login_start(self: &Arc<Self>, id: &RpcId, params: LoginStartParams) -> Option<Result<serde_json::Value, RpcError>> {
        if params.method.as_deref().is_some_and(|m| m != HOST_METHOD) {
            return Some(Err(errors::of(ErrorKind::InvalidRequest, "Friend-IM 只能用 Cindy 账号登录。")));
        }
        let token = params.values.get(login_value::HOST_TOKEN).cloned().filter(|t| !t.is_empty());
        let (flow_id, rx) = self.flows.begin(Kind::Login);
        let result = LoginStartResult { flow_id: flow_id.clone() };
        self.peer.respond(id.clone(), Ok(serde_json::to_value(result).expect("结果总能写成 JSON")));
        let (Some(token), Some(account)) = (token, params.host_account) else {
            // 宿主没给令牌（游客，或不是官方签名的 Friend-IM）：这次登录当场失败。
            tracing::warn!("开始登录时宿主没给 Cindy 令牌或账号");
            let ui = Ui { peer: &self.peer, flow_id: flow_id.clone(), kind: Kind::Login };
            ui.fail(Some("没能登录"), "先登录 Cindy：Friend-IM 用 Friend 现在登录的 Cindy 账号登录。", None);
            self.flows.end(&flow_id);
            return None;
        };
        tracing::info!(token_chars = token.len(), "用 Cindy 账号登录 Friend-IM");
        let start = Start { token, account, server: self.server_url() };
        let (server, id) = (self.clone(), flow_id.clone());
        tokio::spawn(async move {
            let ui = Ui { peer: &server.peer, flow_id: id.clone(), kind: Kind::Login };
            server.clone().run_login(&ui, start, rx).await;
            server.flows.end(&id);
        });
        None
    }

    async fn run_login(self: Arc<Self>, ui: &Ui<'_>, start: Start, mut rx: mpsc::UnboundedReceiver<Input>) {
        ui.step(waiting("正在连接 Friend-IM…"));
        let name = device_name(&start.account.name);
        let config = Config { server: start.server.clone(), device_name: name.clone() };
        let (client, mut updates) = match Client::connect(config, Credentials::generate(), Some(start.token), None).await {
            Ok(connected) => connected,
            Err(error) => {
                tracing::info!(%error, "用 Cindy 账号连 Friend-IM 服务器没成");
                ui.fail(Some("没能登录"), &format!("连不上 Friend-IM 服务器：{error}"), Some("再试一次"));
                return;
            }
        };
        let avatar = start.account.avatar_url.clone();
        let new_credential = |client_credentials: Credentials| {
            Credential::new(&start.server, client.uid().as_str(), &name, client_credentials).with_avatar(avatar.as_deref())
        };
        let finished = match client.status().await {
            DeviceStatus::Unprovisioned => self.provision(ui, &client, &mut rx, &new_credential).await,
            DeviceStatus::Pending => self.join(ui, &client, &mut updates, &mut rx, &new_credential).await,
            DeviceStatus::Active => {
                // 服务器认得这台电脑的钥匙且已可用（不会发生：钥匙刚生成），照常存凭据上线。
                let credential = new_credential(client.credentials().await);
                match self.save_credential(&credential).await {
                    Ok(()) => Some((credential, None)),
                    Err(reason) => {
                        ui.fail(Some("没能登录"), &reason, Some("再试一次"));
                        None
                    }
                }
            }
        };
        let Some((credential, texts)) = finished else {
            client.close();
            return;
        };
        let account: Account = self.go_live(client, updates, credential, false).await;
        let (title, message) = texts.unzip();
        self.peer.notify(
            "login/finished",
            compact(json!({ "flowId": ui.flow_id, "account": account, "title": title, "message": message })),
        );
        tracing::info!("Friend-IM 登录完成");
    }

    /// 第一台电脑：开通、存凭据、出示恢复密钥。
    async fn provision(
        &self,
        ui: &Ui<'_>,
        client: &Client,
        rx: &mut mpsc::UnboundedReceiver<Input>,
        new_credential: &(dyn Fn(Credentials) -> Credential + Sync),
    ) -> Option<(Credential, Option<(&'static str, &'static str)>)> {
        ui.step(waiting("正在开通…"));
        let key = match client.provision().await {
            Ok(key) => key,
            Err(error) => {
                tracing::info!(%error, "开通没成");
                ui.fail(Some("没能开通"), &format!("开通 Friend-IM 没成：{error}"), Some("再试一次"));
                return None;
            }
        };
        let credential = new_credential(client.credentials().await);
        if let Err(reason) = self.save_credential(&credential).await {
            ui.fail(Some("没能开通"), &reason, Some("再试一次"));
            return None;
        }
        ui.step(recovery_key(
            "Friend-IM 已开通。这是你的恢复密钥：所有电脑都丢了时，只有它能找回聊天记录。它只显示这一次，请抄在纸上，或存进密码管理器。",
            &key.to_words(),
        ));
        // 宿主关掉、断了也往下走：凭据已经存好。
        wait_confirm(rx).await;
        Some((credential, Some(("Friend-IM 已开通", "以后在别的电脑上登录同一个 Cindy 账号，用这台电脑批准，就能看到全部聊天记录。"))))
    }

    /// 新电脑：等旧电脑批准，或改用恢复密钥，或重置。
    async fn join(
        &self,
        ui: &Ui<'_>,
        client: &Client,
        updates: &mut Updates,
        rx: &mut mpsc::UnboundedReceiver<Input>,
        new_credential: &(dyn Fn(Credentials) -> Credential + Sync),
    ) -> Option<(Credential, Option<(&'static str, &'static str)>)> {
        enum Mode {
            Approve,
            Recovery,
            Reset,
        }
        let mut mode = Mode::Approve;
        loop {
            match mode {
                Mode::Approve => {
                    let code = match client.join_start().await {
                        Ok(code) => code,
                        Err(error) => {
                            tracing::info!(%error, "发起批准请求没成");
                            ui.fail(Some("没能请求批准"), &format!("发起批准请求没成：{error}"), Some("再试一次"));
                            return None;
                        }
                    };
                    let code_step = |warn: Option<&str>| {
                        compact(json!({
                            "kind": "showText", "layout": "code", "text": code.as_str(), "cancelLabel": "取消",
                            "caption": "这个账号已经在别的电脑上用过。到一台已登录 Friend-IM 的电脑上，在弹出的“批准新电脑”里输入下面 4 个词：",
                            "waiting": "等待批准…（10 分钟内有效）",
                            "note": warn.map(|text| note(text, true)),
                            "links": [link("useKey", "改用恢复密钥"), link("lost", "旧电脑和恢复密钥都没有了")],
                        }))
                    };
                    ui.step(code_step(None));
                    mode = loop {
                        tokio::select! {
                            input = rx.recv() => match input {
                                None | Some(Input::Cancel) => {
                                    let _ = client.join_cancel().await;
                                    return None;
                                }
                                Some(Input::Choose { choice, .. }) if choice == "useKey" => {
                                    let _ = client.join_cancel().await;
                                    break Mode::Recovery;
                                }
                                Some(Input::Choose { choice, .. }) if choice == "lost" => {
                                    let _ = client.join_cancel().await;
                                    break Mode::Reset;
                                }
                                Some(_) => {}
                            },
                            update = updates.recv() => match update {
                                None => {
                                    ui.fail(Some("没能登录"), "和 Friend-IM 服务器断开了。", Some("重新请求"));
                                    return None;
                                }
                                Some(Update::JoinWrongCode { .. }) => {
                                    ui.step(code_step(Some("那台电脑输入的和这里的不一致，请在那台电脑上再输一次。")));
                                }
                                Some(Update::JoinClosed { reason, .. }) => match reason {
                                    JoinCloseReason::Approved => {
                                        ui.step(waiting("已批准，正在取回钥匙…"));
                                        if !wait_active(updates).await {
                                            ui.fail(Some("没能登录"), "批准了，但这台电脑没能取回钥匙。", Some("重新请求"));
                                            return None;
                                        }
                                        return self.saved(ui, client, new_credential, ("这台电脑已加入", "会话列表马上出现，历史消息在后台补齐。你的其它电脑也会收到提醒。")).await;
                                    }
                                    JoinCloseReason::Rejected => {
                                        ui.fail(Some("没有批准"), "那台电脑拒绝了这次请求。如果不是你本人在操作，可能有人登录了你的 Cindy 账号，请尽快修改 Cindy 密码。", Some("重新请求"));
                                        return None;
                                    }
                                    JoinCloseReason::Expired => {
                                        ui.fail(Some("没有批准"), "10 分钟内没有电脑批准。可以重新请求，或改用恢复密钥。", Some("重新请求"));
                                        return None;
                                    }
                                    JoinCloseReason::TooManyAttempts => {
                                        ui.fail(Some("请求已作废"), "那台电脑连续 5 次输入的都和这里的不一致，这次请求已作废。可以重新请求，或改用恢复密钥。", Some("重新请求"));
                                        return None;
                                    }
                                    JoinCloseReason::Cancelled => {}
                                },
                                Some(_) => {}
                            },
                        }
                    };
                }
                Mode::Recovery => {
                    let key_step = |warn: Option<&str>| {
                        compact(json!({
                            "kind": "input", "caption": "输入开通时保存的恢复密钥。",
                            "fields": [{ "id": "key", "label": "恢复密钥", "secret": false, "placeholder": "12 个词，用空格隔开" }],
                            "submitLabel": "加入", "note": warn.map(|text| note(text, true)),
                            "links": [link("back", "改用旧电脑批准")],
                        }))
                    };
                    ui.step(key_step(None));
                    mode = loop {
                        match rx.recv().await {
                            None | Some(Input::Cancel) => return None,
                            Some(Input::Choose { choice, .. }) if choice == "back" => break Mode::Approve,
                            Some(Input::Submit(values)) => {
                                let text = values.get("key").map(String::as_str).unwrap_or_default();
                                ui.step(waiting("正在核对恢复密钥…"));
                                match client.join_with_recovery(text).await {
                                    Ok(()) => {
                                        return self.saved(ui, client, new_credential, ("这台电脑已加入", "会话列表马上出现，历史消息在后台补齐。你的其它电脑也会收到提醒。")).await;
                                    }
                                    Err(error) => {
                                        tracing::info!(%error, "用恢复密钥加入没成");
                                        ui.step(key_step(Some("恢复密钥不对，或已经换过。再核对一下。")));
                                    }
                                }
                            }
                            Some(_) => {}
                        }
                    };
                }
                Mode::Reset => {
                    ui.step(json!({
                        "kind": "confirm", "caption": "只能重置账号。重置后：", "danger": true, "confirmLabel": "重置账号",
                        "sections": [
                            { "title": "以前的消息", "text": "全部读不出来，谁也找不回。" },
                            { "title": "群", "text": "你会退出所有群，需要群里的人重新邀请你。" },
                            { "title": "好友", "text": "好友还在。他们和你的私聊里会出现“你重置了账号”的提示。" }
                        ],
                        "links": [link("back", "改用旧电脑批准")],
                    }));
                    match rx.recv().await {
                        Some(Input::Choose { choice, .. }) if choice == "confirm" => {}
                        Some(Input::Choose { choice, .. }) if choice == "back" => {
                            mode = Mode::Approve;
                            continue;
                        }
                        _ => return None,
                    }
                    ui.step(waiting("正在重置账号…"));
                    let key = match client.reset().await {
                        Ok(key) => key,
                        Err(error) => {
                            tracing::info!(%error, "重置没成");
                            ui.fail(Some("没能重置"), &format!("重置账号没成：{error}"), Some("再试一次"));
                            return None;
                        }
                    };
                    let credential = new_credential(client.credentials().await);
                    if let Err(reason) = self.save_credential(&credential).await {
                        ui.fail(Some("没能重置"), &reason, Some("再试一次"));
                        return None;
                    }
                    ui.step(recovery_key("账号已重置。这是新的恢复密钥，只显示这一次，请保存好。", &key.to_words()));
                    wait_confirm(rx).await;
                    return Some((credential, Some(("账号已重置", "可以继续用了。如果还有别的电脑登录着，它们会被移出，需要重新批准。"))));
                }
            }
        }
    }

    /// 这台电脑可用了：存凭据。
    async fn saved(
        &self,
        ui: &Ui<'_>,
        client: &Client,
        new_credential: &(dyn Fn(Credentials) -> Credential + Sync),
        texts: (&'static str, &'static str),
    ) -> Option<(Credential, Option<(&'static str, &'static str)>)> {
        let credential = new_credential(client.credentials().await);
        match self.save_credential(&credential).await {
            Ok(()) => Some((credential, Some(texts))),
            Err(reason) => {
                ui.fail(Some("没能登录"), &reason, Some("再试一次"));
                None
            }
        }
    }
}

/// 等客户端库说这台电脑可用了（批准后取回钥匙）；客户端停了为假。
async fn wait_active(updates: &mut Updates) -> bool {
    while let Some(update) = updates.recv().await {
        if matches!(update, Update::Activated) {
            return true;
        }
    }
    false
}

/// 声明的登录方式。
pub(crate) fn login_methods() -> Vec<hhh_im_protocol::method::LoginMethod> {
    vec![hhh_im_protocol::method::LoginMethod {
        id: HOST_METHOD.into(),
        kind: LoginKind::Host,
        label: "用 Cindy 账号登录".into(),
        note: "用 Friend 现在登录的 Cindy 账号登录 Friend-IM，不用注册，也不要邀请码。".into(),
        placeholder: None,
        default_value: None,
        id_label: None,
        id_placeholder: None,
        secret_label: None,
        secret_placeholder: None,
        secret_help: None,
        callback_path: None,
        callback_help: None,
        create_link: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hhh_im_protocol::method::{LoginStep, step_problem};

    #[test]
    fn device_names_are_bounded() {
        let name = device_name("李子");
        assert!(!name.is_empty() && name.chars().count() <= 64);
    }

    // 登录里推的步骤照协议、在上限以内。
    #[test]
    fn login_steps_are_valid_protocol_steps() {
        for step in [
            waiting("正在开通…"),
            compact(json!({
                "kind": "showText", "layout": "code", "text": "orbit maple tunnel crisp", "cancelLabel": "取消",
                "caption": "到一台已登录 Friend-IM 的电脑上输入下面 4 个词：", "waiting": "等待批准…（10 分钟内有效）", "note": null,
                "links": [link("useKey", "改用恢复密钥"), link("lost", "旧电脑和恢复密钥都没有了")],
            })),
            compact(json!({
                "kind": "input", "caption": "输入开通时保存的恢复密钥。",
                "fields": [{ "id": "key", "label": "恢复密钥", "secret": false }], "submitLabel": "加入",
                "note": note("恢复密钥不对，或已经换过。再核对一下。", true), "links": [link("back", "改用旧电脑批准")],
            })),
        ] {
            let parsed: LoginStep = serde_json::from_value(step.clone()).unwrap_or_else(|e| panic!("{e}: {step}"));
            assert_eq!(step_problem(&parsed), None, "{step}");
        }
        assert_eq!(login_methods()[0].kind, LoginKind::Host);
    }
}

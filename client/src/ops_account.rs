//! 账号与电脑：开通、重置、移除电脑、退出登录、换恢复密钥、新电脑批准（两边）、好友链接。

use std::collections::BTreeSet;

use friend_im_core::account::{AccountChange, AccountLink, DeviceEntry, ProofRole, device_proof, eldest_body};
use friend_im_core::bytes::Fixed;
use friend_im_core::ids::{DeviceId, RequestId, Uid};
use friend_im_core::keys::{AccountSeed, RecoveryKey};
use friend_im_core::pake::{JoinContext, NewDeviceHandshake, approver_respond};
use friend_im_core::wire::{AccountInfo, AccountKeyBundle, DeviceInfo, DeviceStatus, JoinRequestInfo, Request, Response};
use friend_im_core::words::JoinCode;
use friend_im_core::CoreError;

use crate::conn::Conn;
use crate::error::{ClientError, Result};
use crate::links::{FriendLink, http_base};
use crate::state::{Approval, NewDeviceJoin, State, now_ms};
use crate::types::Update;

fn appended(response: Response) -> Result<u64> {
    match response {
        Response::Appended { log } => Ok(log),
        _ => Err(ClientError::protocol("回执不对")),
    }
}

impl State {
    fn device_entry(&self) -> DeviceEntry {
        DeviceEntry {
            keys: self.creds.device.public(),
            name: self.config.device_name.clone(),
        }
    }

    /// 第一轮的第一环（开通）或新一轮的第一环（重置）：返回第一环、账号钥匙封装、新的恢复密钥和种子。
    fn new_eldest(&self, epoch: u32) -> Result<(AccountLink, AccountKeyBundle, RecoveryKey, AccountSeed)> {
        let recovery = RecoveryKey::generate();
        let recovery_secret = recovery.device_secret();
        let seed = AccountSeed::generate();
        let body = eldest_body(&self.uid, epoch, self.device_entry(), &recovery_secret, seed.public(1), now_ms());
        let link = AccountLink::sign(&body, &self.creds.device);
        let bundle = AccountKeyBundle {
            generation: 1,
            boxes: vec![
                self.seal_account_seed(epoch, 1, &seed, &self.creds.device.public())?,
                self.seal_account_seed(epoch, 1, &seed, &recovery_secret.public())?,
            ],
            prev: None,
        };
        Ok((link, bundle, recovery, seed))
    }

    /// 开通（契约 S1）：返回恢复密钥，上层出示给用户、勾“我已保存”。
    pub async fn provision(&mut self, conn: &Conn) -> Result<RecoveryKey> {
        if self.status != DeviceStatus::Unprovisioned {
            return Err(ClientError::state("账号已经开通过了"));
        }
        let (link, keys, recovery, seed) = self.new_eldest(self.epoch)?;
        appended(conn.request(Request::Provision { eldest: link, keys }).await?)?;
        self.keys.put_account_seed(self.epoch, 1, seed);
        tracing::info!(uid = %self.uid, "账号已开通");
        self.activate(conn).await?;
        Ok(recovery)
    }

    /// 重置账号（契约 S7）：以前的消息全部读不出来，自动退出所有群。返回新的恢复密钥。
    pub async fn reset(&mut self, conn: &Conn) -> Result<RecoveryKey> {
        if self.status == DeviceStatus::Unprovisioned {
            return Err(ClientError::state("账号还没开通，直接开通即可"));
        }
        let epoch = self.epoch + 1;
        let (link, keys, recovery, seed) = self.new_eldest(epoch)?;
        appended(conn.request(Request::Reset { eldest: link, keys }).await?)?;
        self.epoch = epoch;
        self.book.clear();
        self.keys.clear();
        self.keys.put_account_seed(epoch, 1, seed);
        self.join = None;
        tracing::info!(uid = %self.uid, epoch, "账号已重置");
        self.activate(conn).await?;
        Ok(recovery)
    }

    /// 账号钥匙换一代，和 `change`（由新一代的公开部分构造）一起提交。
    async fn rotate_with(&mut self, conn: &Conn, change: impl FnOnce(&AccountSeed, u32) -> AccountChange, extra_recipient: Option<&RecoveryKey>) -> Result<()> {
        let state = self.ensure_account_keys(conn).await?;
        let previous = self.keys.current_account_seed(&state)?.clone();
        let seed = AccountSeed::generate();
        let generation = state.current_key().generation + 1;
        let link = AccountLink::sign(&state.next_body(change(&seed, generation), now_ms()), &self.creds.device);
        let mut next = state.clone();
        next.apply(&link, u64::MAX - 1).map_err(|e| ClientError::state(e.to_string()))?;
        let mut bundle = self.account_bundle(&next, &seed, &previous)?;
        if let Some(recovery) = extra_recipient {
            // 换恢复密钥时 `next.recovery` 已经是新的，account_bundle 已封装给它；这里只核对一下。
            debug_assert_eq!(recovery.device_secret().id(), next.recovery.id());
        }
        bundle.boxes.sort_by(|a, b| a.device.cmp(&b.device));
        appended(
            conn.request(Request::AppendAccount {
                links: vec![link],
                keys: Some(bundle),
            })
            .await?,
        )?;
        self.keys.put_account_seed(state.epoch, generation, seed);
        self.book.load_account(conn, &self.uid, Some(state.epoch)).await?;
        Ok(())
    }

    /// 移除别的电脑（契约 S5）：同时换代，那台电脑之后的新消息读不到。
    pub async fn remove_device(&mut self, conn: &Conn, device: &DeviceId) -> Result<()> {
        self.require_active()?;
        if device == &self.creds.device.id() {
            return Err(ClientError::state("移除本机请用退出登录"));
        }
        let target = device.clone();
        self.rotate_with(conn, move |seed, generation| AccountChange::RemoveDevice {
            device: target,
            key: Some(seed.public(generation)),
        }, None)
        .await?;
        tracing::info!(device = %device, "已移除电脑");
        Ok(())
    }

    /// 补换一代账号钥匙（有电脑退出了自己之后，服务器在登录回执里提示）。
    pub async fn rotate_account_key(&mut self, conn: &Conn) -> Result<()> {
        self.require_active()?;
        self.rotate_with(conn, |seed, generation| AccountChange::RotateKey { key: seed.public(generation) }, None)
            .await
    }

    /// 重新生成恢复密钥（契约 S6）：旧的立即失效。返回新的恢复密钥。
    pub async fn replace_recovery(&mut self, conn: &Conn) -> Result<RecoveryKey> {
        self.require_active()?;
        let recovery = RecoveryKey::generate();
        let secret = recovery.device_secret();
        let proof = device_proof(&secret, &self.uid, self.epoch, ProofRole::Recovery);
        let public = secret.public();
        self.rotate_with(conn, move |seed, generation| AccountChange::ReplaceRecovery {
            recovery: public,
            proof,
            key: seed.public(generation),
        }, Some(&recovery))
        .await?;
        tracing::info!("恢复密钥已换");
        Ok(recovery)
    }

    /// 退出登录（契约 S22）：这台电脑从账号里移除；账号钥匙由别的电脑补换一代（在线的当场换，不在线的下次上线时换）。
    pub async fn logout(&mut self, conn: &Conn) -> Result<()> {
        self.require_active()?;
        let state = self.me(conn).await?;
        let change = AccountChange::RemoveDevice {
            device: self.creds.device.id(),
            key: None,
        };
        let link = AccountLink::sign(&state.next_body(change, now_ms()), &self.creds.device);
        appended(conn.request(Request::AppendAccount { links: vec![link], keys: None }).await?)?;
        tracing::info!("已退出登录");
        Ok(())
    }

    /// 本账号现在的电脑（契约 S5）。
    pub async fn devices(&mut self, conn: &Conn) -> Result<Vec<DeviceInfo>> {
        self.require_active()?;
        match conn.request(Request::ListDevices).await? {
            Response::Devices { devices } => Ok(devices),
            _ => Err(ClientError::protocol("回执不对")),
        }
    }

    // ---------- 新电脑批准：新电脑这边 ----------

    fn join_context<'a>(&'a self, request: &'a RequestId, attempt: u32, device: &'a friend_im_core::keys::DevicePublic) -> JoinContext<'a> {
        JoinContext {
            uid: &self.uid,
            request,
            attempt,
            device,
            name: &self.config.device_name,
        }
    }

    /// 新电脑：发起批准请求（契约 S2），返回要显示的 4 个词。
    pub async fn join_start(&mut self, conn: &Conn) -> Result<JoinCode> {
        self.require_pending()?;
        let code = JoinCode::generate();
        let (handshake, pake) = NewDeviceHandshake::start(&code, &self.uid);
        let proof = device_proof(&self.creds.device, &self.uid, self.epoch, ProofRole::Device);
        let Response::JoinStarted { request, attempt, .. } = conn.request(Request::JoinStart { pake, proof }).await? else {
            return Err(ClientError::protocol("回执不对"));
        };
        self.join = Some(NewDeviceJoin {
            code: JoinCode::parse(code.as_str())?,
            request,
            attempt,
            handshake: Some(handshake),
        });
        Ok(code)
    }

    /// 新电脑：不等了。
    pub async fn join_cancel(&mut self, conn: &Conn) -> Result<()> {
        let Some(join) = self.join.take() else { return Ok(()) };
        conn.request(Request::JoinCancel { request: join.request }).await?;
        Ok(())
    }

    /// 新电脑收到旧电脑的回应：核对，对上了回自己的确认码；对不上（旧电脑输错了）就用同样的 4 个词重新开始一次尝试。
    pub async fn on_join_answered(&mut self, conn: &Conn, request: &RequestId, attempt: u32, pake: &friend_im_core::bytes::Bytes, confirm: &Fixed<32>) -> Result<()> {
        let Some(join) = self.join.as_mut() else { return Ok(()) };
        if &join.request != request || join.attempt != attempt {
            return Ok(());
        }
        let Some(handshake) = join.handshake.take() else { return Ok(()) };
        let public = self.creds.device.public();
        let context = self.join_context(request, attempt, &public);
        match handshake.finish(&context, &pake.0, confirm) {
            Ok(mine) => {
                conn.request(Request::JoinConfirm {
                    request: request.clone(),
                    attempt,
                    confirm: mine,
                })
                .await?;
                Ok(())
            }
            Err(CoreError::WrongCode) => {
                let code = JoinCode::parse(self.join.as_ref().expect("上面刚查到").code.as_str())?;
                let (handshake, pake) = NewDeviceHandshake::start(&code, &self.uid);
                let Response::JoinStarted { attempt: next, .. } = conn.request(Request::JoinRetry { request: request.clone(), pake }).await? else {
                    return Err(ClientError::protocol("回执不对"));
                };
                if next <= attempt {
                    // 输错次数到了上限：服务器已作废这次请求，随后推“请求结束”，这里不再报“已开始下一次”。
                    return Ok(());
                }
                if let Some(join) = self.join.as_mut() {
                    join.attempt = next;
                    join.handshake = Some(handshake);
                }
                self.emit(Update::JoinWrongCode {
                    request: request.clone(),
                    attempt: next,
                });
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// 新电脑：用恢复密钥加入（契约 S3）。
    pub async fn join_with_recovery(&mut self, conn: &Conn, text: &str) -> Result<()> {
        self.require_pending()?;
        let recovery = RecoveryKey::parse(text)?;
        let secret = recovery.device_secret();
        // 取最新的签名链再核对：恢复密钥可能刚在别的电脑上换过，缓存里的还是旧的。
        self.book.load_account(conn, &self.uid, Some(self.epoch)).await?;
        let state = self.me(conn).await?;
        if state.recovery.id() != secret.id() {
            return Err(ClientError::state("恢复密钥不对，或已经换过"));
        }
        let Response::AccountKeys { epoch, boxes, prev } = conn.request(Request::GetRecoveryKeys).await? else {
            return Err(ClientError::protocol("回执不对"));
        };
        if epoch != state.epoch {
            return Err(ClientError::state("账号刚在别处重置，请重试"));
        }
        self.keys.open_account_keys(&secret, &state, &boxes, &prev)?;
        let generation = state.current_key().generation;
        let seed = self.keys.current_account_seed(&state)?.clone();
        let change = AccountChange::AddDevice {
            device: self.device_entry(),
            proof: device_proof(&self.creds.device, &self.uid, self.epoch, ProofRole::Device),
        };
        let link = AccountLink::sign(&state.next_body(change, now_ms()), &secret);
        let keys = AccountKeyBundle {
            generation,
            boxes: vec![self.seal_account_seed(state.epoch, generation, &seed, &self.creds.device.public())?],
            prev: None,
        };
        appended(conn.request(Request::JoinWithRecovery { link, keys }).await?)?;
        self.join = None;
        tracing::info!("已用恢复密钥加入");
        self.activate(conn).await
    }

    // ---------- 新电脑批准：旧电脑这边 ----------

    /// 待处理的批准请求。
    pub async fn join_requests(&mut self, conn: &Conn) -> Result<Vec<JoinRequestInfo>> {
        self.require_active()?;
        let Response::JoinRequests { requests } = conn.request(Request::ListJoinRequests).await? else {
            return Err(ClientError::protocol("回执不对"));
        };
        self.requests = requests.iter().map(|r| (r.request.clone(), r.clone())).collect();
        Ok(requests)
    }

    /// 旧电脑：用户输入新电脑上显示的 4 个词。
    pub async fn join_respond(&mut self, conn: &Conn, request: &RequestId, words: &str) -> Result<()> {
        self.require_active()?;
        if !self.requests.contains_key(request) {
            self.join_requests(conn).await?;
        }
        let info = self.requests.get(request).cloned().ok_or_else(|| ClientError::state("这个批准请求已经结束"))?;
        let code = JoinCode::parse(words)?;
        let context = JoinContext {
            uid: &self.uid,
            request,
            attempt: info.attempt,
            device: &info.device,
            name: &info.name,
        };
        let (handshake, pake, confirm) = approver_respond(&code, &context, &info.pake.0)?;
        conn.request(Request::JoinRespond {
            request: request.clone(),
            attempt: info.attempt,
            pake,
            confirm,
        })
        .await?;
        self.approvals.insert(request.clone(), Approval { info, handshake });
        Ok(())
    }

    /// 旧电脑收到新电脑的确认码：对上了就签“加电脑”并把账号钥匙封装给它，一个请求提交。
    pub async fn on_join_confirmed(&mut self, conn: &Conn, request: &RequestId, attempt: u32, confirm: &Fixed<32>) -> Result<()> {
        let Some(approval) = self.approvals.remove(request) else { return Ok(()) };
        if approval.info.attempt != attempt {
            return Ok(());
        }
        if approval.handshake.check(confirm).is_err() {
            // 新电脑已经核对过我们的确认码，这里还对不上，只能是中间被人改过：拒绝。
            tracing::warn!("新电脑的确认码对不上，拒绝这次请求");
            conn.request(Request::JoinReject { request: request.clone() }).await?;
            return Err(ClientError::verify("新电脑的确认码对不上"));
        }
        let state = self.ensure_account_keys(conn).await?;
        let generation = state.current_key().generation;
        let seed = self.keys.current_account_seed(&state)?.clone();
        let change = AccountChange::AddDevice {
            device: DeviceEntry {
                keys: approval.info.device,
                name: approval.info.name.clone(),
            },
            proof: approval.info.proof,
        };
        let link = AccountLink::sign(&state.next_body(change, now_ms()), &self.creds.device);
        let keys = AccountKeyBundle {
            generation,
            boxes: vec![self.seal_account_seed(state.epoch, generation, &seed, &approval.info.device)?],
            prev: None,
        };
        appended(
            conn.request(Request::JoinApprove {
                request: request.clone(),
                link,
                keys,
            })
            .await?,
        )?;
        tracing::info!("新电脑已批准");
        self.book.load_account(conn, &self.uid, Some(state.epoch)).await?;
        Ok(())
    }

    /// 旧电脑：拒绝（契约 S20）。
    pub async fn join_reject(&mut self, conn: &Conn, request: &RequestId) -> Result<()> {
        self.require_active()?;
        self.approvals.remove(request);
        conn.request(Request::JoinReject { request: request.clone() }).await?;
        Ok(())
    }

    // ---------- 好友链接 ----------

    /// 我的好友链接（契约 S8）；`rotate` 为真时换一条，旧的立即失效。
    pub async fn friend_link(&mut self, conn: &Conn, rotate: bool) -> Result<FriendLink> {
        self.require_active()?;
        let request = if rotate { Request::RotateFriendLink } else { Request::GetFriendLink };
        let Response::FriendLink { token } = conn.request(request).await? else {
            return Err(ClientError::protocol("回执不对"));
        };
        let eldest = self.me(conn).await?.eldest;
        Ok(FriendLink {
            base: http_base(&self.config.server),
            token,
            eldest,
        })
    }

    /// 按好友链接查对方，并核对链接里的身份指纹（契约 S9“身份已核对”）。
    pub async fn resolve_friend(&mut self, conn: &Conn, link: &FriendLink) -> Result<AccountInfo> {
        self.require_active()?;
        let Response::Profiles { profiles } = conn.request(Request::ResolveFriendLink { token: link.token.clone() }).await? else {
            return Err(ClientError::protocol("回执不对"));
        };
        let info = profiles.into_iter().next().ok_or_else(|| ClientError::protocol("回执不对"))?;
        if info.eldest != Some(link.eldest) {
            return Err(ClientError::verify("好友链接里的身份和服务器上的对不上"));
        }
        self.book.load_account(conn, &info.uid, None).await?;
        if self.book.current(&info.uid).map(|s| s.eldest) != Some(link.eldest) {
            return Err(ClientError::verify("好友链接里的身份和对方的签名链对不上"));
        }
        Ok(info)
    }

    /// 一批账号的名字与身份指纹。
    pub async fn profiles(&mut self, conn: &Conn, uids: &[Uid]) -> Result<Vec<AccountInfo>> {
        self.require_active()?;
        let unique: BTreeSet<Uid> = uids.iter().cloned().collect();
        let Response::Profiles { profiles } = conn.request(Request::GetProfiles { uids: unique.into_iter().collect() }).await? else {
            return Err(ClientError::protocol("回执不对"));
        };
        Ok(profiles)
    }
}

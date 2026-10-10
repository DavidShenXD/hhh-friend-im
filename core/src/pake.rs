//! 新电脑批准握手（SPAKE2，与 magic-wormhole 用短口令传文件同样的做法）。
//!
//! 1. 新电脑随机生成 4 个词（[`JoinCode`]）并显示，用它跑 SPAKE2 的第一步（[`NewDeviceHandshake::start`]），
//!    把这一步的消息和自己的公钥交给服务器。
//! 2. 用户在旧电脑上输入这 4 个词，旧电脑跑完 SPAKE2（[`approver_respond`]），回一个确认码。
//! 3. 新电脑核对旧电脑的确认码（对不上就是输错了），再回自己的确认码（[`NewDeviceHandshake::finish`]）。
//! 4. 旧电脑核对新电脑的确认码（[`ApproverHandshake::check`]），对上了才签“加电脑”。
//!
//! 确认码覆盖新电脑的公钥和名字：服务器在中间换掉新电脑的公钥，两边算出的确认码就对不上。
//! 为什么不让用户“比对一下指纹”：4 个词只有约 44 位，服务器能离线算出指纹相同的假钥匙；
//! SPAKE2 下服务器每猜一次都要真人输一次，5 次上限下成功的机会约是 5 / 2^44。

use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::bytes::{Bytes, Fixed};
use crate::crypto::{self, ctx};
use crate::error::{CoreError, Result};
use crate::ids::{RequestId, Uid};
use crate::keys::DevicePublic;
use crate::words::JoinCode;

const ID_NEW_DEVICE: &[u8] = b"friend-im/v1/join/new-device";
const ID_APPROVER: &[u8] = b"friend-im/v1/join/approver";

/// 一次批准尝试的上下文：两边都要用同样的值算确认码。
pub struct JoinContext<'a> {
    /// 账号。
    pub uid: &'a Uid,
    /// 批准请求。
    pub request: &'a RequestId,
    /// 第几次尝试（从 1 起）：每次输错后新电脑重新跑第一步，旧的确认码不能挪到新的尝试里用。
    pub attempt: u32,
    /// 新电脑的公钥。
    pub device: &'a DevicePublic,
    /// 新电脑的名字。
    pub name: &'a str,
}

fn password(code: &JoinCode, uid: &Uid) -> Password {
    Password::new(crypto::frame(&[code.as_str().as_bytes(), uid.as_str().as_bytes()]))
}

fn transcript(context: &JoinContext<'_>, msg_a: &[u8], msg_b: &[u8]) -> Vec<u8> {
    crypto::frame(&[
        context.uid.as_str().as_bytes(),
        context.request.as_str().as_bytes(),
        &context.attempt.to_be_bytes(),
        &context.device.to_bytes(),
        context.name.as_bytes(),
        msg_a,
        msg_b,
    ])
}

fn confirm(key: &[u8], label: &str, transcript: &[u8]) -> Fixed<32> {
    Fixed(crypto::mac(&*crypto::derive::<32>(key, label), transcript))
}

/// 新电脑这一边。
pub struct NewDeviceHandshake {
    spake: Spake2<Ed25519Group>,
    msg_a: Vec<u8>,
}

impl NewDeviceHandshake {
    /// 用 4 个词跑第一步，返回要交给服务器的消息。
    pub fn start(code: &JoinCode, uid: &Uid) -> (Self, Bytes) {
        let (spake, msg_a) = Spake2::<Ed25519Group>::start_a(&password(code, uid), &Identity::new(ID_NEW_DEVICE), &Identity::new(ID_APPROVER));
        let message = Bytes(msg_a.clone());
        (Self { spake, msg_a }, message)
    }

    /// 收到旧电脑的回应：核对它的确认码，对上了返回自己的确认码；对不上返回 [`CoreError::WrongCode`]（用户输错了）。
    pub fn finish(self, context: &JoinContext<'_>, msg_b: &[u8], approver_confirm: &Fixed<32>) -> Result<Fixed<32>> {
        let key = Zeroizing::new(self.spake.finish(msg_b).map_err(|_| CoreError::WrongCode)?);
        let transcript = transcript(context, &self.msg_a, msg_b);
        let expected = confirm(&key, ctx::KDF_PAKE_CONFIRM_B, &transcript);
        if !crypto::mac_eq(&expected.0, &approver_confirm.0) {
            return Err(CoreError::WrongCode);
        }
        Ok(confirm(&key, ctx::KDF_PAKE_CONFIRM_A, &transcript))
    }
}

/// 旧电脑这一边：跑完 SPAKE2 后留着钥匙，等新电脑的确认码。
pub struct ApproverHandshake {
    key: Zeroizing<Vec<u8>>,
    transcript: Vec<u8>,
}

/// 旧电脑用用户输入的 4 个词回应新电脑的第一步：返回握手现状、要交给服务器的消息和确认码。
pub fn approver_respond(code: &JoinCode, context: &JoinContext<'_>, msg_a: &[u8]) -> Result<(ApproverHandshake, Bytes, Fixed<32>)> {
    let (spake, msg_b) = Spake2::<Ed25519Group>::start_b(&password(code, context.uid), &Identity::new(ID_NEW_DEVICE), &Identity::new(ID_APPROVER));
    let key = Zeroizing::new(spake.finish(msg_a).map_err(|_| CoreError::format("新电脑的握手消息不对"))?);
    let transcript = transcript(context, msg_a, &msg_b);
    let approver_confirm = confirm(&key, ctx::KDF_PAKE_CONFIRM_B, &transcript);
    Ok((ApproverHandshake { key, transcript }, Bytes(msg_b), approver_confirm))
}

impl ApproverHandshake {
    /// 核对新电脑的确认码：对上了，说明新电脑的公钥就是用户眼前那台电脑的，可以签“加电脑”。
    pub fn check(&self, new_device_confirm: &Fixed<32>) -> Result<()> {
        let expected = confirm(&self.key, ctx::KDF_PAKE_CONFIRM_A, &self.transcript);
        if crypto::mac_eq(&expected.0, &new_device_confirm.0) {
            Ok(())
        } else {
            Err(CoreError::WrongCode)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceSecret;

    struct Setup {
        uid: Uid,
        request: RequestId,
        device: DevicePublic,
    }

    fn setup() -> Setup {
        Setup {
            uid: Uid::random(),
            request: RequestId::random(),
            device: DeviceSecret::generate().public(),
        }
    }

    fn context<'a>(s: &'a Setup, device: &'a DevicePublic, attempt: u32) -> JoinContext<'a> {
        JoinContext {
            uid: &s.uid,
            request: &s.request,
            attempt,
            device,
            name: "笔记本",
        }
    }

    #[test]
    fn matching_codes_complete_both_confirmations() {
        let s = setup();
        let code = JoinCode::generate();
        let (new_side, msg_a) = NewDeviceHandshake::start(&code, &s.uid);
        let typed = JoinCode::parse(code.as_str()).unwrap();
        let (approver, msg_b, confirm_b) = approver_respond(&typed, &context(&s, &s.device, 1), &msg_a.0).unwrap();
        let confirm_a = new_side.finish(&context(&s, &s.device, 1), &msg_b.0, &confirm_b).unwrap();
        assert!(approver.check(&confirm_a).is_ok());
    }

    #[test]
    fn mistyped_code_is_detected_by_new_device() {
        let s = setup();
        let code = JoinCode::generate();
        let (new_side, msg_a) = NewDeviceHandshake::start(&code, &s.uid);
        let wrong = loop {
            let other = JoinCode::generate();
            if other != code {
                break other;
            }
        };
        let (_, msg_b, confirm_b) = approver_respond(&wrong, &context(&s, &s.device, 1), &msg_a.0).unwrap();
        assert_eq!(new_side.finish(&context(&s, &s.device, 1), &msg_b.0, &confirm_b), Err(CoreError::WrongCode));
    }

    #[test]
    fn server_swapping_the_new_device_key_is_detected() {
        let s = setup();
        let code = JoinCode::generate();
        let (new_side, msg_a) = NewDeviceHandshake::start(&code, &s.uid);
        // 服务器把新电脑的公钥换成自己的，旧电脑据此算确认码。
        let fake = DeviceSecret::generate().public();
        let (_, msg_b, confirm_b) = approver_respond(&code, &context(&s, &fake, 1), &msg_a.0).unwrap();
        assert_eq!(new_side.finish(&context(&s, &s.device, 1), &msg_b.0, &confirm_b), Err(CoreError::WrongCode));
    }

    #[test]
    fn confirmations_do_not_carry_across_attempts_or_accounts() {
        let s = setup();
        let code = JoinCode::generate();
        let (new_side, msg_a) = NewDeviceHandshake::start(&code, &s.uid);
        let (_, msg_b, confirm_b) = approver_respond(&code, &context(&s, &s.device, 1), &msg_a.0).unwrap();
        assert_eq!(new_side.finish(&context(&s, &s.device, 2), &msg_b.0, &confirm_b), Err(CoreError::WrongCode));
        // 同样的 4 个词，换一个账号也对不上。
        let other = Setup {
            uid: Uid::random(),
            request: s.request.clone(),
            device: s.device,
        };
        let (new_side, msg_a) = NewDeviceHandshake::start(&code, &s.uid);
        let (_, msg_b, confirm_b) = approver_respond(&code, &context(&other, &s.device, 1), &msg_a.0).unwrap();
        assert!(new_side.finish(&context(&s, &s.device, 1), &msg_b.0, &confirm_b).is_err());
    }

    #[test]
    fn approver_rejects_a_forged_new_device_confirmation() {
        let s = setup();
        let code = JoinCode::generate();
        let (_, msg_a) = NewDeviceHandshake::start(&code, &s.uid);
        let (approver, _, _) = approver_respond(&code, &context(&s, &s.device, 1), &msg_a.0).unwrap();
        assert_eq!(approver.check(&Fixed([0; 32])), Err(CoreError::WrongCode));
    }
}

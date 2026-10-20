//! 账号签名链：一个账号的电脑、恢复密钥和账号钥匙的全部变化，每一环由有权限的钥匙签名。
//!
//! 每一环是 `{版本, 账号, 重置轮次, 序号, 上一环摘要, 时间, 变化}`，签名人签的是这段原文的字节（[`AccountLink::body`]），
//! 不用重新序列化，避免“同一个 JSON 两种写法”的歧义。
//!
//! | 变化 | 谁签 | 附带 |
//! |---|---|---|
//! | 开通（第一环） | 第一台电脑 | 恢复密钥的公钥与它的证明、账号钥匙第一代 |
//! | 加电脑 | 已有电脑或恢复密钥 | 新电脑的证明（证明私钥在它手里） |
//! | 移除电脑 | 已有电脑 | 移除别的电脑时必须同时换代；电脑退出自己时可以不换，由别的电脑稍后补换 |
//! | 账号钥匙换代 | 已有电脑 | 新一代 |
//! | 换恢复密钥 | 已有电脑 | 新恢复密钥的证明、新一代 |
//!
//! 插件只认签名正确、序号连续、类型合规的链：服务器私自加电脑，签名对不上，插件拒绝并提醒用户（契约 §5）。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bytes::{Bytes, Fixed};
use crate::crypto::{self, ctx};
use crate::error::{CoreError, Result};
use crate::ids::{DeviceId, Uid};
use crate::wire::DeviceKind;
use crate::keys::{AccountKeyPub, DevicePublic, DeviceSecret};

/// 签名链格式版本。
pub const LINK_VERSION: u32 = 1;
/// 一环原文的上限：一环里最多两把公钥加一个名字，16 KiB 绰绰有余，防止服务器塞超大数据拖垮插件。
pub const LINK_BODY_MAX: usize = 16 * 1024;
/// 电脑名最长多少个字符。
pub const DEVICE_NAME_MAX_CHARS: usize = 64;

/// 校验电脑名：1–64 个字符，不含控制字符。
pub fn check_device_name(name: &str) -> Result<()> {
    let count = name.chars().count();
    if count == 0 || count > DEVICE_NAME_MAX_CHARS || name.chars().any(char::is_control) {
        return Err(CoreError::format("电脑名应是 1–64 个字符、不含控制字符"));
    }
    Ok(())
}

/// 一台新加入的电脑：公钥 + 名字。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntry {
    /// 公钥。
    pub keys: DevicePublic,
    /// 给人看的电脑名。
    pub name: String,
    /// 设备类别；旧签名链没有时按电脑处理。
    #[serde(default, skip_serializing_if = "DeviceKind::is_unknown")]
    pub kind: DeviceKind,
}

/// 新钥匙的“证明”扮演的角色：电脑，或恢复密钥。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofRole {
    /// 一台电脑。
    Device,
    /// 恢复密钥。
    Recovery,
}

impl ProofRole {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Device => b"device",
            Self::Recovery => b"recovery",
        }
    }
}

fn proof_message(uid: &Uid, epoch: u32, keys: &DevicePublic, role: ProofRole) -> Vec<u8> {
    crypto::frame(&[uid.as_str().as_bytes(), &epoch.to_be_bytes(), &keys.to_bytes(), role.label()])
}

/// 新钥匙用自己签一份“我要加入这个账号的这一轮”：证明私钥在它手里，也不能被挪到别的账号或别的轮次。
pub fn device_proof(secret: &DeviceSecret, uid: &Uid, epoch: u32, role: ProofRole) -> Fixed<64> {
    secret.sign(ctx::DEVICE_PROOF, &proof_message(uid, epoch, &secret.public(), role))
}

/// 核对 [`device_proof`]：服务器收到批准请求时先验一遍，旧电脑签“加电脑”时链上还会再验。
pub fn check_proof(keys: &DevicePublic, proof: &Fixed<64>, uid: &Uid, epoch: u32, role: ProofRole) -> Result<()> {
    keys.verify(ctx::DEVICE_PROOF, &proof_message(uid, epoch, keys, role), proof)
}

/// 签名链一环里的变化。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AccountChange {
    /// 开通：第一台电脑、恢复密钥、账号钥匙第一代。
    Eldest {
        /// 第一台电脑。
        device: DeviceEntry,
        /// 恢复密钥派生出的公钥。
        recovery: DevicePublic,
        /// 恢复密钥的证明。
        recovery_proof: Fixed<64>,
        /// 账号钥匙第一代。
        key: AccountKeyPub,
    },
    /// 加电脑。
    AddDevice {
        /// 新电脑。
        device: DeviceEntry,
        /// 新电脑的证明。
        proof: Fixed<64>,
    },
    /// 移除电脑；`key` 为换出的新一代（电脑退出自己时可以为空）。
    RemoveDevice {
        /// 被移除的电脑。
        device: DeviceId,
        /// 新一代账号钥匙。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<AccountKeyPub>,
    },
    /// 账号钥匙换代（补上电脑退出自己时没换的那一代）。
    RotateKey {
        /// 新一代。
        key: AccountKeyPub,
    },
    /// 换恢复密钥（旧的立即失效），同时换代：旧恢复密钥拿不到新一代。
    ReplaceRecovery {
        /// 新恢复密钥的公钥。
        recovery: DevicePublic,
        /// 新恢复密钥的证明。
        proof: Fixed<64>,
        /// 新一代账号钥匙。
        key: AccountKeyPub,
    },
}

/// 一环的原文（签名覆盖它的字节）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountLinkBody {
    /// 格式版本。
    pub v: u32,
    /// 账号。
    pub uid: Uid,
    /// 重置轮次：账号每重置一次加 1，新一轮从第一环重新开始。
    pub epoch: u32,
    /// 序号，从 1 起，连续。
    pub seq: u64,
    /// 上一环的摘要（第一环为空）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Fixed<32>>,
    /// 签名时的本机时间（毫秒，只作展示）。
    pub ctime_ms: i64,
    /// 变化。
    pub change: AccountChange,
}

/// 签名链的一环：原文字节 + 签名人 + 签名。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountLink {
    /// 原文（[`AccountLinkBody`] 的 JSON 字节）。
    pub body: Bytes,
    /// 签名人：一台电脑或恢复密钥的编号。
    pub by: DeviceId,
    /// 签名。
    pub sig: Fixed<64>,
}

impl AccountLink {
    /// 签一环。
    pub fn sign(body: &AccountLinkBody, signer: &DeviceSecret) -> Self {
        let bytes = serde_json::to_vec(body).expect("签名链一环一定能写成 JSON");
        let sig = signer.sign(ctx::ACCOUNT_LINK, &bytes);
        Self {
            body: Bytes(bytes),
            by: signer.id(),
            sig,
        }
    }

    /// 解出原文。
    pub fn parse(&self) -> Result<AccountLinkBody> {
        if self.body.len() > LINK_BODY_MAX {
            return Err(CoreError::Limit("签名链一环太大".into()));
        }
        serde_json::from_slice(&self.body.0).map_err(|_| CoreError::format("签名链一环读不懂"))
    }

    /// 这一环的摘要（下一环的 `prev`；第一环的摘要就是账号的身份指纹）。
    pub fn hash(&self) -> Fixed<32> {
        Fixed(crypto::hash(ctx::ACCOUNT_LINK, &self.body.0))
    }
}

/// 签名链里的位置：链上序号 + 服务器日志序号（服务器给的统一时钟，用来判断一条消息签出时那台电脑还在不在）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Position {
    /// 链上序号。
    pub seq: u64,
    /// 服务器日志序号。
    pub log: u64,
}

/// 链上记录的一台电脑。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    /// 公钥。
    pub keys: DevicePublic,
    /// 电脑名。
    pub name: String,
    /// 设备类别。
    pub kind: DeviceKind,
    /// 加入的位置。
    pub added: Position,
    /// 被移除的位置（还在则为空）。
    pub removed: Option<Position>,
}

/// 按签名链算出的账号现状。只能由 [`AccountState::eldest`] 和 [`AccountState::apply`] 一环一环验过来。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountState {
    /// 账号。
    pub uid: Uid,
    /// 重置轮次。
    pub epoch: u32,
    /// 第一环的摘要：账号这一轮的身份指纹（好友链接里带它，重置后会变）。
    pub eldest: Fixed<32>,
    /// 最新一环的摘要。
    pub head: Fixed<32>,
    /// 最新一环的序号。
    pub seq: u64,
    /// 链上出现过的全部电脑（含已移除）。
    pub devices: BTreeMap<DeviceId, DeviceRecord>,
    /// 当前的恢复密钥公钥。
    pub recovery: DevicePublic,
    /// 账号钥匙各代（下标 = 代数 - 1）。
    pub keys: Vec<AccountKeyPub>,
    /// 有电脑退出了自己但账号钥匙还没换代：下一台上线的电脑要先换代（[`AccountChange::RotateKey`]）。
    pub rotation_pending: bool,
}

impl AccountState {
    /// 验第一环，得到初始现状。`uid`、`epoch` 是调用方期望的账号与轮次（来自服务器的分组，不是链里自报的）。
    pub fn eldest(uid: &Uid, epoch: u32, link: &AccountLink, log: u64) -> Result<Self> {
        let body = link.parse()?;
        if body.v != LINK_VERSION || &body.uid != uid || body.epoch != epoch || body.seq != 1 || body.prev.is_some() {
            return Err(CoreError::chain("第一环的账号、轮次、序号不对"));
        }
        let AccountChange::Eldest {
            device,
            recovery,
            recovery_proof,
            key,
        } = &body.change
        else {
            return Err(CoreError::chain("第一环必须是开通"));
        };
        check_device_name(&device.name)?;
        device.keys.check()?;
        recovery.check()?;
        let device_id = device.keys.id();
        if device_id == recovery.id() {
            return Err(CoreError::chain("电脑和恢复密钥不能是同一把钥匙"));
        }
        if key.generation != 1 {
            return Err(CoreError::chain("账号钥匙应从第 1 代开始"));
        }
        if link.by != device_id {
            return Err(CoreError::chain("第一环应由第一台电脑签"));
        }
        device.keys.verify(ctx::ACCOUNT_LINK, &link.body.0, &link.sig)?;
        check_proof(recovery, recovery_proof, uid, epoch, ProofRole::Recovery)?;
        let position = Position { seq: 1, log };
        let hash = link.hash();
        let mut devices = BTreeMap::new();
        devices.insert(
            device_id,
            DeviceRecord {
                keys: device.keys,
                name: device.name.clone(),
                kind: device.kind,
                added: position,
                removed: None,
            },
        );
        Ok(Self {
            uid: uid.clone(),
            epoch,
            eldest: hash,
            head: hash,
            seq: 1,
            devices,
            recovery: *recovery,
            keys: vec![*key],
            rotation_pending: false,
        })
    }

    /// 从头验一整条链。`links` 按序号排好，每环带服务器日志序号。
    pub fn verify_chain(uid: &Uid, epoch: u32, links: &[(AccountLink, u64)]) -> Result<Self> {
        let ((first, log), rest) = links.split_first().ok_or_else(|| CoreError::chain("签名链是空的"))?;
        let mut state = Self::eldest(uid, epoch, first, *log)?;
        for (link, log) in rest {
            state.apply(link, *log)?;
        }
        Ok(state)
    }

    /// 在现状上接一环；验不过时现状不变。
    pub fn apply(&mut self, link: &AccountLink, log: u64) -> Result<()> {
        let mut next = self.clone();
        next.apply_in_place(link, log)?;
        *self = next;
        Ok(())
    }

    fn apply_in_place(&mut self, link: &AccountLink, log: u64) -> Result<()> {
        let body = link.parse()?;
        if body.v != LINK_VERSION || body.uid != self.uid || body.epoch != self.epoch {
            return Err(CoreError::chain("这一环不属于这个账号的这一轮"));
        }
        if body.seq != self.seq + 1 || body.prev != Some(self.head) {
            return Err(CoreError::chain("序号不连续或上一环摘要对不上"));
        }
        let position = Position { seq: body.seq, log };
        match &body.change {
            AccountChange::Eldest { .. } => return Err(CoreError::chain("开通只能是第一环")),
            AccountChange::AddDevice { device, proof } => {
                // 已有电脑或恢复密钥都可以批准新电脑。
                let signer = self
                    .active_key(&link.by)
                    .or_else(|| (self.recovery.id() == link.by).then_some(self.recovery))
                    .ok_or_else(|| CoreError::chain("签名人不是这个账号现有的电脑或恢复密钥"))?;
                signer.verify(ctx::ACCOUNT_LINK, &link.body.0, &link.sig)?;
                check_device_name(&device.name)?;
                device.keys.check()?;
                let id = device.keys.id();
                if self.devices.contains_key(&id) || id == self.recovery.id() {
                    return Err(CoreError::chain("这台电脑已经在链上出现过"));
                }
                check_proof(&device.keys, proof, &self.uid, self.epoch, ProofRole::Device)?;
                self.devices.insert(
                    id,
                    DeviceRecord {
                        keys: device.keys,
                        name: device.name.clone(),
                        kind: device.kind,
                        added: position,
                        removed: None,
                    },
                );
            }
            AccountChange::RemoveDevice { device, key } => {
                let signer = self.active_key(&link.by).ok_or_else(|| CoreError::chain("签名人不是这个账号现有的电脑"))?;
                signer.verify(ctx::ACCOUNT_LINK, &link.body.0, &link.sig)?;
                if self.active_key(device).is_none() {
                    return Err(CoreError::chain("要移除的电脑不在账号里"));
                }
                match key {
                    Some(key) => self.push_key(key)?,
                    // 移除别的电脑必须当场换代：那台电脑拿得到旧代，不换就还能读之后的消息。
                    None if &link.by != device => return Err(CoreError::chain("移除别的电脑必须同时换代")),
                    None => self.rotation_pending = true,
                }
                if let Some(record) = self.devices.get_mut(device) {
                    record.removed = Some(position);
                }
            }
            AccountChange::RotateKey { key } => {
                let signer = self.active_key(&link.by).ok_or_else(|| CoreError::chain("签名人不是这个账号现有的电脑"))?;
                signer.verify(ctx::ACCOUNT_LINK, &link.body.0, &link.sig)?;
                self.push_key(key)?;
            }
            AccountChange::ReplaceRecovery { recovery, proof, key } => {
                let signer = self.active_key(&link.by).ok_or_else(|| CoreError::chain("签名人不是这个账号现有的电脑"))?;
                signer.verify(ctx::ACCOUNT_LINK, &link.body.0, &link.sig)?;
                recovery.check()?;
                let id = recovery.id();
                if self.devices.contains_key(&id) || id == self.recovery.id() {
                    return Err(CoreError::chain("新恢复密钥不能是已有的钥匙"));
                }
                check_proof(recovery, proof, &self.uid, self.epoch, ProofRole::Recovery)?;
                self.push_key(key)?;
                self.recovery = *recovery;
            }
        }
        self.seq = body.seq;
        self.head = link.hash();
        Ok(())
    }

    fn push_key(&mut self, key: &AccountKeyPub) -> Result<()> {
        if key.generation != self.current_key().generation + 1 {
            return Err(CoreError::chain("账号钥匙代数不连续"));
        }
        self.keys.push(*key);
        self.rotation_pending = false;
        Ok(())
    }

    fn active_key(&self, id: &DeviceId) -> Option<DevicePublic> {
        self.devices.get(id).filter(|d| d.removed.is_none()).map(|d| d.keys)
    }

    /// 现在还在的电脑。
    pub fn active_devices(&self) -> impl Iterator<Item = (&DeviceId, &DeviceRecord)> {
        self.devices.iter().filter(|(_, d)| d.removed.is_none())
    }

    /// 这台电脑现在在不在账号里。
    pub fn is_active(&self, id: &DeviceId) -> bool {
        self.active_key(id).is_some()
    }

    /// 某台电脑在服务器日志位置 `log` 时是否有效（加入之后、移除之前），有效返回公钥。
    /// 用来验消息和会话签名链：被移除的电脑之后签的东西一律不认。
    pub fn device_at(&self, id: &DeviceId, log: u64) -> Option<DevicePublic> {
        let record = self.devices.get(id)?;
        let joined = record.added.log <= log;
        let still_there = record.removed.is_none_or(|removed| log < removed.log);
        (joined && still_there).then_some(record.keys)
    }

    /// 账号钥匙当前一代。
    pub fn current_key(&self) -> &AccountKeyPub {
        self.keys.last().expect("账号钥匙至少有第一代")
    }

    /// 账号钥匙某一代。
    pub fn key(&self, generation: u32) -> Option<&AccountKeyPub> {
        generation.checked_sub(1).and_then(|i| self.keys.get(i as usize))
    }

    /// 给下一环填好账号、轮次、序号与上一环摘要。
    pub fn next_body(&self, change: AccountChange, ctime_ms: i64) -> AccountLinkBody {
        AccountLinkBody {
            v: LINK_VERSION,
            uid: self.uid.clone(),
            epoch: self.epoch,
            seq: self.seq + 1,
            prev: Some(self.head),
            ctime_ms,
            change,
        }
    }
}

/// 第一环的原文。
pub fn eldest_body(uid: &Uid, epoch: u32, device: DeviceEntry, recovery: &DeviceSecret, key: AccountKeyPub, ctime_ms: i64) -> AccountLinkBody {
    AccountLinkBody {
        v: LINK_VERSION,
        uid: uid.clone(),
        epoch,
        seq: 1,
        prev: None,
        ctime_ms,
        change: AccountChange::Eldest {
            device,
            recovery: recovery.public(),
            recovery_proof: device_proof(recovery, uid, epoch, ProofRole::Recovery),
            key,
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::{AccountSeed, RecoveryKey};

    pub(crate) struct Fixture {
        pub uid: Uid,
        pub device: DeviceSecret,
        pub recovery: RecoveryKey,
        pub seed: AccountSeed,
        pub links: Vec<(AccountLink, u64)>,
        pub state: AccountState,
    }

    pub(crate) fn entry(secret: &DeviceSecret, name: &str) -> DeviceEntry {
        DeviceEntry {
            keys: secret.public(),
            name: name.into(),
            kind: DeviceKind::Computer,
        }
    }

    pub(crate) fn provisioned() -> Fixture {
        let uid = Uid::random();
        let device = DeviceSecret::generate();
        let recovery = RecoveryKey::generate();
        let seed = AccountSeed::generate();
        let body = eldest_body(&uid, 0, entry(&device, "台式机"), &recovery.device_secret(), seed.public(1), 1);
        let link = AccountLink::sign(&body, &device);
        let state = AccountState::eldest(&uid, 0, &link, 10).unwrap();
        Fixture {
            uid,
            device,
            recovery,
            seed,
            links: vec![(link, 10)],
            state,
        }
    }

    fn add_device(f: &mut Fixture, signer: &DeviceSecret, log: u64) -> DeviceSecret {
        let new = DeviceSecret::generate();
        let change = AccountChange::AddDevice {
            device: entry(&new, "笔记本"),
            proof: device_proof(&new, &f.uid, 0, ProofRole::Device),
        };
        let link = AccountLink::sign(&f.state.next_body(change, 2), signer);
        f.state.apply(&link, log).unwrap();
        f.links.push((link, log));
        new
    }

    #[test]
    fn eldest_then_add_device_by_device_and_by_recovery() {
        let mut f = provisioned();
        let device = f.device.clone();
        let laptop = add_device(&mut f, &device, 11);
        let recovery = f.recovery.device_secret();
        let tablet = add_device(&mut f, &recovery, 12);
        assert!(f.state.is_active(&laptop.id()));
        assert!(f.state.is_active(&tablet.id()));
        assert_eq!(f.state.active_devices().count(), 3);
        // 从头验一遍得到同样的现状。
        assert_eq!(AccountState::verify_chain(&f.uid, 0, &f.links).unwrap(), f.state);
    }

    #[test]
    fn stranger_cannot_add_a_device() {
        let mut f = provisioned();
        let stranger = DeviceSecret::generate();
        let new = DeviceSecret::generate();
        let change = AccountChange::AddDevice {
            device: entry(&new, "x"),
            proof: device_proof(&new, &f.uid, 0, ProofRole::Device),
        };
        let link = AccountLink::sign(&f.state.next_body(change, 2), &stranger);
        let before = f.state.clone();
        assert!(matches!(f.state.apply(&link, 11), Err(CoreError::Chain(_))));
        assert_eq!(f.state, before, "验不过时现状不变");
    }

    #[test]
    fn forged_signature_or_missing_proof_is_rejected() {
        let f = provisioned();
        let new = DeviceSecret::generate();
        // 证明是给别的账号签的。
        let change = AccountChange::AddDevice {
            device: entry(&new, "x"),
            proof: device_proof(&new, &Uid::random(), 0, ProofRole::Device),
        };
        let link = AccountLink::sign(&f.state.next_body(change, 2), &f.device);
        assert_eq!(f.state.clone().apply(&link, 11), Err(CoreError::BadSignature));
        // 原文被改过。
        let change = AccountChange::AddDevice {
            device: entry(&new, "x"),
            proof: device_proof(&new, &f.uid, 0, ProofRole::Device),
        };
        let mut link = AccountLink::sign(&f.state.next_body(change, 2), &f.device);
        link.body.0[10] ^= 1;
        assert!(f.state.clone().apply(&link, 11).is_err());
    }

    #[test]
    fn gaps_reorders_and_wrong_prev_are_rejected() {
        let mut f = provisioned();
        let device = f.device.clone();
        let _ = add_device(&mut f, &device, 11);
        let third = {
            let new = DeviceSecret::generate();
            let change = AccountChange::AddDevice {
                device: entry(&new, "c"),
                proof: device_proof(&new, &f.uid, 0, ProofRole::Device),
            };
            AccountLink::sign(&f.state.next_body(change, 3), &f.device)
        };
        // 缺第二环。
        let gap = vec![f.links[0].clone(), (third.clone(), 12)];
        assert!(AccountState::verify_chain(&f.uid, 0, &gap).is_err());
        // 链属于别的账号或别的轮次。
        assert!(AccountState::verify_chain(&Uid::random(), 0, &f.links).is_err());
        assert!(AccountState::verify_chain(&f.uid, 1, &f.links).is_err());
        // 第一环换成别的类型。
        assert!(AccountState::verify_chain(&f.uid, 0, &f.links[1..]).is_err());
    }

    #[test]
    fn removing_another_device_requires_rotation_and_cuts_it_off() {
        let mut f = provisioned();
        let device = f.device.clone();
        let laptop = add_device(&mut f, &device, 11);
        let no_rotation = AccountLink::sign(
            &f.state.next_body(
                AccountChange::RemoveDevice {
                    device: laptop.id(),
                    key: None,
                },
                3,
            ),
            &f.device,
        );
        assert!(f.state.clone().apply(&no_rotation, 12).is_err());
        let next = AccountSeed::generate();
        let remove = AccountLink::sign(
            &f.state.next_body(
                AccountChange::RemoveDevice {
                    device: laptop.id(),
                    key: Some(next.public(2)),
                },
                3,
            ),
            &f.device,
        );
        f.state.apply(&remove, 12).unwrap();
        assert!(!f.state.is_active(&laptop.id()));
        assert_eq!(f.state.current_key().generation, 2);
        // 被移除的电脑之前签的仍认，之后签的不认。
        assert!(f.state.device_at(&laptop.id(), 11).is_some());
        assert!(f.state.device_at(&laptop.id(), 12).is_none());
        // 它也不能再签链。
        let link = AccountLink::sign(&f.state.next_body(AccountChange::RotateKey { key: AccountSeed::generate().public(3) }, 4), &laptop);
        assert!(f.state.clone().apply(&link, 13).is_err());
    }

    #[test]
    fn self_removal_may_defer_rotation_until_another_device_rotates() {
        let mut f = provisioned();
        let device = f.device.clone();
        let laptop = add_device(&mut f, &device, 11);
        let leave = AccountLink::sign(
            &f.state.next_body(
                AccountChange::RemoveDevice {
                    device: laptop.id(),
                    key: None,
                },
                3,
            ),
            &laptop,
        );
        f.state.apply(&leave, 12).unwrap();
        assert!(f.state.rotation_pending);
        let rotate = AccountLink::sign(&f.state.next_body(AccountChange::RotateKey { key: AccountSeed::generate().public(2) }, 4), &f.device);
        f.state.apply(&rotate, 13).unwrap();
        assert!(!f.state.rotation_pending);
        // 代数必须连续。
        let skip = AccountLink::sign(&f.state.next_body(AccountChange::RotateKey { key: AccountSeed::generate().public(9) }, 5), &f.device);
        assert!(f.state.clone().apply(&skip, 14).is_err());
    }

    #[test]
    fn replaced_recovery_key_can_no_longer_add_devices() {
        let mut f = provisioned();
        let old_recovery = f.recovery.device_secret();
        let new_recovery = RecoveryKey::generate().device_secret();
        let change = AccountChange::ReplaceRecovery {
            recovery: new_recovery.public(),
            proof: device_proof(&new_recovery, &f.uid, 0, ProofRole::Recovery),
            key: AccountSeed::generate().public(2),
        };
        let link = AccountLink::sign(&f.state.next_body(change, 2), &f.device);
        f.state.apply(&link, 11).unwrap();
        let new = DeviceSecret::generate();
        let change = AccountChange::AddDevice {
            device: entry(&new, "x"),
            proof: device_proof(&new, &f.uid, 0, ProofRole::Device),
        };
        let by_old = AccountLink::sign(&f.state.next_body(change.clone(), 3), &old_recovery);
        assert!(f.state.clone().apply(&by_old, 12).is_err());
        let by_new = AccountLink::sign(&f.state.next_body(change, 3), &new_recovery);
        assert!(f.state.clone().apply(&by_new, 12).is_ok());
    }

    #[test]
    fn removed_device_cannot_rejoin_with_same_key() {
        let mut f = provisioned();
        let device = f.device.clone();
        let laptop = add_device(&mut f, &device, 11);
        let remove = AccountLink::sign(
            &f.state.next_body(
                AccountChange::RemoveDevice {
                    device: laptop.id(),
                    key: Some(AccountSeed::generate().public(2)),
                },
                3,
            ),
            &f.device,
        );
        f.state.apply(&remove, 12).unwrap();
        let change = AccountChange::AddDevice {
            device: entry(&laptop, "又来了"),
            proof: device_proof(&laptop, &f.uid, 0, ProofRole::Device),
        };
        let link = AccountLink::sign(&f.state.next_body(change, 4), &f.device);
        assert!(f.state.clone().apply(&link, 13).is_err());
    }

    #[test]
    fn device_names_are_validated() {
        assert!(check_device_name("台式机").is_ok());
        assert!(check_device_name("").is_err());
        assert!(check_device_name("a\nb").is_err());
        assert!(check_device_name(&"字".repeat(65)).is_err());
    }
}

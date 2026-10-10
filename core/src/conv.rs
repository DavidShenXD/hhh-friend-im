//! 会话签名链：一个私聊或群的成员、钥匙代数、群资料、群邀请的全部变化，每一环由成员的电脑签名。
//!
//! | 变化 | 谁能签 |
//! |---|---|
//! | 建会话（成员表、钥匙第一代、加密的群资料） | 建的人（成为群主） |
//! | 邀请成员 | 任何成员（契约 §12 第 6 项），写明被邀请人账号签名链第一环的摘要 |
//! | 凭群邀请链接加入 | 加入的人自己，另用链接里的邀请钥匙签一份证明 |
//! | 移出成员 | 群主；对方重置了账号时任何成员都可以补签 |
//! | 退群 | 本人 |
//! | 换代 | 任何成员 |
//! | 私聊对方重置后改记新身份并换代 | 两边任何一方 |
//! | 改群资料、发 / 作废群邀请 | 任何成员 |
//!
//! 有人被移出或退群后，钥匙在下一次换代之前标为“待换代”（[`ConvState::rotation_pending`]）：
//! 任何成员在用这个会话加密新内容之前必须先换代，所以离开的人拿不到之后的钥匙。
//! 群主移出别人时服务器要求同一个请求里带上换代（见服务器），这里只记待换代。
//!
//! 签名人的电脑是否属于这个账号由调用方的 [`Directory`] 判断（插件按自己验过的账号签名链，服务器按库里的链）。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bytes::{Bytes, Fixed};
use crate::crypto::{self, ctx};
use crate::error::{CoreError, Result};
use crate::file::FileRef;
use crate::ids::{ConvId, DeviceId, InviteId, Uid};
use crate::keys::{ConvKeyPub, ConvSeed, DevicePublic, DeviceSecret, InviteSecret};

/// 会话签名链格式版本。
pub const LINK_VERSION: u32 = 1;
/// 一环原文的上限：群资料密文最大的一环也远小于 64 KiB。
pub const LINK_BODY_MAX: usize = 64 * 1024;
/// 群资料密文上限（群名、简介、头像引用）。
pub const PROFILE_MAX: usize = 16 * 1024;
/// 群人数上限（与服务器上限一致）。
pub const GROUP_MAX_MEMBERS: usize = 200;

/// 签名链之外的账号信息：某账号某台电脑在某时是否有效，某账号当前的身份指纹。
pub trait Directory {
    /// 身份指纹为 `eldest` 的那一轮账号签名链里，电脑 `device` 在服务器日志位置 `log` 时是否有效；有效返回公钥。
    fn device(&self, uid: &Uid, eldest: &Fixed<32>, device: &DeviceId, log: u64) -> Option<DevicePublic>;
    /// 某账号当前这一轮的身份指纹（第一环摘要）；不知道返回 `None`。
    fn eldest(&self, uid: &Uid) -> Option<Fixed<32>>;
}

/// 会话类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvKind {
    /// 私聊：固定两个人。
    Dm,
    /// 群。
    Group,
}

/// 成员：账号 + 当时核对过的身份指纹。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRef {
    /// 账号。
    pub uid: Uid,
    /// 账号签名链第一环的摘要。
    pub eldest: Fixed<32>,
}

/// 私聊是怎么来的（决定第一条系统提示）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Via {
    /// 通过好友链接添加，身份已核对。
    FriendLink,
    /// 在某个群里认识的。
    Group {
        /// 那个群。
        conv: ConvId,
    },
}

/// 被移出的原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoveReason {
    /// 群主移出。
    Kicked,
    /// 对方重置了账号（契约 S7：重置后自动退出所有群）。
    Reset,
}

/// 会话签名链一环里的变化。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConvChange {
    /// 建会话。
    Create {
        /// 类型。
        kind: ConvKind,
        /// 全部成员（含建的人）。
        members: Vec<MemberRef>,
        /// 钥匙第一代。
        key: ConvKeyPub,
        /// 加密的群资料（私聊没有）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<Bytes>,
        /// 私聊的来源。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via: Option<Via>,
    },
    /// 邀请成员。
    Add {
        /// 新成员。
        members: Vec<MemberRef>,
    },
    /// 凭群邀请链接加入。
    JoinByInvite {
        /// 加入的人（就是签名人）。
        member: MemberRef,
        /// 邀请编号。
        invite: InviteId,
        /// 邀请钥匙签的证明（见 [`invite_join_proof`]）。
        proof: Fixed<64>,
    },
    /// 移出成员。
    Remove {
        /// 被移出的人。
        uid: Uid,
        /// 原因。
        reason: RemoveReason,
    },
    /// 退群。
    Leave,
    /// 换代。
    Rotate {
        /// 新一代。
        key: ConvKeyPub,
    },
    /// 私聊里对方重置了账号：改记新身份并换代（新钥匙封装给对方的新账号钥匙）。
    MemberReset {
        /// 对方的新身份。
        member: MemberRef,
        /// 新一代。
        key: ConvKeyPub,
    },
    /// 改群资料。
    SetProfile {
        /// 加密的群资料。
        profile: Bytes,
        /// 用哪一代钥匙加密的。
        generation: u32,
    },
    /// 发群邀请链接。
    CreateInvite {
        /// 邀请编号。
        invite: InviteId,
        /// 邀请签名公钥。
        public: Fixed<32>,
        /// 过期时间（毫秒）。
        expires_ms: i64,
    },
    /// 作废群邀请链接。
    RevokeInvite {
        /// 邀请编号。
        invite: InviteId,
    },
}

/// 一环的原文。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvLinkBody {
    /// 格式版本。
    pub v: u32,
    /// 会话。
    pub conv: ConvId,
    /// 序号，从 1 起，连续。
    pub seq: u64,
    /// 上一环摘要。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Fixed<32>>,
    /// 签名时的本机时间（毫秒）。
    pub ctime_ms: i64,
    /// 签名的账号。
    pub author: Uid,
    /// 签名的账号当时的身份指纹（重置前后的同一个人用它区分）。
    pub author_eldest: Fixed<32>,
    /// 变化。
    pub change: ConvChange,
}

/// 会话签名链的一环。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvLink {
    /// 原文字节。
    pub body: Bytes,
    /// 签名的电脑。
    pub by: DeviceId,
    /// 签名。
    pub sig: Fixed<64>,
}

impl ConvLink {
    /// 签一环。
    pub fn sign(body: &ConvLinkBody, signer: &DeviceSecret) -> Self {
        let bytes = serde_json::to_vec(body).expect("会话签名链一环一定能写成 JSON");
        let sig = signer.sign(ctx::CONV_LINK, &bytes);
        Self {
            body: Bytes(bytes),
            by: signer.id(),
            sig,
        }
    }

    /// 解出原文。
    pub fn parse(&self) -> Result<ConvLinkBody> {
        if self.body.len() > LINK_BODY_MAX {
            return Err(CoreError::Limit("会话签名链一环太大".into()));
        }
        serde_json::from_slice(&self.body.0).map_err(|_| CoreError::format("会话签名链一环读不懂"))
    }

    /// 这一环的摘要。
    pub fn hash(&self) -> Fixed<32> {
        Fixed(crypto::hash(ctx::CONV_LINK, &self.body.0))
    }
}

fn invite_join_message(conv: &ConvId, invite: &InviteId, member: &MemberRef) -> Vec<u8> {
    crypto::frame(&[conv.as_str().as_bytes(), invite.as_str().as_bytes(), member.uid.as_str().as_bytes(), &member.eldest.0])
}

/// 凭群邀请链接加入时，用链接里的邀请钥匙签的证明：成员据此确认加入的人确实拿到了链接（服务器没有链接里的钥匙，冒充不了）。
pub fn invite_join_proof(secret: &InviteSecret, conv: &ConvId, invite: &InviteId, member: &MemberRef) -> Fixed<64> {
    secret.sign(ctx::INVITE_JOIN, &invite_join_message(conv, invite, member))
}

/// 一个成员的现状。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberState {
    /// 身份指纹。
    pub eldest: Fixed<32>,
    /// 加入时的服务器日志序号。
    pub joined_log: u64,
}

/// 一个群邀请链接的现状。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteState {
    /// 邀请签名公钥。
    pub public: Fixed<32>,
    /// 过期时间（毫秒）。
    pub expires_ms: i64,
    /// 是否已作废。
    pub revoked: bool,
}

/// 按签名链算出的会话现状。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConvState {
    /// 会话。
    pub conv: ConvId,
    /// 类型。
    pub kind: ConvKind,
    /// 群主（建的人）。
    pub owner: Uid,
    /// 私聊的来源。
    pub via: Option<Via>,
    /// 现在的成员。
    pub members: BTreeMap<Uid, MemberState>,
    /// 离开过的人：离开时的服务器日志序号。
    pub former: BTreeMap<Uid, u64>,
    /// 钥匙各代（下标 = 代数 - 1）。
    pub keys: Vec<ConvKeyPub>,
    /// 有人离开后还没换代。
    pub rotation_pending: bool,
    /// 群邀请。
    pub invites: BTreeMap<InviteId, InviteState>,
    /// 最新的群资料：密文 + 用哪一代加密的。
    pub profile: Option<(Bytes, u32)>,
    /// 最新一环的序号。
    pub seq: u64,
    /// 最新一环的摘要。
    pub head: Fixed<32>,
}

fn check_members_unique(members: &[MemberRef]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    if members.iter().all(|m| seen.insert(&m.uid)) {
        Ok(())
    } else {
        Err(CoreError::chain("成员重复"))
    }
}

impl ConvState {
    /// 验第一环。
    pub fn create(conv: &ConvId, link: &ConvLink, log: u64, directory: &dyn Directory) -> Result<Self> {
        let body = link.parse()?;
        if body.v != LINK_VERSION || &body.conv != conv || body.seq != 1 || body.prev.is_some() {
            return Err(CoreError::chain("第一环的会话或序号不对"));
        }
        let ConvChange::Create {
            kind,
            members,
            key,
            profile,
            via,
        } = &body.change
        else {
            return Err(CoreError::chain("第一环必须是建会话"));
        };
        check_members_unique(members)?;
        let author = members
            .iter()
            .find(|m| m.uid == body.author && m.eldest == body.author_eldest)
            .ok_or_else(|| CoreError::chain("建会话的人必须在成员里"))?;
        verify_author(link, &body, author, log, directory)?;
        match kind {
            ConvKind::Dm if members.len() != 2 || profile.is_some() => {
                return Err(CoreError::chain("私聊必须正好两个人、没有群资料"));
            }
            ConvKind::Group if members.is_empty() || members.len() > GROUP_MAX_MEMBERS || via.is_some() => {
                return Err(CoreError::chain("群的人数不对"));
            }
            _ => {}
        }
        if profile.as_ref().is_some_and(|p| p.len() > PROFILE_MAX) {
            return Err(CoreError::Limit("群资料太大".into()));
        }
        if key.generation != 1 {
            return Err(CoreError::chain("会话钥匙应从第 1 代开始"));
        }
        Ok(Self {
            conv: conv.clone(),
            kind: *kind,
            owner: body.author.clone(),
            via: via.clone(),
            members: members
                .iter()
                .map(|m| {
                    (
                        m.uid.clone(),
                        MemberState {
                            eldest: m.eldest,
                            joined_log: log,
                        },
                    )
                })
                .collect(),
            former: BTreeMap::new(),
            keys: vec![*key],
            rotation_pending: false,
            invites: BTreeMap::new(),
            profile: profile.clone().map(|p| (p, 1)),
            seq: 1,
            head: link.hash(),
        })
    }

    /// 从头验一整条链。
    pub fn verify_chain(conv: &ConvId, links: &[(ConvLink, u64)], directory: &dyn Directory) -> Result<Self> {
        let ((first, log), rest) = links.split_first().ok_or_else(|| CoreError::chain("会话签名链是空的"))?;
        let mut state = Self::create(conv, first, *log, directory)?;
        for (link, log) in rest {
            state.apply(link, *log, directory)?;
        }
        Ok(state)
    }

    /// 接一环；验不过时现状不变。
    pub fn apply(&mut self, link: &ConvLink, log: u64, directory: &dyn Directory) -> Result<()> {
        let mut next = self.clone();
        next.apply_in_place(link, log, directory)?;
        *self = next;
        Ok(())
    }

    fn require_member(&self, body: &ConvLinkBody) -> Result<MemberRef> {
        match self.members.get(&body.author) {
            Some(member) if member.eldest == body.author_eldest => Ok(MemberRef {
                uid: body.author.clone(),
                eldest: member.eldest,
            }),
            _ => Err(CoreError::chain("签名的人不是现在的成员")),
        }
    }

    fn require_group(&self) -> Result<()> {
        if self.kind == ConvKind::Group {
            Ok(())
        } else {
            Err(CoreError::chain("私聊不能这样改"))
        }
    }

    fn apply_in_place(&mut self, link: &ConvLink, log: u64, directory: &dyn Directory) -> Result<()> {
        let body = link.parse()?;
        if body.v != LINK_VERSION || body.conv != self.conv {
            return Err(CoreError::chain("这一环不属于这个会话"));
        }
        if body.seq != self.seq + 1 || body.prev != Some(self.head) {
            return Err(CoreError::chain("序号不连续或上一环摘要对不上"));
        }
        match &body.change {
            ConvChange::Create { .. } => return Err(CoreError::chain("建会话只能是第一环")),
            ConvChange::Add { members } => {
                self.require_group()?;
                let author = self.require_member(&body)?;
                verify_author(link, &body, &author, log, directory)?;
                check_members_unique(members)?;
                if members.is_empty() || members.iter().any(|m| self.members.contains_key(&m.uid)) {
                    return Err(CoreError::chain("邀请的人为空或已经在群里"));
                }
                if self.members.len() + members.len() > GROUP_MAX_MEMBERS {
                    return Err(CoreError::Limit("群人数超过上限".into()));
                }
                for m in members {
                    self.former.remove(&m.uid);
                    self.members.insert(
                        m.uid.clone(),
                        MemberState {
                            eldest: m.eldest,
                            joined_log: log,
                        },
                    );
                }
            }
            ConvChange::JoinByInvite { member, invite, proof } => {
                self.require_group()?;
                if member.uid != body.author || member.eldest != body.author_eldest || self.members.contains_key(&member.uid) {
                    return Err(CoreError::chain("只能自己凭邀请加入，且不能已经在群里"));
                }
                verify_author(link, &body, member, log, directory)?;
                let state = self.invites.get(invite).ok_or_else(|| CoreError::chain("没有这个群邀请"))?;
                if state.revoked {
                    return Err(CoreError::chain("群邀请已作废"));
                }
                crypto::verify(&state.public.0, ctx::INVITE_JOIN, &invite_join_message(&self.conv, invite, member), proof)?;
                if self.members.len() + 1 > GROUP_MAX_MEMBERS {
                    return Err(CoreError::Limit("群人数超过上限".into()));
                }
                self.former.remove(&member.uid);
                self.members.insert(
                    member.uid.clone(),
                    MemberState {
                        eldest: member.eldest,
                        joined_log: log,
                    },
                );
            }
            ConvChange::Remove { uid, reason } => {
                self.require_group()?;
                let author = self.require_member(&body)?;
                verify_author(link, &body, &author, log, directory)?;
                let target = self.members.get(uid).ok_or_else(|| CoreError::chain("要移出的人不在群里"))?;
                if uid == &body.author {
                    return Err(CoreError::chain("自己离开用退群"));
                }
                match reason {
                    RemoveReason::Kicked if body.author != self.owner => {
                        return Err(CoreError::chain("只有群主能移出成员"));
                    }
                    // 对方真的重置了（当前身份指纹与群里记的不同），任何成员都能补签移出。
                    RemoveReason::Reset if directory.eldest(uid).is_none_or(|current| current == target.eldest) => {
                        return Err(CoreError::chain("对方没有重置账号"));
                    }
                    _ => {}
                }
                self.members.remove(uid);
                self.former.insert(uid.clone(), log);
                self.rotation_pending = true;
            }
            ConvChange::Leave => {
                self.require_group()?;
                let author = self.require_member(&body)?;
                verify_author(link, &body, &author, log, directory)?;
                self.members.remove(&body.author);
                self.former.insert(body.author.clone(), log);
                self.rotation_pending = true;
            }
            ConvChange::Rotate { key } => {
                let author = self.require_member(&body)?;
                verify_author(link, &body, &author, log, directory)?;
                self.push_key(key)?;
            }
            ConvChange::MemberReset { member, key } => {
                if self.kind != ConvKind::Dm {
                    return Err(CoreError::chain("群里重置的人应移出"));
                }
                let old = self.members.get(&member.uid).ok_or_else(|| CoreError::chain("对方不在私聊里"))?;
                if old.eldest == member.eldest {
                    return Err(CoreError::chain("身份指纹没有变"));
                }
                if body.author == member.uid {
                    // 重置的人自己用新身份接上私聊。
                    if body.author_eldest != member.eldest {
                        return Err(CoreError::chain("重置的人应以新身份签"));
                    }
                    verify_author(link, &body, member, log, directory)?;
                } else {
                    let author = self.require_member(&body)?;
                    verify_author(link, &body, &author, log, directory)?;
                }
                self.push_key(key)?;
                if let Some(state) = self.members.get_mut(&member.uid) {
                    state.eldest = member.eldest;
                }
            }
            ConvChange::SetProfile { profile, generation } => {
                self.require_group()?;
                let author = self.require_member(&body)?;
                verify_author(link, &body, &author, log, directory)?;
                if profile.len() > PROFILE_MAX {
                    return Err(CoreError::Limit("群资料太大".into()));
                }
                if *generation == 0 || *generation > self.current_key().generation {
                    return Err(CoreError::chain("群资料用的钥匙代数不对"));
                }
                self.profile = Some((profile.clone(), *generation));
            }
            ConvChange::CreateInvite { invite, public, expires_ms } => {
                self.require_group()?;
                let author = self.require_member(&body)?;
                verify_author(link, &body, &author, log, directory)?;
                crypto::check_sign_public(&public.0)?;
                if self.invites.contains_key(invite) || *expires_ms <= body.ctime_ms {
                    return Err(CoreError::chain("群邀请编号重复或已过期"));
                }
                self.invites.insert(
                    invite.clone(),
                    InviteState {
                        public: *public,
                        expires_ms: *expires_ms,
                        revoked: false,
                    },
                );
            }
            ConvChange::RevokeInvite { invite } => {
                self.require_group()?;
                let author = self.require_member(&body)?;
                verify_author(link, &body, &author, log, directory)?;
                let state = self.invites.get_mut(invite).ok_or_else(|| CoreError::chain("没有这个群邀请"))?;
                state.revoked = true;
            }
        }
        self.seq = body.seq;
        self.head = link.hash();
        Ok(())
    }

    fn push_key(&mut self, key: &ConvKeyPub) -> Result<()> {
        if key.generation != self.current_key().generation + 1 {
            return Err(CoreError::chain("会话钥匙代数不连续"));
        }
        self.keys.push(*key);
        self.rotation_pending = false;
        Ok(())
    }

    /// 当前一代。
    pub fn current_key(&self) -> &ConvKeyPub {
        self.keys.last().expect("会话钥匙至少有第一代")
    }

    /// 某一代。
    pub fn key(&self, generation: u32) -> Option<&ConvKeyPub> {
        generation.checked_sub(1).and_then(|i| self.keys.get(i as usize))
    }

    /// 是不是现在的成员（且身份指纹一致）。
    pub fn is_member(&self, uid: &Uid, eldest: &Fixed<32>) -> bool {
        self.members.get(uid).is_some_and(|m| &m.eldest == eldest)
    }

    /// 给下一环填好会话、序号、上一环摘要与签名的账号。
    pub fn next_body(&self, author: &Uid, author_eldest: Fixed<32>, change: ConvChange, ctime_ms: i64) -> ConvLinkBody {
        ConvLinkBody {
            v: LINK_VERSION,
            conv: self.conv.clone(),
            seq: self.seq + 1,
            prev: Some(self.head),
            ctime_ms,
            author: author.clone(),
            author_eldest,
            change,
        }
    }
}

fn verify_author(link: &ConvLink, body: &ConvLinkBody, author: &MemberRef, log: u64, directory: &dyn Directory) -> Result<()> {
    if author.uid != body.author || author.eldest != body.author_eldest {
        return Err(CoreError::chain("签名的账号与身份指纹对不上"));
    }
    let key = directory
        .device(&author.uid, &author.eldest, &link.by, log)
        .ok_or_else(|| CoreError::chain("签名的电脑不属于这个账号，或当时已被移除"))?;
    key.verify(ctx::CONV_LINK, &link.body.0, &link.sig)
}

/// 一批会话签名链里出现的全部账号（签名人，以及成员变化涉及的人），排序去重。
/// 校验前要先把这些账号的签名链准备好（[`Directory`] 是同步查询）。
pub fn link_uids<'a>(links: impl IntoIterator<Item = &'a ConvLink>) -> Vec<Uid> {
    let mut out = Vec::new();
    for link in links {
        let Ok(body) = link.parse() else { continue };
        out.push(body.author.clone());
        match &body.change {
            ConvChange::Create { members, .. } | ConvChange::Add { members } => out.extend(members.iter().map(|m| m.uid.clone())),
            ConvChange::JoinByInvite { member, .. } | ConvChange::MemberReset { member, .. } => out.push(member.uid.clone()),
            ConvChange::Remove { uid, .. } => out.push(uid.clone()),
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// 第一环的原文。
pub fn create_body(conv: &ConvId, author: &MemberRef, change: ConvChange, ctime_ms: i64) -> ConvLinkBody {
    ConvLinkBody {
        v: LINK_VERSION,
        conv: conv.clone(),
        seq: 1,
        prev: None,
        ctime_ms,
        author: author.uid.clone(),
        author_eldest: author.eldest,
        change,
    }
}

/// 群资料（加密后放进签名链）。
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GroupProfile {
    /// 群名。
    pub name: String,
    /// 简介。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// 群头像（加密文件）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<FileRef>,
}

fn profile_aad(conv: &ConvId, generation: u32) -> Vec<u8> {
    crypto::frame(&[ctx::AEAD_CONV_PROFILE.as_bytes(), conv.as_str().as_bytes(), &generation.to_be_bytes()])
}

impl GroupProfile {
    /// 用某一代会话钥匙加密。
    pub fn seal(&self, conv: &ConvId, generation: u32, seed: &ConvSeed) -> Result<Bytes> {
        let plain = serde_json::to_vec(self).map_err(|_| CoreError::format("群资料写不出"))?;
        let sealed = crypto::encrypt(&seed.profile_key(), &profile_aad(conv, generation), &plain);
        if sealed.len() > PROFILE_MAX {
            return Err(CoreError::Limit("群资料太大".into()));
        }
        Ok(Bytes(sealed))
    }

    /// 解密。
    pub fn open(sealed: &Bytes, conv: &ConvId, generation: u32, seed: &ConvSeed) -> Result<Self> {
        let plain = crypto::decrypt(&seed.profile_key(), &profile_aad(conv, generation), &sealed.0)?;
        serde_json::from_slice(&plain).map_err(|_| CoreError::format("群资料读不懂"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::account::tests::{Fixture, provisioned};

    /// 测试用的通讯录：按账号签名链判断电脑是否有效。
    #[derive(Default)]
    pub(crate) struct TestDirectory {
        pub chains: BTreeMap<Uid, crate::account::AccountState>,
    }

    impl Directory for TestDirectory {
        fn device(&self, uid: &Uid, eldest: &Fixed<32>, device: &DeviceId, log: u64) -> Option<DevicePublic> {
            self.chains.get(uid).filter(|s| &s.eldest == eldest).and_then(|s| s.device_at(device, log))
        }
        fn eldest(&self, uid: &Uid) -> Option<Fixed<32>> {
            self.chains.get(uid).map(|s| s.eldest)
        }
    }

    pub(crate) fn member(f: &Fixture) -> MemberRef {
        MemberRef {
            uid: f.uid.clone(),
            eldest: f.state.eldest,
        }
    }

    struct Group {
        conv: ConvId,
        alice: Fixture,
        bob: Fixture,
        carol: Fixture,
        dir: TestDirectory,
        state: ConvState,
        seed: ConvSeed,
    }

    fn group() -> Group {
        let (alice, bob, carol) = (provisioned(), provisioned(), provisioned());
        let mut dir = TestDirectory::default();
        for f in [&alice, &bob, &carol] {
            dir.chains.insert(f.uid.clone(), f.state.clone());
        }
        let conv = ConvId::random();
        let seed = ConvSeed::generate();
        let profile = GroupProfile {
            name: "周末爬山".into(),
            ..Default::default()
        }
        .seal(&conv, 1, &seed)
        .unwrap();
        let change = ConvChange::Create {
            kind: ConvKind::Group,
            members: vec![member(&alice), member(&bob)],
            key: seed.public(1),
            profile: Some(profile),
            via: None,
        };
        let link = ConvLink::sign(&create_body(&conv, &member(&alice), change, 1), &alice.device);
        let state = ConvState::create(&conv, &link, 100, &dir).unwrap();
        Group {
            conv,
            alice,
            bob,
            carol,
            dir,
            state,
            seed,
        }
    }

    fn sign_next(g: &Group, by: &Fixture, change: ConvChange) -> ConvLink {
        ConvLink::sign(&g.state.next_body(&by.uid, by.state.eldest, change, 2), &by.device)
    }

    #[test]
    fn create_then_profile_decrypts_for_members() {
        let g = group();
        assert_eq!(g.state.owner, g.alice.uid);
        let (sealed, generation) = g.state.profile.clone().unwrap();
        assert_eq!(GroupProfile::open(&sealed, &g.conv, generation, &g.seed).unwrap().name, "周末爬山");
        assert!(GroupProfile::open(&sealed, &g.conv, generation, &ConvSeed::generate()).is_err());
    }

    #[test]
    fn any_member_can_invite_but_strangers_cannot() {
        let mut g = group();
        let by_stranger = sign_next(&g, &g.carol, ConvChange::Add { members: vec![member(&g.carol)] });
        assert!(g.state.clone().apply(&by_stranger, 101, &g.dir).is_err());
        let by_bob = sign_next(&g, &g.bob, ConvChange::Add { members: vec![member(&g.carol)] });
        g.state.apply(&by_bob, 101, &g.dir).unwrap();
        assert!(g.state.is_member(&g.carol.uid, &g.carol.state.eldest));
    }

    #[test]
    fn device_not_in_account_cannot_sign() {
        let g = group();
        let impostor = DeviceSecret::generate();
        let body = g.state.next_body(&g.bob.uid, g.bob.state.eldest, ConvChange::Add { members: vec![member(&g.carol)] }, 2);
        let link = ConvLink::sign(&body, &impostor);
        assert!(g.state.clone().apply(&link, 101, &g.dir).is_err());
    }

    #[test]
    fn only_owner_kicks_and_kick_marks_rotation_pending() {
        let mut g = group();
        let by_bob = sign_next(
            &g,
            &g.bob,
            ConvChange::Remove {
                uid: g.alice.uid.clone(),
                reason: RemoveReason::Kicked,
            },
        );
        assert!(g.state.clone().apply(&by_bob, 101, &g.dir).is_err());
        let by_owner = sign_next(
            &g,
            &g.alice,
            ConvChange::Remove {
                uid: g.bob.uid.clone(),
                reason: RemoveReason::Kicked,
            },
        );
        g.state.apply(&by_owner, 101, &g.dir).unwrap();
        assert!(g.state.rotation_pending);
        assert_eq!(g.state.former.get(&g.bob.uid), Some(&101));
        // 被移出的人不能再签。
        let after = sign_next(&g, &g.bob, ConvChange::Rotate { key: ConvSeed::generate().public(2) });
        assert!(g.state.clone().apply(&after, 102, &g.dir).is_err());
        let rotate = sign_next(&g, &g.alice, ConvChange::Rotate { key: ConvSeed::generate().public(2) });
        g.state.apply(&rotate, 102, &g.dir).unwrap();
        assert!(!g.state.rotation_pending);
    }

    #[test]
    fn reset_removal_requires_an_actual_reset() {
        let mut g = group();
        let fake = sign_next(
            &g,
            &g.alice,
            ConvChange::Remove {
                uid: g.bob.uid.clone(),
                reason: RemoveReason::Reset,
            },
        );
        assert!(g.state.clone().apply(&fake, 101, &g.dir).is_err());
        // Bob 重置：通讯录里换成新的一轮。
        let mut reset = provisioned();
        reset.uid = g.bob.uid.clone();
        let body = crate::account::eldest_body(&reset.uid, 1, crate::account::tests::entry(&reset.device, "新电脑"), &reset.recovery.device_secret(), reset.seed.public(1), 1);
        let link = crate::account::AccountLink::sign(&body, &reset.device);
        g.dir.chains.insert(reset.uid.clone(), crate::account::AccountState::eldest(&reset.uid, 1, &link, 50).unwrap());
        let real = sign_next(
            &g,
            &g.alice,
            ConvChange::Remove {
                uid: g.bob.uid.clone(),
                reason: RemoveReason::Reset,
            },
        );
        g.state.apply(&real, 101, &g.dir).unwrap();
        assert!(!g.state.members.contains_key(&g.bob.uid));
    }

    #[test]
    fn leave_then_rejoin_by_invite() {
        let mut g = group();
        let leave = sign_next(&g, &g.bob, ConvChange::Leave);
        g.state.apply(&leave, 101, &g.dir).unwrap();
        assert!(g.state.rotation_pending);
        let invite = InviteSecret::generate();
        let invite_id = InviteId::random();
        let create = sign_next(
            &g,
            &g.alice,
            ConvChange::CreateInvite {
                invite: invite_id.clone(),
                public: invite.public(),
                expires_ms: 10_000,
            },
        );
        g.state.apply(&create, 102, &g.dir).unwrap();
        let carol = member(&g.carol);
        // 没有链接钥匙的证明不认。
        let forged = sign_next(
            &g,
            &g.carol,
            ConvChange::JoinByInvite {
                member: carol.clone(),
                invite: invite_id.clone(),
                proof: invite_join_proof(&InviteSecret::generate(), &g.conv, &invite_id, &carol),
            },
        );
        assert!(g.state.clone().apply(&forged, 103, &g.dir).is_err());
        let join = sign_next(
            &g,
            &g.carol,
            ConvChange::JoinByInvite {
                member: carol.clone(),
                invite: invite_id.clone(),
                proof: invite_join_proof(&invite, &g.conv, &invite_id, &carol),
            },
        );
        g.state.apply(&join, 103, &g.dir).unwrap();
        assert!(g.state.is_member(&carol.uid, &carol.eldest));
        // 作废后不能再用。
        let revoke = sign_next(&g, &g.alice, ConvChange::RevokeInvite { invite: invite_id.clone() });
        g.state.apply(&revoke, 104, &g.dir).unwrap();
        let bob = member(&g.bob);
        let late = sign_next(
            &g,
            &g.bob,
            ConvChange::JoinByInvite {
                member: bob.clone(),
                invite: invite_id.clone(),
                proof: invite_join_proof(&invite, &g.conv, &invite_id, &bob),
            },
        );
        assert!(g.state.clone().apply(&late, 105, &g.dir).is_err());
    }

    #[test]
    fn dm_is_fixed_to_two_and_member_reset_rekeys() {
        let (alice, bob) = (provisioned(), provisioned());
        let mut dir = TestDirectory::default();
        dir.chains.insert(alice.uid.clone(), alice.state.clone());
        dir.chains.insert(bob.uid.clone(), bob.state.clone());
        let conv = ConvId::random();
        let seed = ConvSeed::generate();
        let three = ConvChange::Create {
            kind: ConvKind::Dm,
            members: vec![member(&alice), member(&bob), member(&provisioned())],
            key: seed.public(1),
            profile: None,
            via: Some(Via::FriendLink),
        };
        let link = ConvLink::sign(&create_body(&conv, &member(&alice), three, 1), &alice.device);
        assert!(ConvState::create(&conv, &link, 20, &dir).is_err());
        let change = ConvChange::Create {
            kind: ConvKind::Dm,
            members: vec![member(&alice), member(&bob)],
            key: seed.public(1),
            profile: None,
            via: Some(Via::FriendLink),
        };
        let link = ConvLink::sign(&create_body(&conv, &member(&alice), change, 1), &alice.device);
        let mut state = ConvState::create(&conv, &link, 20, &dir).unwrap();
        let leave = ConvLink::sign(&state.next_body(&bob.uid, bob.state.eldest, ConvChange::Leave, 2), &bob.device);
        assert!(state.clone().apply(&leave, 21, &dir).is_err(), "私聊不能退");
        // Bob 重置后自己用新身份接上私聊。
        let mut reset = provisioned();
        reset.uid = bob.uid.clone();
        let body = crate::account::eldest_body(&reset.uid, 1, crate::account::tests::entry(&reset.device, "新"), &reset.recovery.device_secret(), reset.seed.public(1), 1);
        let eldest_link = crate::account::AccountLink::sign(&body, &reset.device);
        let new_state = crate::account::AccountState::eldest(&reset.uid, 1, &eldest_link, 30).unwrap();
        dir.chains.insert(reset.uid.clone(), new_state.clone());
        let new_ref = MemberRef {
            uid: reset.uid.clone(),
            eldest: new_state.eldest,
        };
        let rekey = ConvLink::sign(
            &state.next_body(
                &reset.uid,
                new_state.eldest,
                ConvChange::MemberReset {
                    member: new_ref.clone(),
                    key: ConvSeed::generate().public(2),
                },
                3,
            ),
            &reset.device,
        );
        state.apply(&rekey, 31, &dir).unwrap();
        assert!(state.is_member(&new_ref.uid, &new_ref.eldest));
        assert_eq!(state.current_key().generation, 2);
    }

    #[test]
    fn removed_device_links_after_removal_are_rejected() {
        let mut g = group();
        // Alice 的电脑在日志 150 被移除。
        let mut chain = g.dir.chains.get(&g.alice.uid).unwrap().clone();
        let second = DeviceSecret::generate();
        let add = crate::account::AccountLink::sign(
            &chain.next_body(
                crate::account::AccountChange::AddDevice {
                    device: crate::account::tests::entry(&second, "二号"),
                    proof: crate::account::device_proof(&second, &g.alice.uid, 0, crate::account::ProofRole::Device),
                },
                2,
            ),
            &g.alice.device,
        );
        chain.apply(&add, 120).unwrap();
        let remove = crate::account::AccountLink::sign(
            &chain.next_body(
                crate::account::AccountChange::RemoveDevice {
                    device: g.alice.device.id(),
                    key: Some(crate::keys::AccountSeed::generate().public(2)),
                },
                3,
            ),
            &second,
        );
        chain.apply(&remove, 150).unwrap();
        g.dir.chains.insert(g.alice.uid.clone(), chain);
        let link = sign_next(&g, &g.alice, ConvChange::Rotate { key: ConvSeed::generate().public(2) });
        assert!(g.state.clone().apply(&link, 149, &g.dir).is_ok());
        assert!(g.state.clone().apply(&link, 151, &g.dir).is_err());
    }
}

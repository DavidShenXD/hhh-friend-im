//! 好友链接与群邀请链接的文字形式。
//!
//! - 好友链接：`https://<服务器>/f/<好友链接编号>#<身份指纹>`。身份指纹放在 `#` 后面：加好友时插件拿服务器返回的
//!   身份指纹和它比对，对上才算“身份已核对”（契约 S9）；服务器换了人，指纹对不上，插件拒绝。
//! - 群邀请链接：`https://<服务器>/g/<邀请编号>#<邀请钥匙>`。邀请钥匙只在链接里，不发给服务器（方案 §4）。
//!
//! `#` 后面的部分浏览器不会发给服务器；以后服务器给这两个地址配一个说明页也不会泄露它。

use std::fmt;

use friend_im_core::bytes::{self, Bytes, Fixed};
use friend_im_core::ids::InviteId;
use friend_im_core::keys::InviteSecret;

use crate::error::{ClientError, Result};

/// 好友链接。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriendLink {
    /// 服务器地址（`https://…`）。
    pub base: String,
    /// 好友链接编号。
    pub token: Bytes,
    /// 对方的身份指纹（账号签名链第一环的摘要）。
    pub eldest: Fixed<32>,
}

/// 群邀请链接。
pub struct InviteLink {
    /// 服务器地址（`https://…`）。
    pub base: String,
    /// 邀请编号。
    pub invite: InviteId,
    /// 邀请钥匙。
    pub secret: InviteSecret,
}

impl fmt::Debug for InviteLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InviteLink({})", self.invite)
    }
}

/// 拆出 `<base>/<kind>/<path>#<fragment>`。
fn split<'a>(text: &'a str, kind: &str) -> Option<(&'a str, &'a str, &'a str)> {
    let text = text.trim();
    let (head, fragment) = text.split_once('#')?;
    let marker = format!("/{kind}/");
    let at = head.rfind(&marker)?;
    let base = &head[..at];
    let path = &head[at + marker.len()..];
    (base.starts_with("https://") || base.starts_with("http://")).then_some((base, path, fragment))
}

impl FriendLink {
    /// 解析用户粘贴的好友链接。
    pub fn parse(text: &str) -> Result<Self> {
        let bad = || ClientError::state("好友链接格式不对");
        let (base, token, eldest) = split(text, "f").ok_or_else(bad)?;
        let token = bytes::decode(token).filter(|t| t.len() == 16).ok_or_else(bad)?;
        let eldest = bytes::decode(eldest).and_then(|e| Fixed::from_slice(&e)).ok_or_else(bad)?;
        Ok(Self {
            base: base.to_owned(),
            token: Bytes(token),
            eldest,
        })
    }
}

impl fmt::Display for FriendLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/f/{}#{}", self.base, bytes::encode(&self.token.0), bytes::encode(&self.eldest.0))
    }
}

impl InviteLink {
    /// 解析用户粘贴的群邀请链接。
    pub fn parse(text: &str) -> Result<Self> {
        let bad = || ClientError::state("群邀请链接格式不对");
        let (base, invite, secret) = split(text, "g").ok_or_else(bad)?;
        let invite = InviteId::parse(invite).map_err(|_| bad())?;
        let secret = bytes::decode(secret).ok_or_else(bad)?;
        let secret = InviteSecret::from_slice(&secret).map_err(|_| bad())?;
        Ok(Self {
            base: base.to_owned(),
            invite,
            secret,
        })
    }
}

impl fmt::Display for InviteLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/g/{}#{}", self.base, self.invite, bytes::encode(self.secret.as_bytes()))
    }
}

/// 由 WebSocket 地址得到 HTTPS 地址（`wss://x` → `https://x`，`ws://x` → `http://x`），去掉末尾的 `/`。
pub(crate) fn http_base(server: &str) -> String {
    let server = server.trim_end_matches('/');
    let server = server.strip_suffix("/v1/ws").unwrap_or(server);
    if let Some(rest) = server.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = server.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        server.to_owned()
    }
}

/// 由服务器地址得到 WebSocket 地址：`https://x` 或 `wss://x` → `wss://x/v1/ws`。
pub(crate) fn ws_url(server: &str) -> String {
    let base = http_base(server);
    if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}/v1/ws")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}/v1/ws")
    } else {
        format!("{base}/v1/ws")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn friend_link_round_trips_and_rejects_garbage() {
        let link = FriendLink {
            base: "https://im.example.com".into(),
            token: Bytes(vec![7; 16]),
            eldest: Fixed([9; 32]),
        };
        let text = link.to_string();
        assert!(text.starts_with("https://im.example.com/f/"));
        assert_eq!(FriendLink::parse(&text).unwrap(), link);
        assert_eq!(FriendLink::parse(&format!("  {text}\n")).unwrap(), link);
        assert!(FriendLink::parse("https://im.example.com/f/abc").is_err());
        assert!(FriendLink::parse("ftp://x/f/AAAAAAAAAAAAAAAAAAAAAA#AA").is_err());
    }

    #[test]
    fn invite_link_round_trips() {
        let link = InviteLink {
            base: "http://127.0.0.1:9".into(),
            invite: InviteId::random(),
            secret: InviteSecret::generate(),
        };
        let back = InviteLink::parse(&link.to_string()).unwrap();
        assert_eq!(back.invite, link.invite);
        assert_eq!(back.secret.public(), link.secret.public());
    }

    #[test]
    fn server_urls_convert_both_ways() {
        assert_eq!(http_base("wss://im.example.com/"), "https://im.example.com");
        assert_eq!(http_base("ws://127.0.0.1:8080/v1/ws"), "http://127.0.0.1:8080");
        assert_eq!(ws_url("https://im.example.com"), "wss://im.example.com/v1/ws");
        assert_eq!(ws_url("ws://127.0.0.1:8080"), "ws://127.0.0.1:8080/v1/ws");
    }
}

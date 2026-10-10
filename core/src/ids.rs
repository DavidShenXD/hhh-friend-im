//! 编号：账号、电脑、会话、消息、文件、批准请求、群邀请。
//!
//! 全部是 16 字节随机数（或摘要的前 16 字节）的 base64url，固定 22 个字符；
//! 反序列化时格式不对直接拒绝，后面的代码拿到的编号一定是合法的。

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::bytes;
use crate::crypto;
use crate::error::CoreError;

/// 编号的固定长度：16 字节的 base64url（不带 `=`）。
pub const ID_LEN: usize = 22;

fn valid(text: &str) -> bool {
    text.len() == ID_LEN && bytes::decode(text).is_some_and(|raw| raw.len() == 16)
}

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// 新取一个随机编号。
            pub fn random() -> Self {
                Self(bytes::encode(&crypto::random::<16>()))
            }

            /// 由 16 字节构造。
            pub fn from_raw(raw: [u8; 16]) -> Self {
                Self(bytes::encode(&raw))
            }

            /// 校验并接受一个外来的编号字符串。
            pub fn parse(text: &str) -> Result<Self, CoreError> {
                if valid(text) {
                    Ok(Self(text.to_owned()))
                } else {
                    Err(CoreError::format(concat!(stringify!($name), " 格式不对")))
                }
            }

            /// 字符串形式。
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = CoreError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(&value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }
    };
}

id_type!(
    /// 账号编号：服务器由“Cindy 签发方 + membership 编号”摘要得到，同一个 Cindy 身份永远是同一个编号。
    Uid
);
id_type!(
    /// 电脑编号：电脑签名公钥的摘要（见 [`DeviceId::from_sign_key`]），换钥匙就是另一台电脑。
    DeviceId
);
id_type!(
    /// 会话编号（私聊或群）：建会话的电脑随机取。
    ConvId
);
id_type!(
    /// 消息编号：发送的电脑随机取并签进密文；服务器按它去重，重放旧密文只会被当成同一条。
    MsgId
);
id_type!(
    /// 文件编号：服务器分配。
    FileId
);
id_type!(
    /// 新电脑批准请求的编号：服务器分配。
    RequestId
);
id_type!(
    /// 群邀请链接的编号：发邀请的电脑随机取。
    InviteId
);

impl Uid {
    /// 由 Cindy 身份算账号编号：签发方与 membership 编号之间用 0 分隔，防止拼接歧义。
    pub fn from_cindy(issuer: &str, membership_id: &str) -> Self {
        let mut data = Vec::with_capacity(issuer.len() + membership_id.len() + 1);
        data.extend_from_slice(issuer.as_bytes());
        data.push(0);
        data.extend_from_slice(membership_id.as_bytes());
        Self::from_raw(first16(&crypto::hash(crypto::ctx::UID, &data)))
    }
}

impl DeviceId {
    /// 电脑编号就是签名公钥摘要的前 16 字节：服务器、别的电脑拿到公钥就能算出同一个编号，不用另行约定。
    pub fn from_sign_key(sign_public: &[u8; 32]) -> Self {
        Self::from_raw(first16(&crypto::hash(crypto::ctx::DEVICE_ID, sign_public)))
    }
}

fn first16(digest: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_ids_are_22_chars_and_parse_back() {
        let id = ConvId::random();
        assert_eq!(id.as_str().len(), ID_LEN);
        assert_eq!(ConvId::parse(id.as_str()).unwrap(), id);
    }

    #[test]
    fn malformed_ids_are_rejected_on_deserialize() {
        assert!(serde_json::from_str::<MsgId>("\"short\"").is_err());
        assert!(serde_json::from_str::<MsgId>("\"AAAAAAAAAAAAAAAAAAAAA=\"").is_err());
        assert!(serde_json::from_str::<MsgId>("\"AAAAAAAAAAAAAAAAAAAAAA\"").is_ok());
    }

    #[test]
    fn uid_is_stable_and_separates_issuer_from_member() {
        let a = Uid::from_cindy("https://auth.cindy.app", "m1");
        assert_eq!(a, Uid::from_cindy("https://auth.cindy.app", "m1"));
        assert_ne!(a, Uid::from_cindy("https://auth.cindy.com.cn", "m1"));
        assert_ne!(Uid::from_cindy("ab", "c"), Uid::from_cindy("a", "bc"));
    }
}

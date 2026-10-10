//! 二进制字段：线上一律写成 base64url（不带 `=`），在 JSON 里是普通字符串。
//!
//! - [`Bytes`]：长度不定（密文、签名链一环的原文）。
//! - [`Fixed`]：长度固定（公钥 32 字节、签名 64 字节、摘要 32 字节），反序列化时长度不对直接报错。

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// 编码成 base64url（不带 `=`）。
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 解 base64url（不带 `=`）；格式不对返回 `None`。
pub fn decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// 长度不定的二进制。
#[derive(Clone, PartialEq, Eq, Default, Hash)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    /// 字节长度。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Bytes {
    // 日志与调试输出只写长度：密文、钥匙材料都可能经过这里。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({} 字节)", self.0.len())
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        decode(&text).map(Self).ok_or_else(|| D::Error::custom("base64url 格式不对"))
    }
}

/// 长度固定的二进制。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fixed<const N: usize>(pub [u8; N]);

impl<const N: usize> Fixed<N> {
    /// 从切片取；长度不对返回 `None`。
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }
}

impl<const N: usize> From<[u8; N]> for Fixed<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> zeroize::Zeroize for Fixed<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> AsRef<[u8]> for Fixed<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for Fixed<N> {
    // 只写前 4 字节的十六进制：公钥、摘要够认出是哪一个，又不会把钥匙材料整段写进日志。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fixed<{N}>(")?;
        for byte in self.0.iter().take(4) {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…)")
    }
}

impl<const N: usize> Serialize for Fixed<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode(&self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Fixed<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = decode(&text).ok_or_else(|| D::Error::custom("base64url 格式不对"))?;
        Self::from_slice(&bytes).ok_or_else(|| D::Error::custom(format!("长度应为 {N} 字节")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_as_base64url_without_padding() {
        let value = Bytes(vec![0xfb, 0xff, 0x00]);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, "\"-_8A\"");
        assert_eq!(serde_json::from_str::<Bytes>(&json).unwrap(), value);
    }

    #[test]
    fn fixed_rejects_wrong_length() {
        let json = serde_json::to_string(&Bytes(vec![1; 31])).unwrap();
        assert!(serde_json::from_str::<Fixed<32>>(&json).is_err());
        let json = serde_json::to_string(&Fixed([7u8; 32])).unwrap();
        assert_eq!(serde_json::from_str::<Fixed<32>>(&json).unwrap(), Fixed([7u8; 32]));
    }

    #[test]
    fn padded_or_standard_alphabet_is_rejected() {
        assert!(serde_json::from_str::<Bytes>("\"AA==\"").is_err());
        assert!(serde_json::from_str::<Bytes>("\"+/8A\"").is_err());
    }

    #[test]
    fn debug_never_prints_whole_value() {
        assert_eq!(format!("{:?}", Bytes(vec![9; 100])), "Bytes(100 字节)");
        assert_eq!(format!("{:?}", Fixed([0xabu8; 32])), "Fixed<32>(abababab…)");
    }
}

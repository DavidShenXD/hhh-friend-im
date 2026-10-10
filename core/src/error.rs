//! core 的错误：只说“哪一类不对”，不带任何钥匙、明文或密文内容，可以放心写进日志。

/// core 里所有可能的失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    /// 解不开：钥匙不对、密文被改过、附加数据对不上，三者对外不区分。
    #[error("解密失败")]
    Decrypt,
    /// 签名验不过。
    #[error("签名不对")]
    BadSignature,
    /// 格式不对（JSON、长度、编号、编码）。
    #[error("格式不对：{0}")]
    Format(String),
    /// 签名链不合规（缺环、乱序、类型或签名人不允许）。
    #[error("签名链不合规：{0}")]
    Chain(String),
    /// 钥匙与签名链里的承诺对不上（服务器可能换了钥匙）。
    #[error("钥匙对不上：{0}")]
    KeyMismatch(String),
    /// 新电脑批准时两边的 4 个词不一致。
    #[error("验证码不一致")]
    WrongCode,
    /// 超出格式规定的上限。
    #[error("超出上限：{0}")]
    Limit(String),
}

impl CoreError {
    pub(crate) fn format(message: impl Into<String>) -> Self {
        Self::Format(message.into())
    }

    pub(crate) fn chain(message: impl Into<String>) -> Self {
        Self::Chain(message.into())
    }
}

/// core 的结果类型。
pub type Result<T> = std::result::Result<T, CoreError>;

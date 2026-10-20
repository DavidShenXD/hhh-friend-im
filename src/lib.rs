//! Cindy IM 插件：把客户端库（`friend-im-client`）翻成 HHH-IM-Protocol v1，规范见 hhh-im-sdk 的 `docs/protocol-v1.md`。
//!
//! - 加密、签名链核对、钥匙都在客户端库里；插件只做翻译：服务器上的会话、消息、系统提示、文件 → 协议的会话、消息、资源，
//!   HHH 要发的内容 → 客户端库的消息正文。
//! - 聊天记录、凭据、设置都交给 HHH（[`credential`] 是交给 HHH 存的那一串的格式），插件只在内存里缓存名字与会话资料，
//!   上传的附件暂存在 HHH 给的临时目录里，发出去就删。
//! - 登录（用 Cindy 账号自动登录、开通、新电脑批准）要 HHH 插件协议 v13 的通用能力，在下一阶段做；这一版只能用已经
//!   登录好的凭据上线（契约 hhh-im/friend-im v1，方案 plan-v1 §13）。

pub mod credential;
pub mod server;
#[cfg(target_os = "wasi")]
mod wasi_stdio;

pub use server::{Options, run_stdio, serve};

//! 客户端库的错误 → 协议的错误（protocol-v1 §12）。给用户看的说明都是人话，不带钥匙、密文或消息内容。

use friend_im_client::ClientError;
use friend_im_client::core::wire::ErrorCode;
use hhh_im_protocol::rpc::{ErrorKind, ReauthReason, RpcError, code};

/// 一个给定分类与说明的协议错误。
pub(crate) fn of(kind: ErrorKind, message: impl Into<String>) -> RpcError {
    RpcError::from_kind(kind, message)
}

/// 授权失效，带上要不要重新登录的原因。
pub(crate) fn auth(reason: ReauthReason, message: impl Into<String>) -> RpcError {
    let mut error = of(ErrorKind::AuthExpired, message);
    if let Some(data) = error.data.as_mut() {
        data.reauth = Some(reason);
    }
    error
}

/// 参数不合法（-32602）：宿主发来的参数读不懂。
pub(crate) fn invalid_params(error: impl std::fmt::Display) -> RpcError {
    RpcError {
        code: code::INVALID_PARAMS,
        ..of(ErrorKind::InvalidRequest, format!("参数不对：{error}"))
    }
}

/// 方法不存在（-32601）。
pub(crate) fn method_not_found(method: &str) -> RpcError {
    RpcError {
        code: code::METHOD_NOT_FOUND,
        ..of(ErrorKind::Unsupported, format!("Cindy IM 插件不支持 {method}。"))
    }
}

/// 还没上线（没有 `session/open`，或这台电脑已经下线）。
pub(crate) fn offline() -> RpcError {
    of(ErrorKind::Disconnected, "Cindy IM 还没有连上。")
}

/// 客户端库的错误。服务器的拒绝按错误码分类，服务器给的说明原样带上（服务器只写人话，不带内容）。
pub(crate) fn client(error: &ClientError) -> RpcError {
    match error {
        ClientError::Disconnected | ClientError::Timeout => of(ErrorKind::Disconnected, "没连上 Cindy IM 服务器，稍后再试。"),
        ClientError::Transfer(message) => of(ErrorKind::Disconnected, format!("文件传输没成：{message}")),
        ClientError::Server(wire) => {
            let message = format!("Cindy IM 服务器拒绝了：{}", wire.message);
            match wire.code {
                ErrorCode::Unauthorized => auth(ReauthReason::Expired, "Cindy IM 的登录已失效，要重新登录。"),
                ErrorCode::DeviceRemoved => auth(ReauthReason::Revoked, "这台电脑已被移出你的 Cindy IM 账号。"),
                ErrorCode::NotApproved => auth(ReauthReason::CredentialInvalid, "这台电脑还没被批准加入 Cindy IM 账号。"),
                ErrorCode::Forbidden => of(ErrorKind::PermissionDenied, message),
                ErrorCode::NotFound => of(ErrorKind::NotFound, message),
                ErrorCode::LimitExceeded => of(ErrorKind::LimitExceeded, message),
                ErrorCode::RateLimited => {
                    let mut error = of(ErrorKind::RateLimited, "发得太快了，稍等一下再发。");
                    if let Some(data) = error.data.as_mut() {
                        data.retry_after_secs = Some(1);
                    }
                    error
                }
                ErrorCode::Unsupported => of(ErrorKind::Unsupported, message),
                ErrorCode::Internal => of(ErrorKind::Disconnected, "Cindy IM 服务器出错了，稍后再试。"),
                ErrorCode::BadRequest | ErrorCode::Invalid | ErrorCode::Conflict | ErrorCode::RotationRequired | ErrorCode::Expired => {
                    of(ErrorKind::InvalidRequest, message)
                }
            }
        }
        ClientError::Verify(reason) => of(ErrorKind::ProtocolError, format!("服务器给的东西核对不通过（{reason}），没有采用。")),
        ClientError::Core(_) | ClientError::Protocol(_) => of(ErrorKind::ProtocolError, format!("服务器给的数据不对：{error}")),
        ClientError::State(reason) => of(ErrorKind::InvalidRequest, reason.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use friend_im_client::core::wire::WireError;

    fn kind(error: &RpcError) -> ErrorKind {
        error.data.as_ref().unwrap().kind
    }

    #[test]
    fn server_refusals_map_to_protocol_kinds() {
        let server = |code| ClientError::Server(WireError { code, message: "说明".into() });
        assert_eq!(kind(&client(&server(ErrorCode::Forbidden))), ErrorKind::PermissionDenied);
        assert_eq!(kind(&client(&server(ErrorCode::NotFound))), ErrorKind::NotFound);
        let removed = client(&server(ErrorCode::DeviceRemoved));
        assert_eq!(kind(&removed), ErrorKind::AuthExpired);
        assert_eq!(removed.data.as_ref().unwrap().reauth, Some(ReauthReason::Revoked));
        assert_eq!(
            removed.data.as_ref().unwrap().user_message.as_deref(),
            Some("这台电脑已被移出你的 Cindy IM 账号。")
        );
        let limited = client(&server(ErrorCode::RateLimited));
        assert_eq!(limited.data.as_ref().unwrap().retry_after_secs, Some(1));
        assert_eq!(kind(&client(&ClientError::Disconnected)), ErrorKind::Disconnected);
        assert_eq!(kind(&client(&ClientError::Verify("x".into()))), ErrorKind::ProtocolError);
        assert_eq!(method_not_found("x/y").code, code::METHOD_NOT_FOUND);
    }
}

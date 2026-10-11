//! `initialize`（protocol-v1 §4.1、§5）：插件信息、平台说明、能力与设置项。`tests/initialize.rs` 用 hhh-im-check 同一套规则核对。
//!
//! - 能重读历史（`history = server`）：服务器按会话存着全部密文，随时能翻；新消息另有实时推送。
//! - 每条消息能回复；本人发的能撤回，不限时（服务器上的密文随之删除）。不能编辑、不能点表情、没有话题。
//! - 附件上限与服务器一致：图片、文件都到 100 MiB；文件名按字节算，255 字节以内（服务器按 255 个字收）。
//! - 设置只有一项：服务器地址，默认填用户自己部署的那台。

use friend_im_client::core::limits;
use hhh_im_protocol::method::{InitializeParams, InitializeResult, ProviderInfo};
use hhh_im_protocol::platform::{
    ActionRules, AvatarShape, Capabilities, ConversationCaps, DiscoveryDesc, EventCaps, HistoryMode, Limits, MessageCaps,
    OwnWithin, PeopleCaps, PlatformDesc, RateBudget, ResourceCaps, SendCaps, SettingDecl,
};
use hhh_im_protocol::rpc::{ErrorKind, RpcError};
use serde_json::Value;

use super::errors;

/// 插件编号（同清单 `id`）。
pub(crate) const PROVIDER_ID: &str = "friend-im";
/// 给用户看的名字（同清单 `name`）。
pub(crate) const PROVIDER_NAME: &str = "Friend-IM";
/// 设置项：服务器地址。
pub(crate) const SETTING_SERVER: &str = "serverUrl";
/// 服务器地址的默认值：用户部署在 xdt-server 上的那台（契约 §8：服务器地址是插件的设置项，默认填用户的服务器）。
pub(crate) const DEFAULT_SERVER: &str = "https://hhh-friend-im.magiclizi.com";
/// 一页最多几条（同服务器的上限）。
pub(crate) const PAGE_MAX: u32 = limits::HISTORY_PAGE_MAX;
/// 文件按多大一段读：16 个加密块，正好 1 MiB 明文（协议一段的上限）。
pub(crate) const FILE_SEGMENT_BYTES: u64 = 1024 * 1024;
/// 附件名的上限（字节）：服务器按 255 个字收，这里按字节写 255，任何写法都不会超。
const ATTACHMENT_NAME_MAX_BYTES: u32 = 255;

/// 平台说明。
pub(crate) fn platform() -> PlatformDesc {
    PlatformDesc {
        avatar_shape: AvatarShape::Circle,
        avatar_identity: None,
        history: HistoryMode::Server,
        actions: ActionRules {
            reply: true,
            thread: false,
            react: false,
            recall: Some(OwnWithin { own: true, within_secs: None }),
            edit: None,
        },
        chat_link: None,
        image_name_prefix: Some(PROVIDER_NAME.into()),
        conversation_nouns: None,
        page_max: Some(PAGE_MAX),
        // 服务器不限读取；新电脑补齐 1 万条要翻 100 页（契约 §7：5 分钟内），比宿主默认的每分钟 120 次放宽一些。
        reads: Some(RateBudget { per_second: 20, per_minute: 600 }),
        downloads: None,
        file_segment_bytes: Some(FILE_SEGMENT_BYTES),
        limits: Some(Limits {
            image_upload_max_bytes: limits::FILE_PLAIN_MAX,
            file_upload_max_bytes: limits::FILE_PLAIN_MAX,
            attachment_name_max_bytes: ATTACHMENT_NAME_MAX_BYTES,
        }),
        read_defaults: None,
        threads: None,
        deleted_messages_vanish: false,
        reactions_in_reads: false,
        emoji_per_account: false,
        emoji: None,
        // 会话发现：一次问到底（服务器一次给全，至多 1000 个会话）。
        discovery: Some(DiscoveryDesc { fastest_secs: 30, pages: 1, cold_pages: 1 }),
        user_adjustable: Vec::new(),
        edits_by_content: Vec::new(),
        retranslate_rules: Vec::new(),
    }
}

/// 能力：做得到的都声明，做不到的（搜索、编辑、表情、头像、定位私聊）不声明。
pub(crate) fn capabilities() -> Capabilities {
    Capabilities {
        conversations: ConversationCaps { list: true, search: false, members: true, find_direct: false, recent_activity: true },
        messages: MessageCaps { list: true, get: false },
        people: PeopleCaps { get: true, search: false },
        send: Some(SendCaps { text: true, mentions: true, mention_all: true, image: true, file: true, lookup: true }),
        recall: true,
        edit: false,
        reactions: Default::default(),
        resources: ResourceCaps { read: true, avatars: false },
        events: EventCaps { messages: true, deletions: false, reactions: false, conversations: true, people: false },
        retranslate: false,
        session: Default::default(),
    }
}

/// 设置项：服务器地址。
pub(crate) fn settings() -> Vec<SettingDecl> {
    vec![SettingDecl {
        id: SETTING_SERVER.into(),
        label: "服务器地址".into(),
        required: true,
        // 同 `credential::server_url`：https 网址本身；本机测试可以是 http://127.0.0.1 或 http://localhost。
        pattern: Some(r"^\s*(https://[^\s/?#@]+|http://(127\.0\.0\.1|localhost)(:[0-9]+)?)/?\s*$".into()),
        help: Some("你的 Friend-IM 服务器（https 网址）。换了服务器要重新登录。".into()),
        field_type: Some("text".into()),
        default: Some(DEFAULT_SERVER.into()),
        ..Default::default()
    }]
}

/// 握手结果。
pub(crate) fn result() -> InitializeResult {
    InitializeResult {
        protocol_version: 1,
        provider: ProviderInfo { id: PROVIDER_ID.into(), name: PROVIDER_NAME.into(), version: env!("CARGO_PKG_VERSION").into() },
        platform: platform(),
        capabilities: capabilities(),
        settings: settings(),
        login_methods: Vec::new(),
    }
}

/// `initialize`：宿主列出的版本里要有 1。
pub(crate) fn initialize(params: &InitializeParams) -> Result<Value, RpcError> {
    if !params.protocol_versions.contains(&1) {
        return Err(errors::of(ErrorKind::Unsupported, "Friend-IM 插件只会协议第 1 版，和这个 HHH 不兼容。"));
    }
    Ok(serde_json::to_value(result()).expect("握手结果总能写成 JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_is_consistent() {
        let result = serde_json::to_value(result()).unwrap();
        assert_eq!(result["provider"]["id"], PROVIDER_ID);
        assert_eq!(result["platform"]["history"], "server");
        assert_eq!(result["platform"]["pageMax"], 100);
        assert_eq!(result["capabilities"]["messages"]["list"], true, "history=server 必须能读消息（§5.2）");
        assert_eq!(result["capabilities"]["conversations"]["recentActivity"], true, "声明了会话发现就要能答");
        assert_eq!(result["settings"][0]["default"], DEFAULT_SERVER);
        assert!(result.get("loginMethods").is_none(), "这一版没有登录方式");
        // 清单与握手的编号、名字一致。
        let manifest: Value = serde_json::from_str(include_str!("../../hhh-im-provider.json")).unwrap();
        assert_eq!(manifest["id"], PROVIDER_ID);
        assert_eq!(manifest["name"], PROVIDER_NAME);
        assert_eq!(manifest["version"], env!("CARGO_PKG_VERSION"), "清单与 Cargo.toml 的版本一致");
    }
}

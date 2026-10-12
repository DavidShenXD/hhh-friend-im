//! 加密的个人资料与头像（第三阶段方案 plan-v1 §14.4，契约 S1“名字和头像沿用 Cindy”）。
//!
//! - **发出**：头像地址在登录时从宿主拿到（`hostAccount.avatarUrl`），记在凭据里。上线后和上次发出去的不一样，就往自己在的
//!   每个会话发一条个人资料（`Content::Profile`，和普通消息一样只有会话里的人解得开），限速发完再记下“发过了”。
//! - **收到**：个人资料不显示成消息；按发送人记最新的一份（日志序号大的为准，内存里至多 [`PROFILES_MAX`] 人），推
//!   `people` 事件告诉宿主这个人的头像键；之后人名、成员、私聊会话都带上它。
//! - **头像键**就是头像地址（不超过 [`AVATAR_KEY_MAX`] 字节）。宿主来读（`avatars/read`）时插件按地址取：只取 https、主机在
//!   允许的名单里、至多 [`AVATAR_MAX_BYTES`]、只收 PNG / JPEG / WebP / GIF，内存里留最近 [`AVATAR_CACHE_MAX`] 张。名单：取样前
//!   先认自己头像地址的主机（Cindy 给的，可信），好友不能借个人资料让插件去连任意网站。

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use friend_im_client::ClientError;
use friend_im_client::core::ids::{ConvId, MsgId, Uid};
use friend_im_client::core::message::Content;
use hhh_im_protocol::method::{AvatarsReadParams, ResourceChunk};
use hhh_im_protocol::rpc::{ErrorKind, RpcError};
use serde_json::Value;

use super::session::Live;
use super::{Server, errors};
use crate::credential::Announced;

/// 记多少人的个人资料。
pub(crate) const PROFILES_MAX: usize = 4096;
/// 头像键（头像地址）至多多少字节：协议的编号上限。
pub(crate) const AVATAR_KEY_MAX: usize = 256;
/// 一张头像至多多少字节。
pub(crate) const AVATAR_MAX_BYTES: usize = 1024 * 1024;
/// 内存里留几张取过的头像。
pub(crate) const AVATAR_CACHE_MAX: usize = 64;
/// 发个人资料的间隔（服务器每秒至多 5 条，留一条给用户自己发消息）。
pub(crate) const ANNOUNCE_GAP: Duration = Duration::from_millis(250);
/// 取一张头像至多等多久。
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
/// 读头像一段至多多少（协议上限）。
const SEGMENT_MAX: u64 = 1024 * 1024;

/// 一个头像地址能不能当头像键：https、不太长、没有空白与控制字符。
pub(crate) fn avatar_key(url: &str) -> Option<String> {
    (url.starts_with("https://")
        && url.len() <= AVATAR_KEY_MAX
        && !url.chars().any(|c| c.is_whitespace() || c.is_control()))
    .then(|| url.to_owned())
}

/// 地址的主机（`https://host[:port]/…` 里的 host:port，小写）。
pub(crate) fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty() && !host.contains('@')).then(|| host.to_ascii_lowercase())
}

/// 按文件头认出图片格式（只收这四种）。
pub(crate) fn image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else {
        None
    }
}

/// 收到的个人资料：账号 → （日志序号，头像键）。
#[derive(Default)]
pub(crate) struct Profiles {
    seen: Mutex<HashMap<Uid, (u64, Option<String>)>>,
}

impl Profiles {
    /// 记下一份个人资料；比已记的新（日志序号大）才算数。返回这个人的头像是不是变了（变了要告诉宿主）。
    pub(crate) fn note(&self, uid: &Uid, log: u64, avatar: Option<&str>) -> bool {
        let key = avatar.and_then(avatar_key);
        let mut seen = self.seen.lock().expect("个人资料锁中毒");
        if let Some((known, previous)) = seen.get(uid) {
            if *known >= log {
                return false;
            }
            if *previous == key {
                seen.insert(uid.clone(), (log, key));
                return false;
            }
        }
        if seen.len() >= PROFILES_MAX && !seen.contains_key(uid) {
            // 满了：丢掉最旧的那份（日志序号最小的），按需再从翻到的历史里认识。
            if let Some(oldest) = seen.iter().min_by_key(|(_, (log, _))| *log).map(|(uid, _)| uid.clone()) {
                seen.remove(&oldest);
            }
        }
        seen.insert(uid.clone(), (log, key));
        true
    }

    /// 这个人现在的头像键。
    pub(crate) fn avatar(&self, uid: &Uid) -> Option<String> {
        self.seen.lock().expect("个人资料锁中毒").get(uid).and_then(|(_, key)| key.clone())
    }
}

/// 取过的头像（地址 → 字节），按最近使用留 [`AVATAR_CACHE_MAX`] 张。
pub(crate) struct Avatars {
    http: reqwest::Client,
    /// 允许取头像的主机（自己头像地址的主机）。
    allowed: Mutex<Option<String>>,
    cache: Mutex<VecDeque<(String, std::sync::Arc<Vec<u8>>)>>,
}

impl Default for Avatars {
    fn default() -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(FETCH_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            allowed: Mutex::new(None),
            cache: Mutex::new(VecDeque::new()),
        }
    }
}

impl Avatars {
    /// 认下自己头像地址的主机（登录、上线时）。
    pub(crate) fn allow_host_of(&self, own_avatar: Option<&str>) {
        if let Some(host) = own_avatar.and_then(host_of) {
            *self.allowed.lock().expect("头像名单锁中毒") = Some(host);
        }
    }

    /// 这个地址能不能取：https、主机在名单里。
    pub(crate) fn may_fetch(&self, url: &str) -> bool {
        avatar_key(url).is_some()
            && host_of(url).is_some_and(|host| self.allowed.lock().expect("头像名单锁中毒").as_deref() == Some(host.as_str()))
    }

    /// 一张头像的全部字节（先看内存，没有再取）。
    ///
    /// # Errors
    /// 地址不让取、取不到、太大、不是图片时返回给人看的原因。
    pub(crate) async fn get(&self, url: &str) -> Result<std::sync::Arc<Vec<u8>>, String> {
        if let Some(found) = self.cached(url) {
            return Ok(found);
        }
        if !self.may_fetch(url) {
            tracing::info!("头像地址不在允许的主机上，不取");
            return Err("这个头像不能显示。".into());
        }
        let mut response = self.http.get(url).send().await.map_err(|error| {
            tracing::info!(%error, "头像取不到");
            "头像取不到。".to_owned()
        })?;
        if !response.status().is_success() {
            tracing::info!(status = %response.status(), "头像取不到");
            return Err("头像取不到。".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            tracing::info!(%error, "头像没取完");
            "头像取不到。".to_owned()
        })? {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > AVATAR_MAX_BYTES {
                tracing::info!("头像太大，不取");
                return Err("头像太大。".into());
            }
        }
        if image_mime(&bytes).is_none() {
            tracing::info!("取到的头像不是认得的图片");
            return Err("头像不是图片。".into());
        }
        let bytes = std::sync::Arc::new(bytes);
        let mut cache = self.cache.lock().expect("头像缓存锁中毒");
        cache.retain(|(key, _)| key != url);
        cache.push_back((url.to_owned(), bytes.clone()));
        while cache.len() > AVATAR_CACHE_MAX {
            cache.pop_front();
        }
        Ok(bytes)
    }

    fn cached(&self, url: &str) -> Option<std::sync::Arc<Vec<u8>>> {
        let mut cache = self.cache.lock().expect("头像缓存锁中毒");
        let at = cache.iter().position(|(key, _)| key == url)?;
        let entry = cache.remove(at)?;
        let bytes = entry.1.clone();
        cache.push_back(entry);
        Some(bytes)
    }

    /// 测试用：放一张进缓存。
    #[cfg(test)]
    pub(crate) fn put(&self, url: &str, bytes: Vec<u8>) {
        self.cache.lock().unwrap().push_back((url.to_owned(), std::sync::Arc::new(bytes)));
    }
}

impl Server {
    /// 上线后：头像和上次发出去的不一样（或从没发过），就往自己在的每个会话发一条个人资料，发完记下并存凭据。
    /// 没连上、发不出去就停下，下次上线再发。
    pub(crate) async fn announce_profile(&self, live: &Live) {
        let (avatar, outdated) = {
            let credential = live.credential.lock().expect("凭据锁中毒");
            (credential.avatar.clone(), credential.profile_outdated())
        };
        if !outdated {
            return;
        }
        let convs = match live.client.convs().await {
            Ok(convs) => convs,
            Err(error) => {
                tracing::info!(%error, "会话列表取不到，个人资料下次上线再发");
                return;
            }
        };
        let targets: Vec<ConvId> = convs.into_iter().filter(|c| c.member).map(|c| c.conv).collect();
        tracing::info!(count = targets.len(), has_avatar = avatar.is_some(), "往会话里发个人资料");
        for conv in &targets {
            if let Err(error) = self.send_profile(live, conv, avatar.clone()).await {
                if matches!(error, ClientError::Disconnected | ClientError::Timeout) {
                    tracing::info!(%error, "发个人资料时断开了，下次上线再发");
                    return;
                }
                tracing::info!(%conv, %error, "这个会话发不了个人资料，跳过");
            }
            tokio::time::sleep(ANNOUNCE_GAP).await;
        }
        let credential = {
            let mut current = live.credential.lock().expect("凭据锁中毒");
            current.announced = Some(Announced { avatar });
            current.clone()
        };
        if self.save_credential(&credential).await.is_err() {
            tracing::warn!("记“个人资料发过了”没存下，下次上线会再发一遍");
        }
    }

    /// 刚进的会话（建群、加好友、被拉进群、凭链接进群）：发一条个人资料，会话里的人才看得到头像。
    pub(crate) async fn announce_to(&self, live: &Live, conv: &ConvId) {
        if live.read_only {
            return;
        }
        let avatar = live.credential.lock().expect("凭据锁中毒").avatar.clone();
        if let Err(error) = self.send_profile(live, conv, avatar).await {
            tracing::info!(%conv, %error, "新会话里发个人资料没成，换头像或下次发时再补");
        }
    }

    /// 发一条个人资料（和用户自己发的消息排队，一条发完再发下一条）。
    async fn send_profile(&self, live: &Live, conv: &ConvId, avatar: Option<String>) -> Result<(), ClientError> {
        let _turn = self.sends.gate.lock().await;
        live.client.send(conv, &MsgId::random(), Content::Profile { avatar }).await.map(|_| ())
    }

    /// `avatars/read`：按头像键（就是头像地址）读一段。地址不让取、取不到时回“没有”。
    pub(crate) async fn read_avatar(&self, params: AvatarsReadParams) -> Result<Value, RpcError> {
        let bytes = self.avatars.get(&params.key).await.map_err(|reason| errors::of(ErrorKind::NotFound, reason))?;
        let total = bytes.len() as u64;
        if params.offset > total {
            return Err(errors::of(ErrorKind::InvalidRequest, "读的位置超出了头像大小。"));
        }
        let end = (params.offset + params.length.min(SEGMENT_MAX)).min(total);
        let chunk = ResourceChunk {
            data: BASE64.encode(&bytes[params.offset as usize..end as usize]),
            total: Some(total),
            sha256: None,
            eof: end >= total,
        };
        Ok(serde_json::to_value(chunk).expect("结果总能写成 JSON"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 头像键：只收 https、不太长、不含空白；主机取地址里的那一段。
    #[test]
    fn avatar_keys_and_hosts() {
        assert_eq!(avatar_key("https://a.example.com/u/1.png").as_deref(), Some("https://a.example.com/u/1.png"));
        assert!(avatar_key("http://a.example.com/1.png").is_none());
        assert!(avatar_key(&format!("https://a.com/{}", "x".repeat(AVATAR_KEY_MAX))).is_none());
        assert!(avatar_key("https://a.com/a b").is_none());
        assert_eq!(host_of("https://CDN.example.com:443/a?b").as_deref(), Some("cdn.example.com:443"));
        assert!(host_of("https://user@evil.com/a").is_none());
        assert!(host_of("ftp://a.com/x").is_none());
    }

    // 只收四种图片。
    #[test]
    fn only_known_images_are_avatars() {
        assert_eq!(image_mime(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0]), Some("image/png"));
        assert_eq!(image_mime(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(image_mime(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(image_mime(b"GIF89a.."), Some("image/gif"));
        assert_eq!(image_mime(b"<svg>"), None);
    }

    // 个人资料按日志序号认最新的；头像没变不报；满了丢最旧的。
    #[test]
    fn the_latest_profile_wins() {
        let profiles = Profiles::default();
        let (a, b) = (Uid::from_raw([1; 16]), Uid::from_raw([2; 16]));
        assert!(profiles.note(&a, 10, Some("https://x.com/1.png")));
        assert!(!profiles.note(&a, 9, Some("https://x.com/0.png")), "旧的不算");
        assert!(!profiles.note(&a, 11, Some("https://x.com/1.png")), "没变不报");
        assert!(profiles.note(&a, 12, None), "撤掉头像要报");
        assert_eq!(profiles.avatar(&a), None);
        assert!(profiles.note(&b, 1, Some("http://x.com/insecure.png")), "第一次见要报");
        assert_eq!(profiles.avatar(&b), None, "不是 https 的不当头像");
    }

    // 只从自己头像的主机取；缓存里的直接给。
    #[tokio::test]
    async fn avatars_come_only_from_the_allowed_host() {
        let avatars = Avatars::default();
        assert!(!avatars.may_fetch("https://cdn.example.com/a.png"), "还没认主机");
        avatars.allow_host_of(Some("https://cdn.example.com/me.png"));
        assert!(avatars.may_fetch("https://cdn.example.com/a.png"));
        assert!(!avatars.may_fetch("https://evil.example.org/a.png"), "别的主机不取");
        assert!(avatars.get("https://evil.example.org/a.png").await.is_err());
        avatars.put("https://cdn.example.com/a.png", vec![0xFF, 0xD8, 0xFF, 0xE0]);
        assert_eq!(avatars.get("https://cdn.example.com/a.png").await.unwrap().len(), 4);
    }
}

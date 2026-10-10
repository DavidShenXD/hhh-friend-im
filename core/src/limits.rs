//! 两边共用的上限。服务器按这些值拒绝请求；客户端照着这些值提前拦住，不白跑一趟。
//! 任何 Cindy 账号都能登录服务器，所以每一项都必须有上限，防止被刷（契约 §8）。

use crate::file;

/// 每个账号的电脑（不含恢复密钥）：一个人 10 台电脑足够，再多多半是被刷。
pub const MAX_DEVICES: usize = 10;
/// 每个账号存的文件总量：2 GiB（契约 §7 按 1000 个账号设计，单机磁盘撑得住）。
pub const ACCOUNT_STORAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// 单个文件明文上限：100 MiB。
pub const FILE_PLAIN_MAX: u64 = 100 * 1024 * 1024;
/// 单个文件密文上限（由明文上限算出）。
pub fn file_sealed_max() -> u64 {
    file::sealed_len(FILE_PLAIN_MAX)
}
/// 发送频率：每个账号每秒 5 条、每分钟 120 条（人打字远到不了，伙伴自动回复也够用）。
pub const SEND_PER_SECOND: u32 = 5;
/// 见 [`SEND_PER_SECOND`]。
pub const SEND_PER_MINUTE: u32 = 120;
/// 群人数。
pub const GROUP_MAX_MEMBERS: usize = crate::conv::GROUP_MAX_MEMBERS;
/// 每个账号同时进行的批准请求。
pub const JOIN_CONCURRENT: usize = 1;
/// 每个账号每小时最多发起的批准请求。
pub const JOIN_PER_HOUR: u32 = 10;
/// 一次批准最多输错几次（契约 S21）。
pub const JOIN_MAX_ATTEMPTS: u32 = 5;
/// 批准请求多久没处理自动作废（契约 S20）：10 分钟。
pub const JOIN_TTL_MS: i64 = 10 * 60 * 1000;
/// 群邀请链接默认有效期：7 天。
pub const INVITE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// 每台电脑的推送队列：满了服务器断开它，让它按序号补拉，慢电脑拖不垮服务器内存。
pub const PUSH_QUEUE: usize = 1000;
/// WebSocket 每一帧（请求体）上限：1 MiB（文件内容走 HTTPS，另算）。
pub const FRAME_MAX_BYTES: usize = 1024 * 1024;
/// 翻历史每页最多几条（与 HHH 协议一页上限一致）。
pub const HISTORY_PAGE_MAX: u32 = 100;
/// 补拉每批最多几条。
pub const SYNC_PAGE_MAX: u32 = 500;
/// 翻历史、补拉一次回执的大致字节上限：到了就分页（至少给一条）。一条消息最大 80 KiB，
/// 不按字节封顶的话一页 500 条能到几十 MiB，超过客户端的单帧上限。
pub const RESPONSE_SOFT_MAX_BYTES: usize = 4 * 1024 * 1024;
/// 客户端接收单帧的上限：回执按 [`RESPONSE_SOFT_MAX_BYTES`] 分页，再留出单条最大消息和 JSON 的余量。
pub const CLIENT_FRAME_MAX_BYTES: usize = 16 * 1024 * 1024;
/// 一个请求里会话签名链最多几环（移出 + 换代这类批量操作用不了几环）。
pub const CONV_LINKS_PER_REQUEST: usize = 8;
/// 一个请求里账号签名链最多几环。
pub const ACCOUNT_LINKS_PER_REQUEST: usize = 4;
/// 一次查资料最多几个账号。
pub const PROFILES_PER_REQUEST: usize = 256;
/// 文件上传每段最多多少字节（HTTPS 请求体）：8 MiB，断点续传按段走。
pub const UPLOAD_PART_MAX: usize = 8 * 1024 * 1024;

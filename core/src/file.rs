//! 文件、图片的分段流式加密：每个文件一把随机钥匙（放在加了密的消息正文里），
//! 明文按 64 KiB 分段，每段单独用 ChaCha20-Poly1305 加密，可以边读边加密、边下边解，不用整份读进内存。
//!
//! 随机数按 STREAM 构造（与 age 相同）：11 字节大端段号 + 1 字节“最后一段”标记。
//! 段号防止调换或丢段，最后一段的标记防止被截短；钥匙每个文件一把，随机数不会重复。
//! 空文件也有一段（空的最后一段）。

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::bytes::Fixed;
use crate::crypto;
use crate::error::{CoreError, Result};
use crate::ids::FileId;

/// 文件名最长多少个字符。
pub const FILE_NAME_MAX_CHARS: usize = 255;

/// 消息里对一个加密文件的引用（整个引用在加了密的消息正文里，服务器看不到钥匙、文件名和类型）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    /// 服务器上的文件编号。
    pub id: FileId,
    /// 文件钥匙。
    pub key: Fixed<32>,
    /// 明文字节数。
    pub size: u64,
    /// 文件名。
    pub name: String,
    /// 类型（如 `image/png`）。
    pub mime: String,
}

impl std::fmt::Debug for FileRef {
    // 不输出钥匙和文件名：日志里只该有编号和大小。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileRef({}, {} 字节)", self.id, self.size)
    }
}

impl FileRef {
    /// 校验文件名与类型的长度。
    pub fn check(&self) -> Result<()> {
        if self.name.chars().count() > FILE_NAME_MAX_CHARS || self.mime.len() > 255 || self.name.chars().any(char::is_control) {
            return Err(CoreError::format("文件名或类型不对"));
        }
        Ok(())
    }
}

/// 每段明文的长度。
pub const CHUNK_PLAIN: usize = 64 * 1024;
/// 每段密文的长度（明文 + 16 字节校验），最后一段可以更短。
pub const CHUNK_SEALED: usize = CHUNK_PLAIN + 16;

/// 明文长度对应的密文长度。
pub fn sealed_len(plain_len: u64) -> u64 {
    let chunks = plain_len.div_ceil(CHUNK_PLAIN as u64).max(1);
    plain_len + chunks * 16
}

/// 密文长度对应的明文长度；长度不可能出现时返回 `None`。
pub fn plain_len(sealed_len: u64) -> Option<u64> {
    let full = sealed_len / CHUNK_SEALED as u64;
    let rest = sealed_len % CHUNK_SEALED as u64;
    match (full, rest) {
        (0, 0) => None,
        (_, 0) => Some(full * CHUNK_PLAIN as u64),
        (_, r) if r >= 16 && (r > 16 || full == 0) => Some(full * CHUNK_PLAIN as u64 + r - 16),
        _ => None,
    }
}

/// 新生成一把文件钥匙。
pub fn generate_key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new(crypto::random())
}

fn nonce(counter: u64, last: bool) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[3..11].copy_from_slice(&counter.to_be_bytes());
    bytes[11] = u8::from(last);
    Nonce::from(bytes)
}

/// 逐段加密。
pub struct Encryptor {
    cipher: ChaCha20Poly1305,
    counter: u64,
    finished: bool,
}

impl Encryptor {
    /// 用文件钥匙开始。
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&(*key).into()),
            counter: 0,
            finished: false,
        }
    }

    /// 加密一段：除最后一段外必须正好 [`CHUNK_PLAIN`] 字节；最后一段 `last = true`，可以更短（含 0 字节）。
    pub fn seal_chunk(&mut self, plain: &[u8], last: bool) -> Result<Vec<u8>> {
        if self.finished {
            return Err(CoreError::format("最后一段之后不能再加密"));
        }
        if plain.len() > CHUNK_PLAIN || (!last && plain.len() != CHUNK_PLAIN) {
            return Err(CoreError::format("分段长度不对"));
        }
        let sealed = self
            .cipher
            .encrypt(&nonce(self.counter, last), plain)
            .map_err(|_| CoreError::format("加密失败"))?;
        self.counter += 1;
        self.finished = last;
        Ok(sealed)
    }
}

/// 逐段解密。
pub struct Decryptor {
    cipher: ChaCha20Poly1305,
    counter: u64,
    finished: bool,
}

impl Decryptor {
    /// 用文件钥匙开始。
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&(*key).into()),
            counter: 0,
            finished: false,
        }
    }

    /// 解密一段；调用方按 [`CHUNK_SEALED`] 切段，最后一段传 `last = true`。
    /// 被调换、截短、拼接或改动的密文在这里报 [`CoreError::Decrypt`]。
    pub fn open_chunk(&mut self, sealed: &[u8], last: bool) -> Result<Zeroizing<Vec<u8>>> {
        if self.finished || sealed.len() > CHUNK_SEALED || (!last && sealed.len() != CHUNK_SEALED) {
            return Err(CoreError::Decrypt);
        }
        let plain = self
            .cipher
            .decrypt(&nonce(self.counter, last), sealed)
            .map_err(|_| CoreError::Decrypt)?;
        self.counter += 1;
        self.finished = last;
        Ok(Zeroizing::new(plain))
    }

    /// 是否已经解到最后一段：下载结束时必须为真，不然文件被截短了。
    pub fn finished(&self) -> bool {
        self.finished
    }
}

/// 整段加密（小文件、测试用）。
pub fn seal_all(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    let mut encryptor = Encryptor::new(key);
    let mut out = Vec::with_capacity(sealed_len(plain.len() as u64) as usize);
    let mut chunks = plain.chunks(CHUNK_PLAIN).peekable();
    if chunks.peek().is_none() {
        out.extend(encryptor.seal_chunk(&[], true).expect("空的最后一段"));
    }
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        out.extend(encryptor.seal_chunk(chunk, last).expect("分段长度由 chunks 保证"));
    }
    out
}

/// 整段解密（小文件、测试用）。
pub fn open_all(key: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut decryptor = Decryptor::new(key);
    let mut out = Zeroizing::new(Vec::with_capacity(sealed.len()));
    let mut chunks = sealed.chunks(CHUNK_SEALED).peekable();
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        out.extend_from_slice(&decryptor.open_chunk(chunk, last)?);
    }
    if !decryptor.finished() {
        return Err(CoreError::Decrypt);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_various_sizes() {
        let key = generate_key();
        for size in [0, 1, CHUNK_PLAIN - 1, CHUNK_PLAIN, CHUNK_PLAIN + 1, 3 * CHUNK_PLAIN + 7] {
            let plain: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let sealed = seal_all(&key, &plain);
            assert_eq!(sealed.len() as u64, sealed_len(size as u64), "size {size}");
            assert_eq!(plain_len(sealed.len() as u64), Some(size as u64), "size {size}");
            assert_eq!(open_all(&key, &sealed).unwrap().as_slice(), plain.as_slice(), "size {size}");
        }
    }

    #[test]
    fn truncation_reorder_and_tamper_are_rejected() {
        let key = generate_key();
        let plain = vec![5u8; 2 * CHUNK_PLAIN + 10];
        let sealed = seal_all(&key, &plain);
        // 截掉最后一段：前两段都不是“最后一段”，解到头也没有结束标记。
        assert!(open_all(&key, &sealed[..2 * CHUNK_SEALED]).is_err());
        // 调换前两段。
        let mut swapped = sealed[CHUNK_SEALED..2 * CHUNK_SEALED].to_vec();
        swapped.extend_from_slice(&sealed[..CHUNK_SEALED]);
        swapped.extend_from_slice(&sealed[2 * CHUNK_SEALED..]);
        assert!(open_all(&key, &swapped).is_err());
        let mut tampered = sealed.clone();
        tampered[100] ^= 1;
        assert!(open_all(&key, &tampered).is_err());
        assert!(open_all(&generate_key(), &sealed).is_err());
    }

    #[test]
    fn impossible_lengths_are_rejected() {
        assert_eq!(plain_len(0), None);
        assert_eq!(plain_len(15), None);
        assert_eq!(plain_len(16), Some(0));
        assert_eq!(plain_len(CHUNK_SEALED as u64 + 16), None);
        assert_eq!(plain_len(CHUNK_SEALED as u64 + 17), Some(CHUNK_PLAIN as u64 + 1));
    }
}

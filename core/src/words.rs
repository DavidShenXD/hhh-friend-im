//! 给人看、给人输的编码：新电脑批准用的 4 个词、恢复密钥的两种写法。
//!
//! 词表是 BIP39 英文词表（2048 个词，前 4 个字母互不相同，输前 4 个字母就能认出是哪个词），
//! 随包带一份并用摘要锁住，防止被悄悄改动。
//!
//! 恢复密钥最终用哪种写法在重做原型时选（契约 §12 第 1 项），两种都在这里：
//! - [`RecoveryKey::to_words`]：12 个词（128 位 + 4 位校验，与 BIP39 助记词同样的算法）；
//! - [`RecoveryKey::to_groups`]：7 组、每组 4 个字母数字（Crockford base32，26 位数据 + 2 位校验）。
//!
//! [`RecoveryKey::parse`] 两种都认。

use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::keys::RecoveryKey;

const WORDLIST: &str = include_str!("wordlist-en.txt");

/// 新电脑批准用的词数：4 个词约 44 位。
pub const JOIN_CODE_WORDS: usize = 4;

fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| WORDLIST.lines().map(str::trim).filter(|w| !w.is_empty()).collect())
}

/// 认一个用户输入的词：整词，或唯一的前 4 个字母（大小写不论）。
fn index_of(input: &str) -> Option<usize> {
    let input = input.to_ascii_lowercase();
    if input.len() < 3 {
        return None;
    }
    let list = words();
    if let Ok(index) = list.binary_search(&input.as_str()) {
        return Some(index);
    }
    // 只输前 4 个字母（或更多）也认：BIP39 词表的前 4 个字母互不相同。
    if input.len() >= 4 {
        let prefix = &input[..4];
        let mut found = list.iter().enumerate().filter(|(_, w)| w.starts_with(prefix) && w.starts_with(input.as_str()));
        if let (Some((index, _)), None) = (found.next(), found.next()) {
            return Some(index);
        }
    }
    None
}

/// 新电脑批准用的一次性验证码：4 个词。新电脑生成并显示，用户在旧电脑上输入。
#[derive(Clone, PartialEq, Eq)]
pub struct JoinCode(Zeroizing<String>);

impl std::fmt::Debug for JoinCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JoinCode(…)")
    }
}

impl JoinCode {
    /// 随机生成 4 个词。
    pub fn generate() -> Self {
        let list = words();
        let picked: Vec<&str> = (0..JOIN_CODE_WORDS)
            .map(|_| {
                let raw = crypto::random::<2>();
                // 2048 = 2^11：取 16 位随机数的低 11 位，没有取模偏差。
                list[(u16::from_be_bytes(raw) & 0x07ff) as usize]
            })
            .collect();
        Self(Zeroizing::new(picked.join(" ")))
    }

    /// 解析用户输入：空格或横线分隔，大小写不论，每个词可只输前 4 个字母。
    pub fn parse(input: &str) -> Result<Self> {
        let list = words();
        let parts: Vec<&str> = input.split(|c: char| c.is_whitespace() || c == '-').filter(|p| !p.is_empty()).collect();
        if parts.len() != JOIN_CODE_WORDS {
            return Err(CoreError::format("验证码应是 4 个词"));
        }
        let mut normalized = Vec::with_capacity(JOIN_CODE_WORDS);
        for part in parts {
            let index = index_of(part).ok_or_else(|| CoreError::format("验证码里有不认识的词"))?;
            normalized.push(list[index]);
        }
        Ok(Self(Zeroizing::new(normalized.join(" "))))
    }

    /// 给人看的形式：4 个小写词，空格分隔。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn checksum_bits(entropy: &[u8; 16]) -> u8 {
    // BIP39：校验位是熵的 SHA-256 的前 (位数 / 32) 位，128 位熵对应 4 位。
    use sha2::{Digest, Sha256};
    Sha256::digest(entropy)[0] >> 4
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn crockford_value(c: char) -> Option<u32> {
    let c = c.to_ascii_uppercase();
    let c = match c {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    CROCKFORD.iter().position(|&b| b as char == c).map(|p| p as u32)
}

fn group_check(entropy: &[u8; 16]) -> u16 {
    // 10 位校验：恢复密钥摘要的前 10 位，抄错一个字符几乎一定能发现。
    let digest = crypto::hash("friend-im/v1/recovery/groups-check", entropy);
    u16::from_be_bytes([digest[0], digest[1]]) >> 6
}

impl RecoveryKey {
    /// 写成 12 个词。
    pub fn to_words(&self) -> Zeroizing<String> {
        let list = words();
        // 132 位 = 128 位熵 + 4 位校验，每 11 位一个词。
        let mut bits = Zeroizing::new(Vec::with_capacity(132));
        for byte in self.0 {
            for shift in (0..8).rev() {
                bits.push((byte >> shift) & 1);
            }
        }
        let check = checksum_bits(&self.0);
        for shift in (0..4).rev() {
            bits.push((check >> shift) & 1);
        }
        let picked: Vec<&str> = bits
            .chunks(11)
            .map(|chunk| list[chunk.iter().fold(0usize, |acc, &bit| (acc << 1) | bit as usize)])
            .collect();
        Zeroizing::new(picked.join(" "))
    }

    /// 写成 7 组、每组 4 个字母数字，用横线分隔。
    pub fn to_groups(&self) -> Zeroizing<String> {
        // 128 位熵补 2 个 0 位凑成 130 位 = 26 个 5 位字符，再接 10 位校验 = 2 个字符。
        let mut value = Zeroizing::new(Vec::with_capacity(28));
        let mut acc: u32 = 0;
        let mut have = 0;
        for byte in self.0 {
            acc = (acc << 8) | byte as u32;
            have += 8;
            while have >= 5 {
                have -= 5;
                value.push(CROCKFORD[((acc >> have) & 31) as usize]);
            }
        }
        value.push(CROCKFORD[((acc << (5 - have)) & 31) as usize]);
        let check = group_check(&self.0);
        value.push(CROCKFORD[((check >> 5) & 31) as usize]);
        value.push(CROCKFORD[(check & 31) as usize]);
        let groups: Vec<&str> = value.chunks(4).map(|c| std::str::from_utf8(c).expect("Crockford 字符都是 ASCII")).collect();
        Zeroizing::new(groups.join("-"))
    }

    /// 解析用户输入的恢复密钥：12 个词，或 28 个字母数字（横线、空格随意，`O`/`I`/`L` 按 Crockford 规则认）。
    pub fn parse(input: &str) -> Result<Self> {
        let tokens: Vec<&str> = input.split_whitespace().collect();
        if tokens.len() == 12 {
            return Self::parse_words(&tokens);
        }
        Self::parse_groups(input)
    }

    fn parse_words(tokens: &[&str]) -> Result<Self> {
        let mut bits = Zeroizing::new(Vec::with_capacity(132));
        for token in tokens {
            let index = index_of(token).ok_or_else(|| CoreError::format("恢复密钥里有不认识的词"))?;
            for shift in (0..11).rev() {
                bits.push(((index >> shift) & 1) as u8);
            }
        }
        let mut entropy = [0u8; 16];
        for (i, byte) in entropy.iter_mut().enumerate() {
            *byte = bits[i * 8..i * 8 + 8].iter().fold(0u8, |acc, &bit| (acc << 1) | bit);
        }
        let check = bits[128..132].iter().fold(0u8, |acc, &bit| (acc << 1) | bit);
        if check != checksum_bits(&entropy) {
            return Err(CoreError::format("恢复密钥校验不对，可能抄错了"));
        }
        Ok(Self(entropy))
    }

    fn parse_groups(input: &str) -> Result<Self> {
        let chars: Vec<char> = input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
        if chars.len() != 28 {
            return Err(CoreError::format("恢复密钥应是 12 个词或 28 个字母数字"));
        }
        let mut values = Vec::with_capacity(28);
        for c in chars {
            values.push(crockford_value(c).ok_or_else(|| CoreError::format("恢复密钥里有不认识的字符"))?);
        }
        let mut entropy = [0u8; 16];
        let mut acc: u32 = 0;
        let mut have = 0;
        let mut out = 0;
        for &v in &values[..26] {
            acc = (acc << 5) | v;
            have += 5;
            if have >= 8 && out < 16 {
                have -= 8;
                entropy[out] = ((acc >> have) & 0xff) as u8;
                out += 1;
            }
        }
        // 补的 2 个 0 位必须真是 0，不然是抄错了。
        if acc & ((1 << have) - 1) != 0 {
            return Err(CoreError::format("恢复密钥校验不对，可能抄错了"));
        }
        let check = ((values[26] << 5) | values[27]) as u16;
        if check != group_check(&entropy) {
            return Err(CoreError::format("恢复密钥校验不对，可能抄错了"));
        }
        Ok(Self(entropy))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_the_locked_bip39_english_list() {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(WORDLIST.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
        assert_eq!(words().len(), 2048);
        assert!(words().windows(2).all(|w| w[0] < w[1]), "词表要有序，二分查找才对");
    }

    #[test]
    fn join_code_parses_prefixes_and_case() {
        let code = JoinCode::generate();
        assert_eq!(code.as_str().split(' ').count(), 4);
        assert_eq!(JoinCode::parse(&code.as_str().to_uppercase()).unwrap(), code);
        let prefixes: Vec<String> = code.as_str().split(' ').map(|w| w.chars().take(4).collect()).collect();
        assert_eq!(JoinCode::parse(&prefixes.join("-")).unwrap(), code);
        assert!(JoinCode::parse("abandon ability able").is_err());
        assert!(JoinCode::parse("abandon ability able qqqq").is_err());
    }

    #[test]
    fn recovery_words_match_bip39_test_vector() {
        // BIP39 官方测试向量：全 0 的 128 位熵。
        let zero = RecoveryKey::from_bytes([0u8; 16]);
        assert_eq!(
            zero.to_words().as_str(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        let ff = RecoveryKey::from_bytes([0xffu8; 16]);
        assert_eq!(ff.to_words().as_str(), "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
    }

    #[test]
    fn recovery_round_trips_in_both_encodings() {
        for _ in 0..50 {
            let key = RecoveryKey::generate();
            assert_eq!(RecoveryKey::parse(&key.to_words()).unwrap(), key);
            let groups = key.to_groups();
            assert_eq!(groups.len(), 34);
            assert_eq!(RecoveryKey::parse(&groups).unwrap(), key);
            assert_eq!(RecoveryKey::parse(&groups.to_lowercase().replace('-', " ")).unwrap(), key);
        }
    }

    #[test]
    fn recovery_typos_are_caught_by_checksum() {
        // 固定的密钥：随机密钥下 4 位校验有 1/16 的机会碰巧对上，测试会偶发失败。
        let key = RecoveryKey::from_bytes(*b"friend-im-vector");
        let mut words: Vec<String> = key.to_words().split(' ').map(str::to_owned).collect();
        words.swap(0, 1);
        assert_ne!(words[0], words[1]);
        assert!(RecoveryKey::parse(&words.join(" ")).is_err());
        let groups = key.to_groups().to_string();
        let mut chars: Vec<char> = groups.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        assert!(RecoveryKey::parse(&chars.iter().collect::<String>()).is_err());
        assert!(RecoveryKey::parse("too short").is_err());
    }
}

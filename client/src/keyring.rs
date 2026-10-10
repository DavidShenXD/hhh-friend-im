//! 钥匙串：本机的账号钥匙各代、会话钥匙缓存。
//!
//! - 账号钥匙：打开封装给这台电脑的最新一代，沿旧钥匙链一路倒推出以前各代；每一代都和签名链里的公钥核对。
//! - 会话钥匙：按需向服务器取封装给我账号的那几份，打开最新的、沿旧钥匙链倒推，每一代都和会话签名链里的承诺核对。
//!   缓存最多 [`CONV_KEYS_MAX`] 把，按最近使用淘汰；淘汰了重新取一次就有。

use std::collections::{BTreeMap, HashMap};

use friend_im_core::account::AccountState;
use friend_im_core::conv::ConvState;
use friend_im_core::ids::{ConvId, Uid};
use friend_im_core::keys::{AccountSeed, ConvSeed, DeviceSecret, account_seed_info, conv_seed_info};
use friend_im_core::wire::{ConvGenerationBox, GenerationBox, GenerationWrap};

use crate::error::{ClientError, Result};

/// 会话钥匙缓存上限（方案 §6：4096 把）。
pub const CONV_KEYS_MAX: usize = 4096;

/// 钥匙串。
pub(crate) struct Keyring {
    /// 账号钥匙：（轮次，代数）→ 种子。
    account: BTreeMap<(u32, u32), AccountSeed>,
    /// 会话钥匙：（会话，代数）→（种子，最近使用的序号）。
    convs: HashMap<(ConvId, u32), (ConvSeed, u64)>,
    tick: u64,
}

impl Keyring {
    pub fn new() -> Self {
        Self {
            account: BTreeMap::new(),
            convs: HashMap::new(),
            tick: 0,
        }
    }

    /// 清空（重置账号后：旧一轮的钥匙用不上了）。
    pub fn clear(&mut self) {
        self.account.clear();
        self.convs.clear();
    }

    /// 账号钥匙某一代。
    pub fn account_seed(&self, epoch: u32, generation: u32) -> Option<&AccountSeed> {
        self.account.get(&(epoch, generation))
    }

    /// 账号钥匙当前一代（按签名链）。
    pub fn current_account_seed(&self, state: &AccountState) -> Result<&AccountSeed> {
        self.account_seed(state.epoch, state.current_key().generation)
            .ok_or_else(|| ClientError::state("还没拿到账号钥匙的当前一代"))
    }

    /// 记下一代自己刚生成的账号钥匙（开通、换代时）。
    pub fn put_account_seed(&mut self, epoch: u32, generation: u32, seed: AccountSeed) {
        self.account.insert((epoch, generation), seed);
    }

    /// 打开服务器给的账号钥匙封装（`opener` 是这台电脑或恢复密钥），沿旧钥匙链倒推，全部和签名链核对。
    pub fn open_account_keys(&mut self, opener: &DeviceSecret, state: &AccountState, boxes: &[GenerationBox], prev: &[GenerationWrap]) -> Result<()> {
        let mismatch = |e| ClientError::verify(format!("账号钥匙：{e}"));
        let mut opened = 0;
        for b in boxes {
            let expected = state.key(b.generation).ok_or_else(|| ClientError::verify("账号钥匙的代数不在签名链里"))?;
            let info = account_seed_info(&state.uid, state.epoch, b.generation, &opener.id());
            let seed = AccountSeed::from_slice(&opener.open(&info, &b.sealed).map_err(mismatch)?).map_err(mismatch)?;
            seed.check(expected).map_err(mismatch)?;
            self.account.insert((state.epoch, b.generation), seed);
            opened += 1;
        }
        if opened == 0 {
            return Err(ClientError::state("服务器上没有封装给这台电脑的账号钥匙"));
        }
        // 从有的最高一代往下倒推。
        let wraps: BTreeMap<u32, &GenerationWrap> = prev.iter().map(|w| (w.generation, w)).collect();
        let top = state.current_key().generation;
        for generation in (2..=top).rev() {
            if self.account.contains_key(&(state.epoch, generation - 1)) {
                continue;
            }
            let (Some(seed), Some(wrap)) = (self.account.get(&(state.epoch, generation)), wraps.get(&generation)) else {
                continue;
            };
            let older = seed.unwrap_previous(&state.uid, state.epoch, generation, &wrap.wrapped).map_err(mismatch)?;
            let expected = state.key(generation - 1).ok_or_else(|| ClientError::verify("旧钥匙链的代数不在签名链里"))?;
            older.check(expected).map_err(mismatch)?;
            self.account.insert((state.epoch, generation - 1), older);
        }
        Ok(())
    }

    /// 会话钥匙某一代（只看缓存）。
    pub fn conv_seed(&mut self, conv: &ConvId, generation: u32) -> Option<ConvSeed> {
        self.tick += 1;
        let tick = self.tick;
        let entry = self.convs.get_mut(&(conv.clone(), generation))?;
        entry.1 = tick;
        Some(entry.0.clone())
    }

    /// 放进一把会话钥匙；超过上限淘汰最久没用的。
    pub fn put_conv_seed(&mut self, conv: &ConvId, generation: u32, seed: ConvSeed) {
        self.tick += 1;
        if self.convs.len() >= CONV_KEYS_MAX
            && !self.convs.contains_key(&(conv.clone(), generation))
            && let Some(oldest) = self.convs.iter().min_by_key(|(_, (_, used))| *used).map(|(k, _)| k.clone())
        {
            self.convs.remove(&oldest);
        }
        self.convs.insert((conv.clone(), generation), (seed, self.tick));
    }

    /// 打开服务器给的会话钥匙封装：能开的都开（只有当前一轮账号钥匙封装的打得开），再沿旧钥匙链补齐，全部和会话签名链核对。
    pub fn open_conv_keys(&mut self, me: &Uid, state: &ConvState, boxes: &[ConvGenerationBox], prev: &[GenerationWrap]) -> Result<()> {
        let mismatch = |e| ClientError::verify(format!("会话钥匙：{e}"));
        let mut have: BTreeMap<u32, ConvSeed> = BTreeMap::new();
        for b in boxes {
            let Some(account) = self.account.get(&(b.account_epoch, b.account_generation)) else {
                continue;
            };
            let expected = state.key(b.generation).ok_or_else(|| ClientError::verify("会话钥匙的代数不在会话签名链里"))?;
            let info = conv_seed_info(&state.conv, b.generation, me, b.account_epoch, b.account_generation);
            let Ok(plain) = account.open(&info, &b.sealed) else {
                tracing::warn!(conv = %state.conv, generation = b.generation, "打不开封装给我的会话钥匙");
                continue;
            };
            let seed = ConvSeed::from_slice(&plain).map_err(mismatch)?;
            seed.check(expected).map_err(mismatch)?;
            have.insert(b.generation, seed);
        }
        let wraps: BTreeMap<u32, &GenerationWrap> = prev.iter().map(|w| (w.generation, w)).collect();
        let top = have.keys().next_back().copied().unwrap_or(0);
        for generation in (2..=top).rev() {
            if have.contains_key(&(generation - 1)) {
                continue;
            }
            let (Some(seed), Some(wrap)) = (have.get(&generation), wraps.get(&generation)) else {
                continue;
            };
            let older = seed.unwrap_previous(&state.conv, generation, &wrap.wrapped).map_err(mismatch)?;
            let expected = state.key(generation - 1).ok_or_else(|| ClientError::verify("旧钥匙链的代数不在会话签名链里"))?;
            older.check(expected).map_err(mismatch)?;
            have.insert(generation - 1, older);
        }
        for (generation, seed) in have {
            self.put_conv_seed(&state.conv, generation, seed);
        }
        Ok(())
    }
}

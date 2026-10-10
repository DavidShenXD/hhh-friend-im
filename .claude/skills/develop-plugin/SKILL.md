---
name: develop-plugin
description: 从这个模板起一个新的 HHH IM 插件，或给插件加功能：逐个实现协议方法、本地自检、在 HHH 里试。用户说“做一个 xx 的插件”“接上 xx 平台”“加个发图片”时用。
---

# 开发 HHH IM 插件

先读 `AGENTS.md`（规矩）与协议 `docs/protocol-v1.md`（在 hhh-im-sdk 仓库）。

## 起一个新 IM

1. 改清单 `hhh-im-provider.json`：`id`（发布后不能改，想清楚）、`name`、`version: 0.1.0`、`logo`、`publisher`、`source`（你的仓库）。
2. 改 `Cargo.toml` 的包名与 `src/main.rs` 里 `initialize` 的 `provider`，与清单一致；`scripts/pack.*` 里的程序名一起改。
3. 换掉 `src/main.rs` 的示例逻辑：
   - `initialize`：如实写 `platform`（`history`：平台能按时间读历史写 `server`，只能收推送写 `none`）与 `capabilities`。
   - `session/open`：有凭据就连平台、核验账号、回 `online`；没有或失效回 `needsLogin`，HHH 随后调 `login/start`。
   - 登录：`login/start` 后用 `login/step` 推二维码 / 打开链接 / 表单；成功先 `credential/save` 等 HHH 回复，再发 `login/finished`。
   - 收消息：平台推来的翻成 `Event` 用 `events/push` 推给 HHH；`history = none` 的每批带 `syncState`，HHH 确认了才算交接。
   - 发消息：`messages/send` 翻成平台调用，回 `accepted`（带平台记下的消息）或 `unknown`。
4. 每加一个方法：对照协议写参数与结果，错误用协议的错误分类（`RpcError::from_kind`），给用户看的原因写人话。

## 每次改完

1. `cargo build --release`。
2. `scripts/pack`（Windows：`powershell -File scripts/pack.ps1`），再 `hhh-im-check dist/stage/hhh-im-provider.json`，全部通过。
3. HHH：设置 → IM → 添加 IM → 文件夹，选 `dist/stage`；已经装过就在卡片「管理 → 从文件更新」选它。登录、收、发都试一遍。

## 不要

- 不在插件里存聊天记录、凭据、配置（交给 HHH）。
- 不往标准输出打协议以外的东西（日志用 `log/write`）。
- 协议没有的能力不伪造；需要就去 hhh-im-sdk 提 issue。

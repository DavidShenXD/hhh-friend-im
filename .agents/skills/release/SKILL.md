---
name: release
description: 给这个 HHH IM 插件发一个新版本：改版本号、打包、核对、发布到 GitHub / GitLab。用户说“发版本”“发布 x.y.z”“出个包”时用。
---

# 发版本

规矩以 hhh-im-sdk 的 `docs/release.md` 为准；这里是步骤。

标签与 Release 标题都只用 `v<版本>`（例如 `v0.3.14`），必须完全一致，不拼接清单的 `name`、`Cindy IM` 或其他前后缀。
`hhh-im-pack --publish` 默认以标签作为标题；不要另行覆盖为产品名加版本号。

1. 定版本号：比仓库里最新的正式版本大（`主.次.修订`）。改清单 `hhh-im-provider.json` 的 `version`，`Cargo.toml` 的 `version` 一起改。
2. 写更新说明 `notes.md`（Markdown，给用户看，2000 字以内：改进、修复，一条一行）。
3. 本地核对：`scripts/pack`（Windows：`powershell -File scripts/pack.ps1`），`hhh-im-check dist/stage/hhh-im-provider.json` 全部通过；
   在 HHH 里「管理 → 从文件更新」装 `dist/` 里的 `.hhhim` 试一遍。
4. 提交，打标签 `v<版本>`（与清单完全一致），推提交与标签。
5. 发布：令牌放环境变量 `HHH_IM_PUBLISH_TOKEN`（GitHub 写 Contents 权限；GitLab 带 `api` 的个人访问令牌），不写进任何文件、不贴进对话：
   - Windows：`powershell -File scripts/pack.ps1 -Publish`
   - macOS / Linux：`scripts/pack.sh --publish`
   要出几个系统的包就在几台电脑上各跑一次；同一版本的索引会合并。
6. 读回 Release，核对标签与标题都等于 `v<版本>`。GitHub 用 `gh release view v<版本> --repo MagicLizi/hhh-friend-im --json tagName,name`；标题不符时用 `gh release edit v<版本> --repo MagicLizi/hhh-friend-im --title v<版本>` 只修正标题，再读回核对。
7. 核对：Release 上有每个目标的 `.hhhim` 与 `hhhim-release.json`；在 HHH 里打开设置 → IM，卡片写“有新版本 x.y.z”，点更新能装上。

标签与清单版本对不上、版本没往上加时打包工具会拒绝，照它说的改，不要绕过。

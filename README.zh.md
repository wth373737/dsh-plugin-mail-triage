# dsh-plugin-mail-triage

**邮件分诊与安全清理** · DeepSeek Harness 插件

把"增量读取 → 分类打标 → 人工确认 → 才允许软删除"做成一条可审计的流水线。
读和写是两套工具、两条代码路径；删除只会**移动到回收站**，插件里没有任何 expunge。

## 它做什么

```
邮箱 IMAP
  → 增量同步（只读，元数据 + 正文片段）
  → 规则引擎硬保护（验证码、账单、附件、钓鱼、学校/公务、已发送、白名单…）
  → 本地小模型批量分类、打标、写摘要（可选；不可用时全部进黄桶）
  → 三桶：绿=可清理候选 / 黄=待复核 / 红=永不自动删除
  → 生成中文分诊报告 + 本地标签清单
  → 你确认 → 生成 manifest（含内容哈希）
  → 审批卡片 → MOVE 到回收站
  → 审计日志（谁触发、哪个模型、理由、审批状态、结果）
```

**默认第一步只读**：第一次运行只读取和打标，不改任何东西。

## 工具

| 工具 | 读写 | 作用 |
| --- | --- | --- |
| `mail_triage_accounts` | 元数据 | `list` / `import_thunderbird` / `set_secret` / `test` / `remove` |
| `mail_triage_scan` | **只读** | 增量扫描 + 规则 + 本地模型分类 + 报告 |
| `mail_triage_review` | 本地 | 取黄桶待复核清单 / 回填判定 |
| `mail_triage_plan` | **只读** | 生成删除候选清单与 manifest（不碰邮箱） |
| `mail_triage_apply` | **写** | 审批通过后 MOVE 到回收站（唯一会改邮箱的工具） |
| `mail_triage_audit` | 只读 | 审计日志、报告与 manifest 列表 |

## 凭据从哪来：雷鸟

插件不要求你手输密码。它读取本机 **Thunderbird** 的 `key4.db` + `logins.json`，
解密出你已经在雷鸟里登录过的账号凭据（密码 / 客户端授权码 / OAuth 刷新令牌），
存进 **本机 DSH 凭据库**，此后独立工作。

- 雷鸟没设主密码时，导入一步完成；设了主密码则需要你输入一次。
- 解密只在本机进行，**凭据不写入工作区明文，也不上传任何地方**；宿主没有凭据服务时，
  插件会直接拒绝保存并说明原因，而不是退回写一个明文文件。
- 导入是一次性动作，需要你在卡片上点"允许导入"。
- Microsoft 令牌每次刷新会轮换，插件会保存新的那份；雷鸟仍可正常使用。

> 技术说明：`key4.db` 由 `node:sqlite` 读取，NSS 的 PBES2（PBKDF2-HMAC-SHA256 +
> AES-256-CBC）由 `node:crypto` 重实现。不需要 Python、NSS DLL 或任何原生模块。

## 安装

**从 GitHub（推荐）**

在 DSH 界面「插件 → + 添加插件」里填：

```
github:wth373737/dsh-plugin-mail-triage
```

安装时 pnpm 会自动装好唯一依赖 `imapflow`。

**从本地目录**

```bash
pnpm add file:/path/to/dsh-plugin-mail-triage
```

## 使用流程

1. `mail_triage_accounts` `{ "action": "import_thunderbird" }` —— 导入账号（需批准一次）
2. `mail_triage_accounts` `{ "action": "test" }` —— 验证每个账号能连上、找到回收站
3. `mail_triage_scan` —— 只读扫描，产出报告（此步不动邮箱）
4. `mail_triage_review` —— 复核黄桶（或让会话模型逐条给判定后回填）
5. `mail_triage_plan` —— 生成删除清单 + manifest
6. `mail_triage_apply` `{ "manifestId": "..." }` —— 审批后移动到回收站
7. `mail_triage_audit` —— 查审计

## 安全设计（写死在代码里）

- 规则层只能**保护**，不能单独产生删除。
- 低置信 / 模型输出不合 schema / 超时 / 模型不可用 → 一律黄桶。
- 不可删类别（验证码、账单发票、钓鱼、附件风险、公务、学术、个人重要、已发送草稿）→ 红桶。
- 只移动到 `\Trash`，找不到回收站就**拒绝执行**而不是猜。
- manifest 带内容哈希，执行前重新校验；不一致直接拒绝。
- 每次写入都有审计记录。

## 状态目录

工作区下的 `.mail-triage/`：`config.json`、`state.json`（增量游标）、
`labels.jsonl`、`verdicts.jsonl`、`audit.jsonl`、`manifests/`、`reports/`。
全部是纯文本，可自行查看、备份或删除。

## 配置

见 `cordis.patch.yml`。常改的几项：

```yaml
scan:
  lookbackDays: 30      # 首次回溯天数
  maxPerRun: 200        # 每个文件夹单次上限
localModel:
  enabled: true         # false 则所有未保护邮件进黄桶（不消耗本地模型）
  model: qwen2.5:7b
safety:
  minAgeDays: 7         # 太新的邮件不进绿桶
  maxDeletesPerRun: 50
  protectDomains: [example.edu, other.example.edu]
  protectSenders: []
```

## 已知限制

- Gmail 若走雷鸟的 Google 授权令牌，个别账号可能无法刷新；此时用 `set_secret`
  填 16 位应用专用密码即可。
- 网易邮箱链接后必须先发 IMAP `ID`（插件已处理），否则服务器会判"不安全登录"。
- 非 UTF-8 编码的邮件正文会显示为乱码（如部分马来语/阿拉伯语邮件用
  windows-1256 编码）。分类仍然可用，只是摘要文字不美观；后续会接入字符集解码。
- 邮件头超过 8 KB（大量 DKIM/ARC 记录）时会二次抓取一次正文；仍拿不到就留空。
- 若雷鸟里的某个 OAuth 授权已过期，插件会如实报错。**在雷鸟里重新登录一次该账号，
  再运行一次 `import_thunderbird` 即可修复**——插件不需要你做别的配置。
- IMAP 服务商的限流、断线重连未做深度优化；单次扫描控制在几百封以内。
- 只处理 INBOX（可配置其它文件夹），不会自动展开子文件夹。
- `node:sqlite` 需要 Node 22.5 及以上。DSH 自带的运行时满足这一条；更老的宿主上插件会直接
  加载失败，而不是降级运行。
- 用 `set_secret` 输入的密码、用 `import_thunderbird` 输入的雷鸟主密码，都会留在这次对话的
  记录里。雷鸟里已经存了密码时，优先用 `import_thunderbird`。
- 1.0.2 之前的版本可能在工作区留下明文 `.mail-triage/secrets.json`：下一次运行
  `mail_triage_accounts` 时会把它迁移进凭据库并删除该文件；凭据服务不可用时则保留文件，
  并提示你手动删除。

## 开发提示

改动插件代码后，Host 进程仍持有旧的模块实例：在「插件」面板把本插件关掉再打开，
即可加载新代码（无需重启整个应用）。

## 开发

```bash
npm test    # 离线冒烟测试：规则、决策矩阵、schema 校验、正文解码、状态、报告、账号归并
```

测试不联网、不连真实邮箱、不写工作区之外。

## License

MIT © 2026 wth373737

## 审批卡片的设计约束（踩过的坑）

卡片正文必须短：DSH 的提问卡片高度有限，正文超过约 6 行时，**选项按钮会被挤出可视区**，
用户只能看到文字、点不到"允许/取消"，实际上等于无法授权。

规则：
- 卡片里只放"数量 + 总量 + 是否可恢复"这类一眼能看完的信息；
- 逐条清单、样例邮件、体积明细一律放在工具的返回值里，由会话模型在对话中展示；
- 需要用户看细节时，先生成报告/manifest 文件让他打开，再弹一张短卡片确认。


## 完成度与验证状态（1.0.0）

**已在真实邮箱上验证**

- 从雷鸟导入 7 个账号（Microsoft 365 / Gmail / 163），零手输凭据
- IMAP 认证：Microsoft 365 OAuth2（XOAUTH2，令牌自动轮换并回写）、Gmail（OAuth 或应用专用密码）、163（含 IMAP ID 命令）
- 只读增量扫描 612 封、硬保护规则、本地模型分类、三桶、中文报告
- 清单 → manifest（含内容哈希）→ 审批卡片 → 批量 MOVE 到回收站
- 审计日志 354 条真实操作，0 失败；两轮共移动 354 封 / 796 MB

**尚未验证或未实现**

- Gmail / 163 只验证了连接与扫描，未做过真实删除
- 非 UTF-8 正文（如 windows-1256）会显示为乱码，分类仍可用
- 默认只扫 INBOX；其它文件夹可配置但未验证
- 不做附件单独清理、不自动展开子文件夹、不提供"清空回收站"（不可恢复操作刻意留给用户）

## 保护策略可按工作区覆盖

发布包里 `protectDomains` 默认是空的（不把任何机构域名写死）。个人策略放在工作区
`.mail-triage/config.json` 的 `safety` 段，会覆盖插件配置：

```json
{
  "safety": {
    "protectDomains": ["example.edu"],
    "protectSenders": [],
    "minAgeDays": 7
  }
}
```

这样升级插件不会冲掉你自己的保护名单。

## 已知故障与修复：凭据键格式（1.0.1）

1.0.0 把邮箱地址直接当 DSH 凭据键写库（例如 `mail-triage/0209560@student.uow.edu.my`）。
DSH 的凭据键要求**每个 `/` 段都匹配 `^[a-z][a-z0-9-]*$`**，加载时校验失败会让整个
`credentials` 服务抛错；它是必需插件，于是**宿主启动直接崩溃**。

1.0.1 起账号 id 会先被 slug 化再作为键段（`0209560@student.uow.edu.my`
→ `a0209560-student-uow-edu-my`），并对生成的键做二次校验，无法合法化时回退到哈希键。

**如果你已经因为 1.0.0 崩溃**，手工修法是编辑 `~/.dsh/.credentials.yaml`（Windows 为
`%APPDATA%` 同级或 DSH_HOME 下的 `.credentials.yaml`），把 `records` 里不合法的键名改成
slug 形式：小写、非字母数字一律换成 `-`、数字开头则前面加 `a`。

## 1.0.2：明文回退已移除

更早的版本在拿不到宿主凭据服务（`credentials`）时，会把密码 / OAuth 令牌写进工作区的
`.mail-triage/secrets.json`。这和本文档说的「不写入工作区明文」不符，也等于把一个密码库
放在随时会被一次 `git add -A` 收走的位置。

1.0.2 起：

- 没有凭据服务就**直接拒绝**保存与读取，并在错误里说明原因，不退回写文件；
- 工作区里已有的旧明文 `secrets.json` 会在下一次调用 `mail_triage_accounts` 时迁移进
  凭据库并删除；凭据服务不可用时保留文件并提示手动删除；
- `package.json` 补上 `engines.node >= 22.5`（`node:sqlite` 的要求）与 `repository` 字段。

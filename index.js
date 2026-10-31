/**
 * dsh-plugin-mail-triage — mail triage and safe cleanup for DeepSeek Harness.
 *
 * Design rules that are enforced in code, not just documented:
 *   1. Reading and writing are different tools. `mail_triage_scan` cannot
 *      change a mailbox; `mail_triage_apply` is the only mutating tool.
 *   2. The rule layer can only protect. It never produces a deletion on its own.
 *   3. Low confidence, a schema-invalid model answer, a timeout or a missing
 *      model all fall to the yellow bucket. Nothing is deleted on a guess.
 *   4. Deletion means MOVE to the server's Trash mailbox. There is no expunge
 *      anywhere in this plugin, so every action stays recoverable.
 *   5. Every mutating batch has a manifest with a content hash and an
 *      approval card; every move is written to an audit log.
 */
import { createTokenCache } from './lib/oauth.mjs'
import { createTools } from './lib/tools.mjs'

export const name = 'mail-triage'
export const inject = ['tools']

const DEFAULTS = {
  stateDir: '.mail-triage',
  scan: {
    lookbackDays: 30,
    maxPerRun: 200,
    mailboxes: ['INBOX'],
  },
  localModel: {
    enabled: true,
    baseURL: 'http://127.0.0.1:11434',
    model: 'qwen2.5:7b',
    timeoutMs: 120000,
    concurrency: 2,
  },
  safety: {
    requireApproval: true,
    minAgeDays: 7,
    maxDeletesPerRun: 50,
    confidenceThreshold: 0.85,
    protectDomains: [],
    protectSenders: [],
    neverDeleteCategories: [
      '验证码/一次性通知',
      '账单/发票',
      '钓鱼可疑',
      '附件风险',
      '公务交流',
      '学术交流',
      '个人重要',
      '已发送/草稿',
    ],
  },
  thunderbird: {
    enabled: true,
    profiles: [],
  },
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function mergeConfig(base, override) {
  if (!isPlainObject(override)) return base
  const out = Array.isArray(base) ? [...base] : { ...base }
  for (const [key, value] of Object.entries(override)) {
    if (isPlainObject(value) && isPlainObject(out[key])) out[key] = mergeConfig(out[key], value)
    else out[key] = value
  }
  return out
}

export function apply(ctx, config = {}) {
  const resolved = mergeConfig(DEFAULTS, config)
  const deps = {
    ctx,
    config: resolved,
    tokenCache: createTokenCache(),
  }
  for (const tool of createTools(deps)) {
    ctx.effect(() => ctx.tools.register(tool))
  }
}

/**
 * Triage logic: a deterministic rule layer that can only *protect*, plus an
 * optional local-model classifier that can only *propose*.
 *
 * Hard rules never produce a deletion. A message reaches the green bucket only
 * when the rule layer saw nothing to protect, the model's answer passes schema
 * validation, and the confidence clears the threshold. Anything unusual falls to
 * yellow, which a human or the session model has to review.
 */

export const CATEGORIES = [
  '广告营销',
  '订阅简报',
  '社交通知',
  '验证码/一次性通知',
  '过期通知',
  '物流通知',
  '账单/发票',
  '钓鱼可疑',
  '附件风险',
  '公务交流',
  '学术交流',
  '个人重要',
  '已发送/草稿',
  '存疑未知',
]

export const ACTIONS = ['keep', 'archive', 'delete_candidate', 'review_required', 'quarantine']

export const RISK_FLAGS = [
  'has_attachment',
  'external_sender',
  'looks_phishing',
  'contains_invoice',
  'contains_credential',
  'thread_with_human',
  'user_whitelisted',
  'is_sent_or_draft',
]

/** Categories where automatic deletion is never allowed. */
export const NEVER_DELETE = new Set([
  '验证码/一次性通知',
  '账单/发票',
  '钓鱼可疑',
  '附件风险',
  '公务交流',
  '学术交流',
  '个人重要',
  '已发送/草稿',
])

/**
 * Even in the explicit space-reclaim path, anything that records an academic or
 * financial fact about the user stays out: registrations, results, offers,
 * applications, fees and credentials are not "announcements" even when they
 * arrive from an automated campus sender.
 */
export const BULK_RECLAIM_EXCLUDE_RE =
  /(pendaftaran|registration|daftar|keputusan|result|gred|grade|markah|transcript|tawaran|offer|permohonan|application|ijazah|graduation|konvokesyen|yuran|fee|payment|invoice|resit|receipt|kata laluan|password|otp|verifikasi|verification|exam|ujian|peperiksaan|timetable|jadual waktu|slip)/i

/** Categories that may become delete candidates when confidence is high. */
export const DELETABLE = new Set(['广告营销', '订阅简报', '社交通知', '过期通知', '物流通知'])

/**
 * Flags that stop a message from ever reaching the green bucket. `external_sender`
 * is deliberately absent: nearly every newsletter comes from an external domain,
 * so treating it as a blocker would make green unreachable.
 */
export const BLOCKING_FLAGS = new Set([
  'contains_credential',
  'contains_invoice',
  'looks_phishing',
  'has_attachment',
  'risky_attachment',
  'thread_with_human',
  'user_whitelisted',
  'is_sent_or_draft',
])

/** Documents that carry a right to exist: never treat as disposable. */
export const PROTECTED_CATEGORIES = NEVER_DELETE

const CREDENTIAL_RE =
  /(验证码|校验码|动态码|动态密码|一次性密码|安全代码|登录代码|临时密码|激活码|verification code|verify code|security code|one[- ]?time (password|passcode|code)|otp\b|2fa code|login code|passcode|magic link|重置密码|password reset|reset your password|登录链接)/i

const INVOICE_RE =
  /(发票|账单|对账单|付款|支付成功|收款|报销|invoice|receipt|billing statement|payment received|order confirmation|订单确认|订阅续费|续费提醒|扣费)/i

const ACADEMIC_RE =
  /(教务|选课|学分|成绩单|成绩|考试|答辩|导师|导师组|学期|注册|缴费通知|校园|课程安排|lecturer|professor|supervisor|assignment|course|transcript|semester|enrol)/i

const OFFICIAL_RE = /(公务|公文|会议通知|人事|财务处|学生事务|行政|official|administration|registrar|faculty office)/i

const PHISHING_RE =
  /(账户异常|账号异常|账号被锁定|立即验证|重新登录以|安全警告|中奖|领取奖品|限时领取|点击下方链接|点击链接验证|suspended|verify your account|account (will be )?(closed|suspended)|unusual activity|confirm your identity)/i

const BULK_HINT_RE = /(no-?reply|do-?not-?reply|newsletter|notification|notify|mailer|marketing|promo|updates?@|news@|info@|service@|support@)/i

const RISKY_ATTACHMENT_RE = /\.(exe|scr|js|jse|vbs|vbe|hta|bat|cmd|com|msi|ps1|lnk|iso|img|docm|xlsm|pptm|jar|apk)(\b|$)/i

const SHORTENER_RE = /(bit\.ly|t\.cn|tinyurl\.com|goo\.gl|is\.gd|ow\.ly|rebrand\.ly|shorturl\.at)/i

function domainOf(address) {
  const at = String(address ?? '').lastIndexOf('@')
  return at >= 0 ? String(address).slice(at + 1).toLowerCase() : ''
}

function matchesDomain(domain, list) {
  if (!domain) return false
  return list.some((entry) => {
    const needle = String(entry).toLowerCase().trim()
    if (!needle) return false
    return domain === needle || domain.endsWith(`.${needle}`)
  })
}

function looksLikeBrandSpoof(message) {
  const { fromName, fromAddress } = message
  if (!fromName) return false
  const brand = /(paypal|apple|microsoft|google|amazon|netflix|bank|maybank|cimb|dhl|fedex|ups|政府|银行|学校|大学)/i
  if (!brand.test(fromName)) return false
  const domain = domainOf(fromAddress)
  return !brand.test(domain) && !/\.edu(\.[a-z]{2})?$/.test(domain)
}

/**
 * Deterministic protection layer.
 * @param {object} message triage message (envelope fields + snippet + flags)
 * @param {object} cfg safety config
 * @param {string} [mailboxKind] 'inbox' | 'sent' | 'drafts' | 'other'
 */
export function applyHardRules(message, cfg, mailboxKind = 'inbox') {
  const reasons = []
  const flags = new Set()
  const haystack = `${message.subject ?? ''}\n${message.snippet ?? ''}\n${message.fromName ?? ''}`
  const fromDomain = domainOf(message.fromAddress)

  if (mailboxKind === 'sent' || mailboxKind === 'drafts') {
    flags.add('is_sent_or_draft')
    reasons.push('sent_or_draft')
  }

  if (matchesDomain(fromDomain, cfg.protectDomains ?? []) || (cfg.protectSenders ?? []).some((s) => String(s).toLowerCase() === message.fromAddress)) {
    flags.add('user_whitelisted')
    reasons.push('whitelisted_sender')
  }

  if (CREDENTIAL_RE.test(haystack)) {
    flags.add('contains_credential')
    reasons.push('contains_credential')
  }

  if (INVOICE_RE.test(haystack)) {
    flags.add('contains_invoice')
    reasons.push('contains_invoice')
  }

  if (message.inReplyTo) {
    flags.add('thread_with_human')
    if (!BULK_HINT_RE.test(message.fromAddress ?? '')) reasons.push('thread_with_human')
  }

  // Attachments are judged by their real filenames (BODYSTRUCTURE), never by
  // scanning body text: a tracking URL ending in ".js" is not an attachment.
  const attachmentNames = (message.attachments ?? []).map((entry) => String(entry?.filename ?? ''))
  const riskyAttachment = attachmentNames.some((name) => RISKY_ATTACHMENT_RE.test(name))
  if (riskyAttachment) {
    flags.add('has_attachment')
    flags.add('risky_attachment')
    reasons.push('risky_attachment')
  } else if (attachmentNames.length > 0) {
    flags.add('has_attachment')
    reasons.push('has_attachment')
  }

  const fromDomainProtected = matchesDomain(fromDomain, cfg.protectDomains ?? [])
  if (!fromDomainProtected && fromDomain) flags.add('external_sender')

  if (PHISHING_RE.test(haystack) || SHORTENER_RE.test(haystack) || looksLikeBrandSpoof(message)) {
    flags.add('looks_phishing')
    reasons.push('looks_phishing')
  }

  const academic =
    ACADEMIC_RE.test(haystack) || /\.(edu|ac)(\.[a-z]{2,3})?$/i.test(fromDomain) || matchesDomain(fromDomain, cfg.protectDomains ?? [])
  const official = OFFICIAL_RE.test(haystack)
  if (academic) reasons.push('academic_or_official')
  if (official) reasons.push('official')

  return { flags: [...flags], reasons, protected: reasons.length > 0, academic, official }
}

/** Folder kind used by the rules. */
export function mailboxKindOf(box, mailboxPath) {
  const flags = box?.flags ?? []
  const special = box?.specialUse ?? ''
  if (/\\Sent/i.test(special) || flags.includes('\\Sent') || /^(sent|sent items|已发送)$/i.test(box?.name ?? '')) return 'sent'
  if (/\\Drafts/i.test(special) || flags.includes('\\Drafts') || /^(drafts|草稿箱?)$/i.test(box?.name ?? '')) return 'drafts'
  if (/\\Junk|\\Spam/i.test(special) || /(spam|junk|垃圾邮件)/i.test(box?.name ?? '')) return 'junk'
  if (mailboxPath === 'INBOX') return 'inbox'
  return 'other'
}

/* ------------------------------------------------------------ local model */

const SYSTEM_PROMPT =
  '你是邮件分诊器。只输出一个 JSON 对象，不要解释，不要加代码块标记。字段：category（必须是给定枚举之一）、confidence（0 到 1 的小数）、summary（不超过 60 字的中文概括）、risk_flags（数组，可为空）。'

export function buildClassifyPrompt(message) {
  return [
    `类别枚举：${CATEGORIES.join('、')}`,
    '风险标记枚举：has_attachment, external_sender, looks_phishing, contains_invoice, contains_credential, thread_with_human, user_whitelisted, is_sent_or_draft',
    '',
    `发件人名称：${message.fromName || '(空)'}`,
    `发件人地址：${message.fromAddress || '(空)'}`,
    `主题：${message.subject || '(空)'}`,
    `日期：${message.date ?? message.internalDate ?? '(未知)'}`,
    `正文片段：${(message.snippet || '(空)').slice(0, 1200)}`,
    '',
    '判断这封邮件属于哪一类，以及它是否值得保留。广告、简报、社交通知、物流通知、已过期通知才可能是可清理的；任何账单、验证码、附件、钓鱼、学校或公务相关都不可清理。',
  ].join('\n')
}

/** Validate one model answer against the schema; returns reasons when invalid. */
export function validateClassification(raw, parsed) {
  const reasons = []
  if (!parsed || typeof parsed !== 'object') return ['not_object']
  if (!CATEGORIES.includes(parsed.category)) reasons.push(`category_not_in_enum(${String(parsed.category).slice(0, 20)})`)
  const confidence = Number(parsed.confidence)
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) reasons.push('confidence_invalid')
  if (typeof parsed.summary !== 'string' || parsed.summary.trim().length === 0) reasons.push('summary_missing')
  if (parsed.risk_flags != null && !Array.isArray(parsed.risk_flags)) reasons.push('risk_flags_not_array')
  return reasons
}

export function parseModelAnswer(text) {
  const cleaned = String(text ?? '')
    .replace(/^\s*```(?:json)?/i, '')
    .replace(/```\s*$/, '')
    .trim()
  try {
    return { parsed: JSON.parse(cleaned), reasons: [] }
  } catch {
    return { parsed: null, reasons: ['json_parse'] }
  }
}

/**
 * Classify a batch with a local Ollama model.
 * Returns one entry per message; failures are reported, never silently dropped.
 * @param {object[]} messages
 * @param {{baseURL: string, model: string, concurrency?: number, timeoutMs?: number, signal?: AbortSignal}} cfg
 */
export async function classifyWithLocalModel(messages, cfg) {
  const base = String(cfg.baseURL ?? 'http://127.0.0.1:11434').replace(/\/+$/, '')
  const model = String(cfg.model ?? 'qwen2.5:7b')
  const concurrency = Math.max(1, Math.min(6, Number(cfg.concurrency) || 2))
  const timeoutMs = Math.max(5000, Number(cfg.timeoutMs) || 120000)
  const results = new Map()
  let cursor = 0

  const one = async (message) => {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(new Error(`timeout ${timeoutMs}ms`)), timeoutMs)
    const relay = () => controller.abort(new Error('cancelled'))
    cfg.signal?.addEventListener?.('abort', relay, { once: true })
    try {
      const response = await fetch(`${base}/api/chat`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          model,
          stream: false,
          format: 'json',
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: buildClassifyPrompt(message) },
          ],
          options: { temperature: 0.1, num_ctx: 4096 },
        }),
        signal: controller.signal,
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const payload = await response.json()
      const text = String(payload?.message?.content ?? '')
      const { parsed, reasons } = parseModelAnswer(text)
      const validation = reasons.length > 0 ? reasons : validateClassification(text, parsed)
      return { ok: validation.length === 0, parsed, reasons: validation, model }
    } catch (error) {
      return { ok: false, parsed: null, reasons: [`call_failed(${String(error?.message ?? error).slice(0, 80)})`], model }
    } finally {
      clearTimeout(timer)
      cfg.signal?.removeEventListener?.('abort', relay)
    }
  }

  const worker = async () => {
    while (cursor < messages.length) {
      const index = cursor++
      results.set(messages[index].key, await one(messages[index]))
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, messages.length || 1) }, worker))
  return results
}

/* --------------------------------------------------------------- decision */

/**
 * Combine rules, model output and the safety config into a bucket.
 * @returns {{bucket: 'red'|'yellow'|'green', category: string, action: string, confidence: number, flags: string[], reasons: string[], summary: string, model: string}}
 */
export function decide(message, rules, modelResult, cfg) {
  const flags = new Set(rules.flags)
  for (const flag of modelResult?.parsed?.risk_flags ?? []) {
    if (RISK_FLAGS.includes(flag)) flags.add(flag)
  }
  const reasons = [...rules.reasons]
  let category = String(modelResult?.parsed?.category ?? '存疑未知')
  let confidence = Number(modelResult?.parsed?.confidence ?? 0)
  const summary = String(modelResult?.parsed?.summary ?? '').slice(0, 200)
  const model = modelResult?.ok ? (modelResult.model ?? 'local') : 'rules-only'

  if (rules.protected) {
    if (flags.has('is_sent_or_draft')) category = '已发送/草稿'
    else if (flags.has('contains_credential')) category = '验证码/一次性通知'
    else if (flags.has('contains_invoice')) category = '账单/发票'
    else if (flags.has('looks_phishing')) category = '钓鱼可疑'
    else if (rules.academic) category = '学术交流'
    else if (rules.official) category = '公务交流'
    else if (flags.has('has_attachment')) category = '附件风险'
    return { bucket: 'red', category, action: 'keep', confidence: 1, flags: [...flags], reasons, summary: summary || '命中硬保护规则，永不自动处理', model }
  }

  if (!modelResult?.ok) {
    reasons.push(...(modelResult?.reasons ?? ['no_model']))
    return { bucket: 'yellow', category: '存疑未知', action: 'review_required', confidence: 0, flags: [...flags], reasons, summary: summary || '本地模型不可用或结果不合规，转人工复核', model }
  }

  if (NEVER_DELETE.has(category)) {
    return { bucket: 'red', category, action: 'keep', confidence, flags: [...flags], reasons, summary, model }
  }
  const blocking = [...flags].filter((flag) => BLOCKING_FLAGS.has(flag))
  if (blocking.length > 0) {
    reasons.push(`blocking_flags(${blocking.join('|')})`)
    return { bucket: 'yellow', category, action: 'review_required', confidence, flags: [...flags], reasons, summary, model }
  }
  if (!DELETABLE.has(category)) {
    return { bucket: 'yellow', category, action: 'review_required', confidence, flags: [...flags], reasons, summary, model }
  }

  const threshold = Number(cfg.confidenceThreshold ?? 0.85)
  if (confidence < threshold) {
    reasons.push(`low_confidence(${confidence.toFixed(2)}<${threshold})`)
    return { bucket: 'yellow', category, action: 'review_required', confidence, flags: [...flags], reasons, summary, model }
  }

  const ageDays = message.internalDate ? (Date.now() - new Date(message.internalDate).getTime()) / 86_400_000 : 0
  const minAge = Number(cfg.minAgeDays ?? 7)
  if (ageDays < minAge) {
    reasons.push(`too_recent(${ageDays.toFixed(1)}d<${minAge}d)`)
    return { bucket: 'yellow', category, action: 'review_required', confidence, flags: [...flags], reasons, summary, model }
  }

  return { bucket: 'green', category, action: 'delete_candidate', confidence, flags: [...flags], reasons, summary, model }
}

/** Stable key for a message inside the local label store. */
export function messageKey(accountId, mailbox, uidValidity, uid) {
  return `${accountId}|${mailbox}|${uidValidity}|${uid}`
}

/** Group triage results into the three buckets for the report. */
export function bucketize(rows) {
  const buckets = { green: [], yellow: [], red: [] }
  for (const row of rows) buckets[row.bucket].push(row)
  return buckets
}

/**
 * Offline smoke test: no network, no real mailbox, no credentials.
 * Covers the rule layer, the decision matrix, schema validation, the store,
 * the report and the pure shaping helpers.
 *
 *   node test/smoke.mjs
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import assert from 'node:assert/strict'

import {
  applyHardRules,
  decide,
  validateClassification,
  parseModelAnswer,
  mailboxKindOf,
  isRoleSender,
} from '../lib/triage.mjs'
import { buildReport, reportName } from '../lib/report.mjs'
import { createStore } from '../lib/store.mjs'
import { snippetFromSource, resolveTrashMailbox, collectAttachments } from '../lib/mailbox.mjs'
import { accountsFromLogins } from '../lib/thunderbird.mjs'

let passed = 0
const failures = []

function check(name, fn) {
  try {
    fn()
    passed += 1
    process.stdout.write(`  ok   ${name}\n`)
  } catch (error) {
    failures.push({ name, error })
    process.stdout.write(`  FAIL ${name}: ${error.message}\n`)
  }
}

const SAFETY = {
  minAgeDays: 7,
  confidenceThreshold: 0.85,
  protectDomains: ['example.edu'],
  protectSenders: ['boss@example.com'],
}

const OLD = new Date(Date.now() - 30 * 86_400_000).toISOString()
const NEW = new Date(Date.now() - 1 * 86_400_000).toISOString()

function msg(overrides = {}) {
  return {
    uid: 1,
    subject: 'hello',
    fromName: 'Sender',
    fromAddress: 'someone@example.com',
    snippet: 'body text',
    date: OLD,
    internalDate: OLD,
    inReplyTo: '',
    attachments: [],
    hasAttachment: false,
    ...overrides,
  }
}

function cleanModel(category = '广告营销', confidence = 0.95) {
  return { ok: true, model: 'qwen2.5:7b', parsed: { category, confidence, summary: '促销邮件', risk_flags: [] }, reasons: [] }
}

process.stdout.write('\n[1] 硬保护规则\n')

check('验证码邮件被标记 contains_credential 且受保护', () => {
  const rules = applyHardRules(msg({ subject: '您的验证码是 123456' }), SAFETY)
  assert.equal(rules.protected, true)
  assert.ok(rules.flags.includes('contains_credential'))
})

check('英语 OTP 同样命中', () => {
  const rules = applyHardRules(msg({ subject: 'Your one-time passcode', snippet: 'code 9981' }), SAFETY)
  assert.ok(rules.flags.includes('contains_credential'))
})

check('白名单域名受保护', () => {
  const rules = applyHardRules(msg({ fromAddress: 'admin@student.example.edu' }), SAFETY)
  assert.ok(rules.flags.includes('user_whitelisted'))
  assert.equal(rules.protected, true)
})

check('白名单地址受保护', () => {
  const rules = applyHardRules(msg({ fromAddress: 'boss@example.com' }), SAFETY)
  assert.ok(rules.flags.includes('user_whitelisted'))
})

check('账单/发票受保护', () => {
  const rules = applyHardRules(msg({ subject: 'Invoice #9912 attached' }), SAFETY)
  assert.ok(rules.flags.includes('contains_invoice'))
})

check('回复线程受保护', () => {
  const rules = applyHardRules(msg({ inReplyTo: '<abc@x>' }), SAFETY)
  assert.ok(rules.flags.includes('thread_with_human'))
  assert.equal(rules.protected, true)
})

check('机构代发地址带 In-Reply-To 不算人类会话', () => {
  const rules = applyHardRules(msg({ fromAddress: 'io@example.com', inReplyTo: '<abc@x>' }), SAFETY)
  assert.ok(rules.flags.includes('bulk_thread'))
  assert.ok(!rules.flags.includes('thread_with_human'))
  assert.equal(rules.protected, false)
})

check('个人地址带 In-Reply-To 仍然保护', () => {
  const rules = applyHardRules(msg({ fromAddress: 'alice@example.com', inReplyTo: '<abc@x>' }), SAFETY)
  assert.ok(rules.flags.includes('thread_with_human'))
  assert.equal(rules.protected, true)
})

check('角色发件人识别', () => {
  for (const address of ['pentadbir_emel@example.edu', 'io@example.edu', 'pg-sac@other.example.edu', 'no-reply@x.com', 'penerbit@example.edu']) {
    assert.equal(isRoleSender(address), true, address)
  }
  for (const address of ['nurfatinamera@example.edu', 'alice@example.com', 'user@example.com']) {
    assert.equal(isRoleSender(address), false, address)
  }
})

check('已发送文件夹受保护', () => {
  const rules = applyHardRules(msg(), SAFETY, 'sent')
  assert.ok(rules.flags.includes('is_sent_or_draft'))
  assert.equal(rules.protected, true)
})

check('钓鱼关键词受保护', () => {
  const rules = applyHardRules(msg({ subject: '账户异常，请立即验证' }), SAFETY)
  assert.ok(rules.flags.includes('looks_phishing'))
})

check('干净广告邮件不被保护', () => {
  const rules = applyHardRules(msg({ subject: '本周优惠速递', snippet: '限时折扣，欢迎选购' }), SAFETY)
  assert.equal(rules.protected, false)
  assert.deepEqual(rules.flags.filter((flag) => flag === 'contains_credential'), [])
})

check('真实附件按文件名判定', () => {
  const rules = applyHardRules(msg({ attachments: [{ filename: 'report.zip', size: 10 }] }), SAFETY)
  assert.ok(rules.flags.includes('has_attachment'))
  assert.equal(rules.protected, true)
})

check('危险附件单独标记 risky_attachment', () => {
  const rules = applyHardRules(msg({ attachments: [{ filename: 'invoice.docm', size: 10 }] }), SAFETY)
  assert.ok(rules.flags.includes('risky_attachment'))
})

check('正文里的 .js 链接不算附件（避免误判）', () => {
  const rules = applyHardRules(msg({ subject: 'newsletter', snippet: '点击 https://track.example.com/pixel.js 查看' }), SAFETY)
  assert.ok(!rules.flags.includes('has_attachment'))
  assert.equal(rules.protected, false)
})

process.stdout.write('\n[2] 决策矩阵\n')

check('受保护 → 红桶', () => {
  const m = msg({ subject: '验证码 1111' })
  const rules = applyHardRules(m, SAFETY)
  const decision = decide(m, rules, cleanModel(), SAFETY)
  assert.equal(decision.bucket, 'red')
  assert.equal(decision.action, 'keep')
})

check('模型不可用 → 黄桶', () => {
  const m = msg({ subject: '本周优惠速递' })
  const rules = applyHardRules(m, SAFETY)
  const decision = decide(m, rules, { ok: false, reasons: ['call_failed(timeout)'] }, SAFETY)
  assert.equal(decision.bucket, 'yellow')
  assert.equal(decision.action, 'review_required')
})

check('高置信广告 + 足够旧 → 绿桶', () => {
  const m = msg({ subject: '本周优惠速递', snippet: '限时折扣' })
  const rules = applyHardRules(m, SAFETY)
  const decision = decide(m, rules, cleanModel('广告营销', 0.95), SAFETY)
  assert.equal(decision.bucket, 'green')
  assert.equal(decision.action, 'delete_candidate')
})

check('低置信 → 黄桶', () => {
  const m = msg({ subject: '本周优惠速递', snippet: '限时折扣' })
  const rules = applyHardRules(m, SAFETY)
  const decision = decide(m, rules, cleanModel('广告营销', 0.55), SAFETY)
  assert.equal(decision.bucket, 'yellow')
})

check('太新 → 黄桶', () => {
  const m = msg({ subject: '本周优惠速递', snippet: '限时折扣', date: NEW, internalDate: NEW })
  const rules = applyHardRules(m, SAFETY)
  const decision = decide(m, rules, cleanModel('广告营销', 0.99), SAFETY)
  assert.equal(decision.bucket, 'yellow')
  assert.ok(decision.reasons.some((reason) => reason.startsWith('too_recent')))
})

check('不可删类别 → 红桶', () => {
  const m = msg({ subject: '本周优惠速递', snippet: '限时折扣' })
  const rules = applyHardRules(m, SAFETY)
  const decision = decide(m, rules, cleanModel('个人重要', 0.99), SAFETY)
  assert.equal(decision.bucket, 'red')
})

check('模型给出的阻断风险标记 → 黄桶', () => {
  const m = msg({ subject: '本周优惠速递', snippet: '限时折扣' })
  const rules = applyHardRules(m, SAFETY)
  const model = cleanModel('广告营销', 0.99)
  model.parsed.risk_flags = ['has_attachment']
  const decision = decide(m, rules, model, SAFETY)
  assert.equal(decision.bucket, 'yellow')
})

check('external_sender 属于信息性标记，不阻断绿桶', () => {
  const m = msg({ subject: '本周优惠速递', snippet: '限时折扣' })
  const rules = applyHardRules(m, SAFETY)
  assert.ok(rules.flags.includes('external_sender'))
  const decision = decide(m, rules, cleanModel('广告营销', 0.95), SAFETY)
  assert.equal(decision.bucket, 'green')
})

process.stdout.write('\n[3] 模型结果校验\n')

check('schema 校验：类别不在枚举内', () => {
  const reasons = validateClassification('', { category: '垃圾', confidence: 0.9, summary: 'x' })
  assert.ok(reasons.some((reason) => reason.startsWith('category_not_in_enum')))
})

check('schema 校验：置信度非法', () => {
  const reasons = validateClassification('', { category: '广告营销', confidence: 'high', summary: 'x' })
  assert.ok(reasons.includes('confidence_invalid'))
})

check('schema 校验：缺 summary', () => {
  const reasons = validateClassification('', { category: '广告营销', confidence: 0.9 })
  assert.ok(reasons.includes('summary_missing'))
})

check('JSON 解析：允许代码围栏', () => {
  const { parsed, reasons } = parseModelAnswer('```json\n{"category":"广告营销"}\n```')
  assert.equal(reasons.length, 0)
  assert.equal(parsed.category, '广告营销')
})

check('JSON 解析：坏 JSON 报错', () => {
  const { reasons } = parseModelAnswer('这不是 JSON')
  assert.ok(reasons.includes('json_parse'))
})

process.stdout.write('\n[4] 正文片段解码\n')

check('quoted-printable 解码', () => {
  const source = 'Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHello=20world=0Asecond line'
  const snippet = snippetFromSource(source)
  assert.ok(snippet.includes('Hello world'))
})

check('HTML 去标签', () => {
  const source = 'Content-Type: text/html\r\n\r\n<html><body><p>优惠</p><script>bad()</script><p>活动</p></body></html>'
  const snippet = snippetFromSource(source)
  assert.ok(snippet.includes('优惠'))
  assert.ok(!snippet.includes('bad()'))
})

check('base64 解码', () => {
  const body = Buffer.from('这是一个 base64 正文', 'utf8').toString('base64')
  const source = `Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n${body}`
  const snippet = snippetFromSource(source)
  assert.ok(snippet.includes('base64'))
})

check('超长邮件头未结束时不臆造正文（交给二次抓取）', () => {
  const headerBlock = 'Received: from a.example.com by b.example.com with HTTPS;\r\nARC-Seal: i 1; a rsa-sha256;\r\n'.repeat(40)
  const snippet = snippetFromSource(headerBlock)
  assert.equal(snippet, '')
})

check('multipart 里优先取 text/plain 段落', () => {
  const source = [
    'Content-Type: multipart/alternative; boundary="BOUND"',
    '',
    '--BOUND',
    'Content-Type: text/plain; charset=utf-8',
    '',
    '纯文本正文内容',
    '--BOUND',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p>HTML 正文</p>',
    '--BOUND--',
  ].join('\r\n')
  const snippet = snippetFromSource(source)
  assert.ok(snippet.includes('纯文本正文内容'))
  assert.ok(!snippet.includes('HTML 正文'))
})

process.stdout.write('\n[5] 文件夹与附件\n')

check('垃圾文件夹识别', () => {
  assert.equal(mailboxKindOf({ path: 'INBOX' }, 'INBOX'), 'inbox')
  assert.equal(mailboxKindOf({ path: 'Sent', specialUse: '\\Sent', flags: [] }, 'Sent'), 'sent')
  assert.equal(mailboxKindOf({ path: 'Drafts', specialUse: '\\Drafts', flags: [] }, 'Drafts'), 'drafts')
  assert.equal(mailboxKindOf({ path: 'Junk', specialUse: '\\Junk', flags: [] }, 'Junk'), 'junk')
})

check('回收站解析：特殊属性优先', () => {
  const boxes = [
    { path: 'INBOX', name: 'INBOX', specialUse: null, flags: [] },
    { path: 'Trash', name: 'Trash', specialUse: '\\Trash', flags: [] },
  ]
  assert.equal(resolveTrashMailbox(boxes), 'Trash')
})

check('回收站解析：没有就拒绝猜测', () => {
  const boxes = [{ path: 'INBOX', name: 'INBOX', specialUse: null, flags: [] }]
  assert.equal(resolveTrashMailbox(boxes), null)
})

check('附件结构解析', () => {
  const structure = {
    childNodes: [
      { part: '1', type: 'text/plain' },
      { part: '2', disposition: 'attachment', dispositionParameters: { filename: 'invoice.pdf' }, size: 1024 },
    ],
  }
  const attachments = collectAttachments(structure)
  assert.equal(attachments.length, 1)
  assert.equal(attachments[0].filename, 'invoice.pdf')
})

process.stdout.write('\n[6] 本地状态\n')

const dir = mkdtempSync(join(tmpdir(), 'mail-triage-test-'))
try {
  check('配置读写', () => {
    const store = createStore(dir)
    store.writeConfig({ accounts: [{ id: 'a@b.c' }] })
    assert.equal(store.readConfig().accounts.length, 1)
  })

  check('游标读写', () => {
    const store = createStore(dir)
    store.setCursor('a@b.c', 'INBOX', { uidNext: 42, uidValidity: 7 })
    assert.equal(store.getCursor('a@b.c', 'INBOX').uidNext, 42)
  })

  check('标签与判定追加', () => {
    const store = createStore(dir)
    store.appendLabels([{ key: 'k1', bucket: 'green' }])
    store.appendVerdicts([{ key: 'k1', action: 'delete_candidate' }])
    assert.equal(store.readLabels().length, 1)
    assert.equal(store.readVerdicts().length, 1)
  })

  check('manifest 写入与读取', () => {
    const store = createStore(dir)
    store.writeManifest({ id: 'm1', items: [{ uid: 1 }], hash: 'h' })
    assert.equal(store.readManifest('m1').items.length, 1)
    assert.equal(store.readManifest('../etc/passwd'), null)
  })

  check('审计日志', () => {
    const store = createStore(dir)
    store.appendAudit({ ok: true, action: 'move_to_trash' })
    store.appendAudit({ ok: false })
    assert.equal(store.readAudit(10).length, 2)
    assert.equal(store.readAudit(1).length, 1)
  })

  check('报告落盘', () => {
    const store = createStore(dir)
    const path = store.writeReport('t.md', '# hi\n')
    assert.ok(path.endsWith('t.md'))
    assert.deepEqual(store.listReports(), ['t.md'])
  })
} finally {
  rmSync(dir, { recursive: true, force: true })
}

process.stdout.write('\n[7] 报告生成\n')

check('报告包含三桶与免责声明', () => {
  const rows = [
    { key: 'a', account: 'x@y.z', mailbox: 'INBOX', date: OLD, fromAddress: 'a@b.c', subject: 's1', category: '广告营销', bucket: 'green', action: 'delete_candidate', confidence: 0.9, reasons: [], flags: [] },
    { key: 'b', account: 'x@y.z', mailbox: 'INBOX', date: OLD, fromAddress: 'a@b.c', subject: 's2', category: '存疑未知', bucket: 'yellow', action: 'review_required', confidence: 0, reasons: ['low_confidence(0.20<0.85)'], flags: [] },
    { key: 'c', account: 'x@y.z', mailbox: 'INBOX', date: OLD, fromAddress: 'a@b.c', subject: 's3', category: '验证码/一次性通知', bucket: 'red', action: 'keep', confidence: 1, reasons: ['contains_credential'], flags: ['contains_credential'] },
  ]
  const buckets = { green: [rows[0]], yellow: [rows[1]], red: [rows[2]] }
  const text = buildReport({ rows, buckets, accounts: [{ address: 'x@y.z' }], scannedMailboxes: ['INBOX'], modelName: 'test', notes: [] })
  assert.ok(text.includes('# 邮件分诊报告'))
  assert.ok(text.includes('本轮没有对邮箱做任何修改'))
  assert.ok(text.includes('绿桶'))
  assert.ok(text.includes('黄桶'))
  assert.ok(text.includes('红桶'))
})

check('报告文件名稳定', () => {
  assert.match(reportName(new Date(2026, 0, 2, 3, 4)), /^triage-20260102-0304\.md$/)
})

process.stdout.write('\n[8] 雷鸟账号归并\n')

check('M365 OAuth 账号识别', () => {
  const accounts = accountsFromLogins([
    { hostname: 'imap://outlook.office365.com', username: 'stu@student.example.edu', password: '' },
    { hostname: 'oauth://login.microsoftonline.com', username: 'stu@student.example.edu', password: 'refresh-token-1', httpRealm: 'IMAP.AccessAsUser.All' },
  ])
  assert.equal(accounts.length, 1)
  assert.equal(accounts[0].provider, 'm365')
  assert.equal(accounts[0].auth.kind, 'xoauth2')
  assert.equal(accounts[0].auth.refreshToken, 'refresh-token-1')
})

check('163 授权码账号识别', () => {
  const accounts = accountsFromLogins([
    { hostname: 'imap://imap.163.com', username: 'a@163.com', password: 'abcdefghijklmnop' },
  ])
  assert.equal(accounts.length, 1)
  assert.equal(accounts[0].provider, '163')
  assert.equal(accounts[0].auth.kind, 'password')
  assert.equal(accounts[0].imap.sendId, true)
})

check('Gmail 无 16 位授权码时标记 needsSecret', () => {
  const accounts = accountsFromLogins([
    { hostname: 'imap://imap.gmail.com', username: 'a@gmail.com', password: 'ninechars' },
  ])
  assert.equal(accounts.length, 1)
  assert.equal(accounts[0].needsSecret, true)
})

check('Gmail 有 16 位授权码时直接可用', () => {
  const accounts = accountsFromLogins([
    { hostname: 'imap://imap.gmail.com', username: 'a@gmail.com', password: 'abcdefghijklmnop' },
  ])
  assert.equal(accounts[0].auth.kind, 'password')
  assert.equal(accounts[0].needsSecret, false)
})

check('无用户名的记录被忽略', () => {
  const accounts = accountsFromLogins([{ hostname: 'imap://imap.163.com', username: '', password: 'x' }])
  assert.equal(accounts.length, 0)
})

process.stdout.write(`\n${passed} passed, ${failures.length} failed\n`)
if (failures.length > 0) {
  process.exitCode = 1
}



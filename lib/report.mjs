/**
 * Markdown triage report. The report is the thing a user reads before approving
 * anything, so it always states plainly that nothing has been changed yet.
 */

function pad(value) {
  return String(value).padStart(2, '0')
}

export function reportName(date = new Date()) {
  return `triage-${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}.md`
}

function fmtDate(iso) {
  if (!iso) return '未知'
  try {
    const d = new Date(iso)
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
  } catch {
    return String(iso)
  }
}

function short(text, max = 46) {
  const value = String(text ?? '').replace(/\s+/g, ' ').trim()
  return value.length > max ? `${value.slice(0, max - 1)}…` : value
}

function table(rows) {
  return rows.join('\n')
}

/**
 * @param {object} input
 * @param {object[]} input.rows triage rows
 * @param {{green: object[], yellow: object[], red: object[]}} input.buckets
 * @param {object[]} input.accounts accounts touched in this run
 * @param {string[]} input.scannedMailboxes
 * @param {string} input.modelName
 * @param {string} [input.notes]
 */
export function buildReport({ rows, buckets, accounts, scannedMailboxes, modelName, notes = [] }) {
  const now = new Date()
  const lines = []
  lines.push('# 邮件分诊报告')
  lines.push('')
  lines.push(`- 生成时间：${fmtDate(now.toISOString())}`)
  lines.push(`- 扫描账号：${accounts.map((a) => a.address).join('、') || '(无)'}`)
  lines.push(`- 扫描文件夹：${scannedMailboxes.join('、') || 'INBOX'}`)
  lines.push(`- 分类模型：${modelName}`)
  lines.push(`- 本轮新分诊：${rows.length} 封`)
  lines.push('')
  lines.push('> **本轮没有对邮箱做任何修改。** 删除是另一步，需要你明确批准后才会执行，而且只会把邮件移动到回收站。')
  lines.push('')

  lines.push('## 三桶统计')
  lines.push('')
  lines.push('| 桶 | 数量 | 含义 |')
  lines.push('| --- | --- | --- |')
  lines.push(`| 绿桶（可清理候选） | ${buckets.green.length} | 高置信且未命中任何保护规则 |`)
  lines.push(`| 黄桶（待复核） | ${buckets.yellow.length} | 低置信、存疑或模型不可用 |`)
  lines.push(`| 红桶（永不自动删除） | ${buckets.red.length} | 硬保护或高风险 |`)
  lines.push('')

  const byCategory = new Map()
  for (const row of rows) byCategory.set(row.category, (byCategory.get(row.category) ?? 0) + 1)
  if (byCategory.size > 0) {
    lines.push('## 类别分布')
    lines.push('')
    const sorted = [...byCategory.entries()].sort((a, b) => b[1] - a[1])
    lines.push(table(sorted.map(([category, count]) => `- ${category}：${count}`)))
    lines.push('')
  }

  if (buckets.green.length > 0) {
    lines.push('## 绿桶：可清理候选')
    lines.push('')
    lines.push(table([
      '| # | 账号 | 文件夹 | 日期 | 发件人 | 主题 | 类别 | 置信度 |',
      '| --- | --- | --- | --- | --- | --- | --- | --- |',
      ...buckets.green.slice(0, 60).map((row, index) =>
        `| ${index + 1} | ${row.account} | ${row.mailbox} | ${fmtDate(row.date)} | ${short(row.fromAddress, 28)} | ${short(row.subject)} | ${row.category} | ${Number(row.confidence).toFixed(2)} |`),
    ]))
    if (buckets.green.length > 60) lines.push('', `（还有 ${buckets.green.length - 60} 封未列出）`)
    lines.push('')
  }

  if (buckets.yellow.length > 0) {
    lines.push('## 黄桶：需要复核')
    lines.push('')
    lines.push(table([
      '| # | 账号 | 日期 | 发件人 | 主题 | 类别猜测 | 原因 |',
      '| --- | --- | --- | --- | --- | --- | --- |',
      ...buckets.yellow.slice(0, 40).map((row, index) =>
        `| ${index + 1} | ${row.account} | ${fmtDate(row.date)} | ${short(row.fromAddress, 24)} | ${short(row.subject, 34)} | ${row.category} | ${short(row.reasons.join(', '), 40)} |`),
    ]))
    if (buckets.yellow.length > 40) lines.push('', `（还有 ${buckets.yellow.length - 40} 封未列出）`)
    lines.push('')
  }

  if (buckets.red.length > 0) {
    lines.push('## 红桶：受保护邮件')
    lines.push('')
    const reasonCounts = new Map()
    for (const row of buckets.red) {
      for (const reason of row.reasons.length > 0 ? row.reasons : ['protected']) {
        reasonCounts.set(reason, (reasonCounts.get(reason) ?? 0) + 1)
      }
    }
    const sorted = [...reasonCounts.entries()].sort((a, b) => b[1] - a[1])
    lines.push(table(sorted.map(([reason, count]) => `- ${reason}：${count} 封`)))
    lines.push('')
  }

  if (notes.length > 0) {
    lines.push('## 说明与限制')
    lines.push('')
    for (const note of notes) lines.push(`- ${note}`)
    lines.push('')
  }

  lines.push('---')
  lines.push('')
  lines.push('下一步：确认无误后运行 `mail_triage_plan` 生成删除清单与 manifest，再运行 `mail_triage_apply` 执行（会再次要求你批准）。')
  lines.push('')
  return lines.join('\n')
}

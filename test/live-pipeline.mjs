// Dev harness: exercises the real pipeline outside the Host (read-only).
// Not shipped with the package.
import { importFromThunderbird } from '../lib/thunderbird.mjs'
import { refreshGoogleToken, refreshMicrosoftToken } from '../lib/oauth.mjs'
import { fetchMessages, listMailboxes, resolveTrashMailbox, withClient } from '../lib/mailbox.mjs'
import { applyHardRules, classifyWithLocalModel, decide, messageKey } from '../lib/triage.mjs'

const SAFETY = { minAgeDays: 7, confidenceThreshold: 0.85, protectDomains: ['usm.my', 'uow.edu.my'], protectSenders: [] }

const wanted = (process.env.ACCOUNTS ?? '').split(',').map((s) => s.trim()).filter(Boolean)
const results = importFromThunderbird({})
const accounts = results.flatMap((r) => r.accounts ?? [])
const targets = wanted.length > 0 ? accounts.filter((a) => wanted.some((w) => a.address.includes(w))) : accounts

console.log(`发现 ${accounts.length} 个账号，本次验证 ${targets.length} 个\n`)

for (const account of targets) {
  const line = `${account.address} (${account.provider})`
  try {
    let secrets
    if (account.auth?.kind === 'xoauth2') {
      const refreshed =
        account.auth.oauthProvider === 'google'
          ? await refreshGoogleToken({ refreshToken: account.auth.refreshToken, clientId: account.auth.clientId, clientSecret: account.auth.clientSecret })
          : await refreshMicrosoftToken({ refreshToken: account.auth.refreshToken, clientId: account.auth.clientId, tenant: account.auth.tenant, scope: account.auth.scope })
      secrets = { accessToken: refreshed.accessToken }
    } else {
      secrets = { password: account.auth.password }
    }

    const info = await withClient(account, secrets, async (client) => {
      const boxes = await listMailboxes(client)
      const trash = resolveTrashMailbox(boxes)
      const fetched = await fetchMessages(client, { mailbox: 'INBOX', lookbackDays: 7, max: 6 })
      return { boxes, trash, fetched }
    })
    console.log(`${line}\n  认证 OK · 文件夹 ${info.boxes.length} · 回收站 ${info.trash ?? '(未找到!)'} · 近 7 天取到 ${info.fetched.messages.length} 封`)

    const prepared = []
    for (const message of info.fetched.messages) {
      const rules = applyHardRules(message, SAFETY, 'inbox')
      prepared.push({ message, rules, key: messageKey(account.id, 'INBOX', info.fetched.cursor.uidValidity, message.uid) })
    }
    const toClassify = prepared.filter((e) => !e.rules.protected).map((e) => ({
      key: e.key,
      subject: e.message.subject,
      fromName: e.message.fromName,
      fromAddress: e.message.fromAddress,
      date: e.message.date,
      snippet: e.message.snippet,
    }))
    const classified = process.env.SKIP_MODEL === '1' || toClassify.length === 0
      ? new Map()
      : await classifyWithLocalModel(toClassify, { baseURL: 'http://127.0.0.1:11434', model: 'qwen2.5:7b', concurrency: 1, timeoutMs: 120000 })

    for (const entry of prepared) {
      const decision = decide(entry.message, entry.rules, classified.get(entry.key), SAFETY)
      console.log(`    [${decision.bucket}] ${decision.category} conf=${Number(decision.confidence).toFixed(2)} | ${(entry.message.fromAddress || '?').slice(0, 32)} | ${String(entry.message.subject).slice(0, 40)} | ${decision.reasons.join(',') || '-'}`)
    }
    console.log('')
  } catch (error) {
    console.log(`${line}\n  失败：${String(error?.message ?? error).slice(0, 220)}\n`)
  }
}


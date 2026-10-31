/**
 * The six agent-facing tools.
 *
 * Read and write are separate tools and separate code paths:
 *   mail_triage_scan   read-only
 *   mail_triage_plan   read-only (writes a manifest file, touches no mailbox)
 *   mail_triage_apply  the only tool that changes a mailbox, and only after an
 *                      explicit approval card, and only by moving to Trash
 */
import { createHash, randomUUID } from 'node:crypto'
import { join } from 'node:path'
import { existsSync } from 'node:fs'
import { importFromThunderbird } from './thunderbird.mjs'
import { resolveAccessToken } from './oauth.mjs'
import { fetchMessages, listMailboxes, moveMessagesToTrash, resolveTrashMailbox, withClient } from './mailbox.mjs'
import { applyHardRules, BLOCKING_FLAGS, bucketize, classifyWithLocalModel, decide, DELETABLE, mailboxKindOf, messageKey, NEVER_DELETE } from './triage.mjs'
import { buildReport, reportName } from './report.mjs'
import { createStore } from './store.mjs'

const CREDENTIAL_PREFIX = 'mail-triage/'

function json(value) {
  return [{ type: 'text', text: JSON.stringify(value, null, 2) }]
}

function output(schema) {
  return { schema, render: (_args, value) => json(value) }
}

function text(value) {
  return [{ type: 'text', text: String(value) }]
}

async function workspaceRoot(deps, exec) {
  const service = deps.ctx.get?.('workingDirectory') ?? deps.ctx.workingDirectory
  try {
    const cwd = await service?.ensure?.(exec.agent, exec.signal)
    if (typeof cwd === 'string' && cwd.length > 0) return cwd
  } catch {
    /* treat as unavailable */
  }
  throw new Error('解析不到会话工作区，邮件分诊的状态目录无处安放。请先设置工作目录。')
}

async function storeFor(deps, exec) {
  const root = await workspaceRoot(deps, exec)
  return createStore(join(root, deps.config.stateDir))
}

/* ---------------------------------------------------------------- secrets */

function credentialKey(accountId) {
  return `${CREDENTIAL_PREFIX}${accountId}`
}

function secretsFallbackPath(store) {
  return join(store.paths.root, 'secrets.json')
}

function readFallbackSecrets(store) {
  return store.readJson('secrets.json', {})
}

function writeFallbackSecrets(store, value) {
  return store.writeJson('secrets.json', value)
}

async function saveAccountRecord(deps, store, account, payload) {
  const credentials = deps.ctx.get?.('credentials') ?? deps.ctx.credentials
  if (credentials?.modifyRecord) {
    await credentials.modifyRecord(credentialKey(account.id), async () => payload)
    return 'credentials'
  }
  const secrets = readFallbackSecrets(store)
  secrets[account.id] = payload
  writeFallbackSecrets(store, secrets)
  return 'workspace-file'
}

async function readAccountRecord(deps, store, account) {
  const credentials = deps.ctx.get?.('credentials') ?? deps.ctx.credentials
  if (credentials?.readRecord) {
    const record = await credentials.readRecord(credentialKey(account.id))
    if (record) return record
    return undefined
  }
  const secrets = readFallbackSecrets(store)
  return secrets[account.id]
}

async function deleteAccountRecord(deps, store, account) {
  const credentials = deps.ctx.get?.('credentials') ?? deps.ctx.credentials
  if (credentials?.deleteRecord) {
    await credentials.deleteRecord(credentialKey(account.id))
    return
  }
  const secrets = readFallbackSecrets(store)
  delete secrets[account.id]
  writeFallbackSecrets(store, secrets)
}

/** Build the IMAP secrets for one account, refreshing OAuth tokens as needed. */
async function resolveSecrets(deps, store, account, signal) {
  const record = await readAccountRecord(deps, store, account)
  if (!record) {
    throw new Error(`${account.address} 还没有可用凭据，请先运行 mail_triage_accounts 的 import_thunderbird 或 set_secret`)
  }
  if (account.authKind === 'xoauth2') {
    if (record.kind !== 'grant' || !record.payload?.refreshToken) {
      throw new Error(`${account.address} 缺少 OAuth 授权，请在雷鸟里重新登录该账号后重新导入`)
    }
    const accessToken = await resolveAccessToken(
      { id: account.id, auth: record.payload },
      {
        cache: deps.tokenCache,
        signal,
        persistRefreshToken: async (target, token) => {
          await saveAccountRecord(deps, store, target, {
            kind: 'grant',
            payload: { ...record.payload, refreshToken: token },
          })
        },
      },
    )
    return { accessToken }
  }
  if (record.kind !== 'api-key' || !record.key) {
    throw new Error(`${account.address} 的密码记录不可用，请用 set_secret 重新设置`)
  }
  return { password: record.key }
}

/* --------------------------------------------------------------- approval */

async function askUser(deps, exec, { header, question, options }) {
  const userQuestions = deps.ctx.get?.('userQuestions') ?? deps.ctx.userQuestions
  if (typeof userQuestions?.ask !== 'function') return null
  const answer = await userQuestions.ask({
    questions: [{ id: 'mail-triage-approval', header, question, options }],
    ...(exec.agent !== undefined ? { agent: exec.agent } : {}),
    ...(exec.signal !== undefined ? { signal: exec.signal } : {}),
  })
  return answer?.answers?.[0]?.selected?.[0] ?? answer?.answers?.[0]?.custom ?? ''
}

/* ---------------------------------------------------------------- helpers */

function selectedAccounts(deps, store, filter) {
  const accounts = store.readConfig({ accounts: [] }).accounts ?? []
  if (!filter || filter.length === 0) return accounts
  const wanted = new Set(filter.map((value) => String(value).toLowerCase()))
  return accounts.filter((account) => wanted.has(account.id) || wanted.has(account.address.toLowerCase()))
}

function modelName(deps, requested) {
  if (requested === false) return 'rules-only'
  if (deps.config.localModel?.enabled === false) return 'rules-only'
  return `${deps.config.localModel?.model ?? 'qwen2.5:7b'} (local)`
}

function newestVerdicts(store) {
  const map = new Map()
  for (const verdict of store.readVerdicts()) map.set(verdict.key, verdict)
  return map
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

/** Drop undefined members: the credential store rejects payloads JSON cannot represent. */
function compact(value) {
  const out = {}
  for (const [key, entry] of Object.entries(value ?? {})) {
    if (entry !== undefined && entry !== null && entry !== '') out[key] = entry
  }
  return out
}

/* ------------------------------------------------------------------ tools */

export function createTools(deps) {
  const accountsTool = {
    name: 'mail_triage_accounts',
    description:
      'Manage the mailbox accounts this plugin can triage. Actions: list (show configured accounts), import_thunderbird (read account credentials from the local Thunderbird profile and store them in the DSH credential store), set_secret (store one password/app-password), test (connect and report mailboxes plus the Trash folder), remove. Secrets are never returned.',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['list', 'import_thunderbird', 'set_secret', 'test', 'remove'] },
        profiles: { type: 'array', items: { type: 'string' }, description: 'Absolute Thunderbird profile paths (default: auto-discover).' },
        primaryPassword: { type: 'string', description: 'Thunderbird primary password, only when one is set.' },
        address: { type: 'string', description: 'Account email address, for set_secret/test/remove.' },
        secret: { type: 'string', description: 'Password or app password, for set_secret.' },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: output({
      type: 'object',
      properties: {
        ok: { type: 'boolean' },
        action: { type: 'string' },
        accounts: { type: 'array', items: { type: 'object' } },
        notes: { type: 'array', items: { type: 'string' } },
      },
      required: ['ok', 'action'],
    }),
    async execute(args, exec) {
      const store = await storeFor(deps, exec)
      const notes = []
      const action = String(args.action)

      if (action === 'list') {
        const accounts = store.readConfig({ accounts: [] }).accounts ?? []
        const rows = []
        for (const account of accounts) {
          const record = await readAccountRecord(deps, store, account)
          rows.push({
            id: account.id,
            address: account.address,
            provider: account.provider,
            imap: `${account.imap.host}:${account.imap.port}`,
            authKind: account.authKind,
            hasSecret: Boolean(record),
            needsSecret: account.needsSecret ?? false,
            notes: account.notes ?? [],
            lastTest: account.lastTest ?? null,
          })
        }
        return { ok: true, action, accounts: rows, notes: ['凭据只在本机：密码/令牌存于 DSH 凭据库，账号元数据存于工作区 ' + deps.config.stateDir] }
      }

      if (action === 'import_thunderbird') {
        const approval = await askUser(deps, exec, {
          header: '读取雷鸟凭据',
          question: [
            '将读取本机 Thunderbird 的凭据库（key4.db + logins.json）并解密其中已登录账号的密码与 OAuth 令牌。',
            '解密只在本机进行，凭据写入本机 DSH 凭据库，不写入工作区明文，也不会发送到任何服务器。',
            `配置的附加路径：${(deps.config.thunderbird?.profiles ?? []).join(', ') || '(自动发现)'}`,
          ].join('\n'),
          options: [
            { label: '允许导入', description: '只读取雷鸟已保存的账号凭据。' },
            { label: '取消', description: '不读取任何凭据。' },
          ],
        })
        if (approval === null) {
          return { ok: false, action, accounts: [], notes: ['本机没有可用的提问服务，无法取得你的批准，因此没有读取凭据。'] }
        }
        if (approval !== '允许导入') {
          return { ok: false, action, accounts: [], notes: ['你取消了凭据导入，没有读取任何数据。'] }
        }

        const results = importFromThunderbird({
          profiles: Array.isArray(args.profiles) ? args.profiles : deps.config.thunderbird?.profiles ?? [],
          primaryPassword: String(args.primaryPassword ?? ''),
        })
        const config = store.readConfig({ accounts: [] })
        const existing = new Map((config.accounts ?? []).map((account) => [account.id, account]))
        const imported = []
        for (const profileResult of results) {
          if (profileResult.error) {
            notes.push(`配置目录 ${profileResult.profile} 读取失败：${profileResult.error}`)
            continue
          }
          for (const account of profileResult.accounts) {
            const stored = { ...account }
            delete stored.auth
            stored.importedFrom = profileResult.profile
            stored.importedAt = new Date().toISOString()
            try {
              if (account.auth) {
                const payload =
                  account.auth.kind === 'xoauth2'
                    ? {
                        kind: 'grant',
                        payload: compact({
                          oauthProvider: account.auth.oauthProvider,
                          refreshToken: account.auth.refreshToken,
                          clientId: account.auth.clientId,
                          clientSecret: account.auth.clientSecret,
                          tenant: account.auth.tenant,
                          scope: account.auth.scope,
                        }),
                      }
                    : { kind: 'api-key', key: account.auth.password }
                const where = await saveAccountRecord(deps, store, stored, payload)
                if (where === 'workspace-file') notes.push('凭据服务不可用，密码/令牌暂存在工作区 secrets.json 中')
                stored.needsSecret = false
              }
            } catch (error) {
              stored.needsSecret = true
              stored.notes = [...(stored.notes ?? []), `凭据写入失败：${String(error?.message ?? error).slice(0, 120)}`]
              notes.push(`${stored.address}：凭据写入失败，需要手动 set_secret`)
            }
            existing.set(stored.id, stored)
            imported.push({ id: stored.id, address: stored.address, authKind: stored.authKind ?? account.auth?.kind, needsSecret: stored.needsSecret ?? false, notes: stored.notes ?? [] })
          }
        }
        config.accounts = [...existing.values()]
        store.writeConfig(config)
        return {
          ok: imported.length > 0,
          action,
          accounts: imported,
          notes: [...notes, `从 ${results.length} 个雷鸟配置目录导入 ${imported.length} 个账号`],
        }
      }

      if (action === 'set_secret') {
        const address = String(args.address ?? '').toLowerCase()
        const secret = String(args.secret ?? '')
        if (!address || !secret) throw new Error('set_secret 需要 address 与 secret')
        const config = store.readConfig({ accounts: [] })
        const account = (config.accounts ?? []).find((entry) => entry.address.toLowerCase() === address || entry.id === address)
        if (!account) throw new Error(`没有这个账号：${args.address}`)
        account.authKind = 'password'
        account.needsSecret = false
        account.notes = (account.notes ?? []).filter((note) => !/需要.*密码/.test(note))
        await saveAccountRecord(deps, store, account, { kind: 'api-key', key: secret })
        store.writeConfig(config)
        return { ok: true, action, accounts: [{ id: account.id, address: account.address, authKind: 'password', hasSecret: true }], notes: [] }
      }

      if (action === 'test') {
        const targets = selectedAccounts(deps, store, args.address ? [args.address] : undefined)
        if (targets.length === 0) throw new Error('没有可测试的账号')
        const rows = []
        for (const account of targets) {
          try {
            const secrets = await resolveSecrets(deps, store, account, exec.signal)
            const result = await withClient(account, secrets, async (client) => {
              const boxes = await listMailboxes(client)
              return {
                mailboxes: boxes.length,
                trash: resolveTrashMailbox(boxes),
                hasInbox: boxes.some((box) => box.path.toUpperCase() === 'INBOX'),
                special: boxes.filter((box) => box.specialUse).map((box) => `${box.path}${box.specialUse}`),
              }
            })
            account.lastTest = { at: new Date().toISOString(), ok: true }
            rows.push({ address: account.address, ok: true, ...result })
          } catch (error) {
            account.lastTest = { at: new Date().toISOString(), ok: false, error: String(error?.message ?? error).slice(0, 200) }
            rows.push({ address: account.address, ok: false, error: String(error?.message ?? error).slice(0, 300) })
          }
        }
        store.writeConfig({ ...store.readConfig({ accounts: [] }), accounts: store.readConfig({ accounts: [] }).accounts.map((entry) => targets.find((t) => t.id === entry.id) ?? entry) })
        return { ok: rows.every((row) => row.ok), action, accounts: rows, notes: [] }
      }

      if (action === 'remove') {
        const address = String(args.address ?? '').toLowerCase()
        const config = store.readConfig({ accounts: [] })
        const account = (config.accounts ?? []).find((entry) => entry.address.toLowerCase() === address || entry.id === address)
        if (!account) throw new Error(`没有这个账号：${args.address}`)
        await deleteAccountRecord(deps, store, account)
        config.accounts = (config.accounts ?? []).filter((entry) => entry.id !== account.id)
        store.writeConfig(config)
        return { ok: true, action, accounts: [{ id: account.id, address: account.address, removed: true }], notes: [] }
      }

      throw new Error(`未知 action：${action}`)
    },
  }

  const scanTool = {
    name: 'mail_triage_scan',
    description:
      'Read-only incremental triage. Fetches new messages, applies the hard-protection rule layer, optionally classifies the rest with a local Ollama model, writes a Chinese triage report plus a local label list, and returns the yellow bucket so the session model can review it. This tool never changes a mailbox.',
    parameters: {
      type: 'object',
      properties: {
        accounts: { type: 'array', items: { type: 'string' }, description: 'Email addresses or account ids; omit for all configured accounts.' },
        mailboxes: { type: 'array', items: { type: 'string' }, description: 'Mailbox paths; default INBOX.' },
        lookbackDays: { type: 'integer', description: 'How far back the first scan goes (default from config, 30).' },
        maxPerRun: { type: 'integer', description: 'Cap on messages fetched per mailbox (default 200).' },
        useLocalModel: { type: 'boolean', description: 'Set false to skip the local model and send everything unprotected to review.' },
        resetCursor: { type: 'boolean', description: 'Ignore the stored cursor and rescan the lookback window.' },
      },
      additionalProperties: false,
    },
    output: output({
      type: 'object',
      properties: {
        ok: { type: 'boolean' },
        scanned: { type: 'integer' },
        buckets: { type: 'object' },
        reportPath: { type: 'string' },
        reviewBatch: { type: 'array', items: { type: 'object' } },
        accounts: { type: 'array', items: { type: 'object' } },
        notes: { type: 'array', items: { type: 'string' } },
      },
      required: ['ok', 'scanned', 'buckets'],
    }),
    async execute(args, exec) {
      const store = await storeFor(deps, exec)
      const accounts = selectedAccounts(deps, store, args.accounts)
      if (accounts.length === 0) {
        throw new Error('还没有配置任何账号。先运行 mail_triage_accounts 的 import_thunderbird。')
      }
      const scanCfg = deps.config.scan ?? {}
      const mailboxes = args.mailboxes && args.mailboxes.length > 0 ? args.mailboxes : scanCfg.mailboxes ?? ['INBOX']
      const lookbackDays = Number(args.lookbackDays ?? scanCfg.lookbackDays ?? 30)
      const maxPerRun = Number(args.maxPerRun ?? scanCfg.maxPerRun ?? 200)
      const safety = { ...(deps.config.safety ?? {}) }
      const useModel = args.useLocalModel !== false && deps.config.localModel?.enabled !== false

      const rows = []
      const notes = []
      const accountReport = []

      for (const account of accounts) {
        let secrets
        try {
          secrets = await resolveSecrets(deps, store, account, exec.signal)
        } catch (error) {
          notes.push(`${account.address}：${String(error?.message ?? error)}`)
          accountReport.push({ address: account.address, ok: false, error: String(error?.message ?? error).slice(0, 200) })
          continue
        }
        try {
          const summary = await withClient(account, secrets, async (client) => {
            const boxes = await listMailboxes(client)
            const result = { address: account.address, mailboxes: [], ok: true }
            for (const mailboxPath of mailboxes) {
              const box = boxes.find((entry) => entry.path === mailboxPath) ?? { path: mailboxPath, name: mailboxPath, flags: [], specialUse: null }
              const kind = mailboxKindOf(box, mailboxPath)
              const cursor = args.resetCursor ? undefined : store.getCursor(account.id, mailboxPath)
              const fetched = await fetchMessages(client, {
                mailbox: mailboxPath,
                sinceUid: cursor?.uidNext,
                lookbackDays,
                max: maxPerRun,
              })
              const prepared = []
              for (const message of fetched.messages) {
                const rules = applyHardRules(message, safety, kind)
                prepared.push({ message, rules, key: messageKey(account.id, mailboxPath, fetched.cursor.uidValidity, message.uid), mailboxPath, kind })
              }

              const toClassify = prepared.filter((entry) => !entry.rules.protected).map((entry) => ({
                key: entry.key,
                subject: entry.message.subject,
                fromName: entry.message.fromName,
                fromAddress: entry.message.fromAddress,
                date: entry.message.date ?? entry.message.internalDate,
                snippet: entry.message.snippet,
              }))
              const classifications = useModel && toClassify.length > 0
                ? await classifyWithLocalModel(toClassify, { ...deps.config.localModel, signal: exec.signal })
                : new Map()

              for (const entry of prepared) {
                const modelResult = classifications.get(entry.key)
                const decision = decide(entry.message, entry.rules, modelResult, safety)
                rows.push({
                  key: entry.key,
                  account: account.address,
                  mailbox: mailboxPath,
                  uidValidity: fetched.cursor.uidValidity,
                  uid: entry.message.uid,
                  date: entry.message.internalDate ?? entry.message.date,
                  fromAddress: entry.message.fromAddress,
                  fromName: entry.message.fromName,
                  subject: entry.message.subject,
                  snippet: (entry.message.snippet ?? '').slice(0, 200),
                  attachments: entry.message.attachments ?? [],
                  category: decision.category,
                  bucket: decision.bucket,
                  action: decision.action,
                  confidence: decision.confidence,
                  flags: decision.flags,
                  reasons: decision.reasons,
                  summary: decision.summary,
                  model: decision.model,
                  scannedAt: new Date().toISOString(),
                })
              }
              store.setCursor(account.id, mailboxPath, fetched.cursor)
              result.mailboxes.push({ path: mailboxPath, kind, newMessages: fetched.messages.length, total: fetched.total })
            }
            return result
          })
          accountReport.push(summary)
        } catch (error) {
          notes.push(`${account.address}：${String(error?.message ?? error)}`)
          accountReport.push({ address: account.address, ok: false, error: String(error?.message ?? error).slice(0, 200) })
        }
      }

      store.appendLabels(rows)
      const buckets = bucketize(rows)
      const markdown = buildReport({
        rows,
        buckets,
        accounts: accounts.map((account) => ({ address: account.address })),
        scannedMailboxes: mailboxes,
        modelName: useModel ? (deps.config.localModel?.model ?? 'qwen2.5:7b') : '未使用本地模型（全部未保护邮件进入黄桶）',
        notes,
      })
      const name = reportName()
      const reportPath = store.writeReport(name, markdown)

      const reviewBatch = buckets.yellow.slice(0, 40).map((row) => ({
        key: row.key,
        account: row.account,
        date: row.date,
        from: `${row.fromName} <${row.fromAddress}>`.trim(),
        subject: row.subject,
        snippet: row.snippet,
        categoryGuess: row.category,
        reasons: row.reasons,
        attachments: row.attachments.map((a) => a.filename),
      }))

      return {
        ok: rows.length >= 0,
        scanned: rows.length,
        buckets: {
          green: buckets.green.length,
          yellow: buckets.yellow.length,
          red: buckets.red.length,
        },
        reportPath,
        reviewBatch,
        accounts: accountReport,
        notes: notes.concat([
          '本轮只读取与本地打标，未对邮箱做任何修改。',
          reviewBatch.length > 0 ? `黄桶前 ${reviewBatch.length} 封已附在 reviewBatch，请用 mail_triage_review 回填判定。` : '没有需要复核的邮件。',
        ]),
      }
    },
  }

  const reviewTool = {
    name: 'mail_triage_review',
    description:
      'Two modes. Without decisions: return the yellow bucket that still needs a verdict. With decisions: record verdicts for specific message keys so they can move to the green bucket (delete candidate) or be kept.',
    parameters: {
      type: 'object',
      properties: {
        decisions: {
          type: 'array',
          description: 'Verdicts to record; omit to read the pending review queue.',
          items: {
            type: 'object',
            properties: {
              key: { type: 'string' },
              action: { type: 'string', enum: ['keep', 'archive', 'delete_candidate', 'review_required', 'quarantine'] },
              category: { type: 'string' },
              reason: { type: 'string' },
            },
            required: ['key', 'action'],
          },
        },
        limit: { type: 'integer', description: 'Pending rows to return (default 40).' },
      },
      additionalProperties: false,
    },
    output: output({
      type: 'object',
      properties: {
        ok: { type: 'boolean' },
        pending: { type: 'array', items: { type: 'object' } },
        recorded: { type: 'integer' },
      },
      required: ['ok'],
    }),
    async execute(args, exec) {
      const store = await storeFor(deps, exec)
      if (Array.isArray(args.decisions) && args.decisions.length > 0) {
        const verdicts = args.decisions.map((decision) => ({
          key: String(decision.key),
          action: String(decision.action),
          category: decision.category ? String(decision.category) : undefined,
          reason: decision.reason ? String(decision.reason) : undefined,
          at: new Date().toISOString(),
          by: 'session',
        }))
        store.appendVerdicts(verdicts)
        return { ok: true, recorded: verdicts.length, pending: [] }
      }

      const limit = Math.max(1, Math.min(200, Number(args.limit) || 40))
      const verdicts = newestVerdicts(store)
      const pending = store
        .readLabels()
        .filter((row) => row.bucket === 'yellow' && !verdicts.has(row.key))
        .slice(-limit)
        .map((row) => ({
          key: row.key,
          account: row.account,
          date: row.date,
          from: `${row.fromName} <${row.fromAddress}>`.trim(),
          subject: row.subject,
          snippet: row.snippet,
          categoryGuess: row.category,
          reasons: row.reasons,
          attachments: (row.attachments ?? []).map((a) => a.filename),
        }))
      return { ok: true, pending, recorded: 0 }
    },
  }

  const planTool = {
    name: 'mail_triage_plan',
    description:
      'Read-only. Builds the delete-candidate list and writes a manifest (message ids, folder, planned action, hash) for the user to approve. Re-checks every protection rule at plan time; nothing is moved.',
    parameters: {
      type: 'object',
      properties: {
        accounts: { type: 'array', items: { type: 'string' } },
        limit: { type: 'integer', description: 'Maximum candidates to include (default from config, 50).' },
        minConfidence: { type: 'number', description: 'Minimum confidence for model-only candidates (default 0.85).' },
      },
      additionalProperties: false,
    },
    output: output({
      type: 'object',
      properties: {
        ok: { type: 'boolean' },
        manifestId: { type: 'string' },
        candidates: { type: 'integer' },
        preview: { type: 'array', items: { type: 'object' } },
        manifestPath: { type: 'string' },
        notes: { type: 'array', items: { type: 'string' } },
      },
      required: ['ok', 'candidates'],
    }),
    async execute(args, exec) {
      const store = await storeFor(deps, exec)
      const safety = deps.config.safety ?? {}
      const threshold = Number(args.minConfidence ?? safety.confidenceThreshold ?? 0.85)
      const limit = Math.max(1, Math.min(500, Number(args.limit ?? safety.maxDeletesPerRun ?? 50)))
      const filter = args.accounts && args.accounts.length > 0
        ? new Set(args.accounts.map((value) => String(value).toLowerCase()))
        : null

      const verdicts = newestVerdicts(store)
      const latest = new Map()
      for (const row of store.readLabels()) latest.set(row.key, row)

      const candidates = []
      const skipped = { protected: 0, notGreen: 0, recent: 0, category: 0, movedBefore: 0 }
      for (const row of latest.values()) {
        if (filter && !filter.has(String(row.account).toLowerCase())) continue
        const verdict = verdicts.get(row.key)
        if (verdict?.action === 'moved') {
          skipped.movedBefore += 1
          continue
        }
        const explicitDelete = verdict?.action === 'delete_candidate'
        const greenDelete = row.bucket === 'green' && row.action === 'delete_candidate'
        if (!explicitDelete && !greenDelete) {
          skipped.notGreen += 1
          continue
        }
        const category = verdict?.category ?? row.category
        if (NEVER_DELETE.has(category) || !DELETABLE.has(category)) {
          skipped.category += 1
          continue
        }
        if ((row.flags ?? []).some((flag) => BLOCKING_FLAGS.has(flag)) || (row.reasons ?? []).some((reason) => /whitelisted|credential|invoice|phishing|sent_or_draft/.test(reason))) {
          skipped.protected += 1
          continue
        }
        if (!verdict && Number(row.confidence) < threshold) {
          skipped.notGreen += 1
          continue
        }
        const ageDays = row.date ? (Date.now() - new Date(row.date).getTime()) / 86_400_000 : 0
        const minAgeDays = Number(safety.minAgeDays ?? 7)
        if (ageDays < minAgeDays) {
          skipped.recent += 1
          continue
        }
        candidates.push({ row, verdict })
      }

      candidates.sort((a, b) => String(a.row.date).localeCompare(String(b.row.date)))
      const selected = candidates.slice(0, limit)
      const id = `manifest-${Date.now()}-${randomUUID().slice(0, 8)}`
      const items = selected.map(({ row, verdict }) => ({
        key: row.key,
        account: row.account,
        mailbox: row.mailbox,
        uidValidity: row.uidValidity,
        uid: row.uid,
        date: row.date,
        from: row.fromAddress,
        subject: row.subject,
        category: verdict?.category ?? row.category,
        confidence: row.confidence,
        decidedBy: verdict ? 'review' : 'rules+model',
      }))
      const digest = sha256(JSON.stringify(items))
      const manifest = {
        id,
        createdAt: new Date().toISOString(),
        items,
        hash: digest,
        approved: false,
        totals: { items: items.length },
      }
      const manifestPath = store.writeManifest(manifest)

      return {
        ok: items.length > 0,
        manifestId: items.length > 0 ? id : undefined,
        candidates: items.length,
        preview: items.slice(0, 30),
        manifestPath: items.length > 0 ? manifestPath : undefined,
        notes: [
          `候选 ${items.length} 封（上限 ${limit}）；跳过：非绿桶 ${skipped.notGreen}、受保护 ${skipped.protected}、太新 ${skipped.recent}、类别不可删 ${skipped.category}`,
          items.length > 0 ? '清单已写入工作区，可先自己查看；执行前仍需要你在卡片上批准。' : '没有可执行的删除候选。',
        ],
      }
    },
  }

  const applyTool = {
    name: 'mail_triage_apply',
    description:
      'The only mutating tool. Shows an approval card listing exactly what will move, then moves those messages to the Trash mailbox. It never expunges and never deletes permanently; every move is written to the audit log.',
    parameters: {
      type: 'object',
      properties: {
        manifestId: { type: 'string', description: 'Manifest id returned by mail_triage_plan.' },
        dryRun: { type: 'boolean', description: 'Show what would happen without moving anything.' },
      },
      required: ['manifestId'],
      additionalProperties: false,
    },
    output: output({
      type: 'object',
      properties: {
        ok: { type: 'boolean' },
        approved: { type: 'boolean' },
        moved: { type: 'integer' },
        failed: { type: 'integer' },
        auditPath: { type: 'string' },
        notes: { type: 'array', items: { type: 'string' } },
      },
      required: ['ok', 'approved'],
    }),
    async execute(args, exec) {
      const store = await storeFor(deps, exec)
      const manifest = store.readManifest(String(args.manifestId ?? ''))
      if (!manifest) throw new Error(`找不到 manifest：${args.manifestId}。请先运行 mail_triage_plan。`)
      const digest = sha256(JSON.stringify(manifest.items))
      if (digest !== manifest.hash) {
        throw new Error('manifest 内容与其记录的哈希不一致，已拒绝执行。请重新生成清单。')
      }
      if (manifest.items.length === 0) {
        return { ok: true, approved: false, moved: 0, failed: 0, notes: ['清单为空，没有需要移动的邮件。'] }
      }
      if (args.dryRun) {
        return { ok: true, approved: false, moved: 0, failed: 0, notes: [`dryRun：将移动 ${manifest.items.length} 封到回收站，未执行。`] }
      }

      const preview = manifest.items.slice(0, 12).map((item, index) => `${index + 1}. ${item.date?.slice(0, 10) ?? '?'} | ${item.from} | ${item.subject}`)
      const approval = await askUser(deps, exec, {
        header: '确认移动到回收站',
        question: [
          `即将把 ${manifest.items.length} 封邮件从原文件夹移动到服务器的回收站（Trash）。`,
          '这不会永久删除：你仍可以在回收站里恢复。插件不会执行 expunge。',
          '前几封如下：',
          ...preview,
          manifest.items.length > preview.length ? `…以及其余 ${manifest.items.length - preview.length} 封。` : '',
        ].filter(Boolean).join('\n'),
        options: [
          { label: '允许移动', description: '只移动到回收站，可恢复。' },
          { label: '取消', description: '不做任何修改。' },
        ],
      })
      if (approval === null) {
        return { ok: false, approved: false, moved: 0, failed: 0, notes: ['本机没有可用的提问服务，无法取得批准，因此没有移动任何邮件。'] }
      }
      if (approval !== '允许移动') {
        return { ok: false, approved: false, moved: 0, failed: 0, notes: ['你取消了本次操作，没有移动任何邮件。'] }
      }

      const grouped = new Map()
      for (const item of manifest.items) {
        const bucket = grouped.get(item.account) ?? []
        bucket.push(item)
        grouped.set(item.account, bucket)
      }

      let moved = 0
      let failed = 0
      const notes = []
      const auditPath = store.paths.audit

      for (const [address, items] of grouped) {
        const account = selectedAccounts(deps, store, [address])[0]
        if (!account) {
          failed += items.length
          notes.push(`${address}：账号配置已不存在，跳过 ${items.length} 封`)
          continue
        }
        try {
          const secrets = await resolveSecrets(deps, store, account, exec.signal)
          await withClient(account, secrets, async (client) => {
            const boxes = await listMailboxes(client)
            const trash = resolveTrashMailbox(boxes)
            if (!trash) throw new Error(`在 ${address} 上找不到回收站文件夹（拒绝猜测）`)
            const byMailbox = new Map()
            for (const item of items) {
              const bucket = byMailbox.get(item.mailbox) ?? []
              bucket.push(item)
              byMailbox.set(item.mailbox, bucket)
            }
            for (const [mailbox, mailboxItems] of byMailbox) {
              const uids = mailboxItems.map((item) => item.uid)
              const result = await moveMessagesToTrash(client, mailbox, uids, trash)
              moved += result.moved.length
              failed += result.failed.length
              const failureByUid = new Map(result.failed.map((entry) => [entry.uid, entry.error]))
              for (const item of mailboxItems) {
                const ok = result.moved.includes(item.uid)
                store.appendAudit({
                  at: new Date().toISOString(),
                  tool: 'mail_triage_apply',
                  manifest: manifest.id,
                  manifestHash: manifest.hash,
                  account: address,
                  mailbox,
                  uid: item.uid,
                  uidValidity: item.uidValidity,
                  subject: item.subject,
                  category: item.category,
                  action: 'move_to_trash',
                  trashPath: trash,
                  ok,
                  error: ok ? undefined : failureByUid.get(item.uid),
                  approvedBy: 'user',
                })
                store.appendVerdicts([{ key: item.key, action: ok ? 'moved' : 'keep', at: new Date().toISOString(), by: 'apply' }])
              }
            }
          })
          notes.push(`${address}：移动 ${items.length} 封到 ${address} 的回收站`)
        } catch (error) {
          failed += items.length
          for (const item of items) {
            store.appendAudit({
              at: new Date().toISOString(),
              tool: 'mail_triage_apply',
              manifest: manifest.id,
              manifestHash: manifest.hash,
              account: address,
              mailbox: item.mailbox,
              uid: item.uid,
              subject: item.subject,
              action: 'move_to_trash',
              ok: false,
              error: String(error?.message ?? error).slice(0, 200),
              approvedBy: 'user',
            })
          }
          notes.push(`${address}：连接或移动失败 —— ${String(error?.message ?? error).slice(0, 200)}`)
        }
      }

      const updated = { ...manifest, approved: true, executedAt: new Date().toISOString(), result: { moved, failed } }
      store.writeManifest(updated)
      return {
        ok: failed === 0,
        approved: true,
        moved,
        failed,
        auditPath,
        notes: [...notes, '所有移动都记录在审计日志里；邮件在回收站中可自行恢复。'],
      }
    },
  }

  const auditTool = {
    name: 'mail_triage_audit',
    description: 'Read the audit log: who triggered each change, which model decided, the reason, approval state and the result. Also lists generated reports and manifests.',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', description: 'Trailing audit entries to return (default 50).' },
      },
      additionalProperties: false,
    },
    output: output({
      type: 'object',
      properties: {
        ok: { type: 'boolean' },
        entries: { type: 'array', items: { type: 'object' } },
        reports: { type: 'array', items: { type: 'string' } },
        summary: { type: 'object' },
      },
      required: ['ok'],
    }),
    async execute(args, exec) {
      const store = await storeFor(deps, exec)
      const entries = store.readAudit(Math.max(1, Math.min(500, Number(args.limit) || 50)))
      const summary = entries.reduce(
        (acc, entry) => {
          acc.total += 1
          if (entry.ok) acc.ok += 1
          else acc.failed += 1
          return acc
        },
        { total: 0, ok: 0, failed: 0 },
      )
      return { ok: true, entries, reports: store.listReports(), summary }
    },
  }

  return [accountsTool, scanTool, reviewTool, planTool, applyTool, auditTool]
}

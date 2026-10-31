// Dev harness: runs the real tools against stubbed Host services and real IMAP.
// Read-only up to mail_triage_plan; apply runs in dryRun mode only.
import { createTools } from '../lib/tools.mjs'
import { createTokenCache } from '../lib/oauth.mjs'

const records = new Map()
const audit = []

const ctx = {
  get(name) {
    if (name === 'workingDirectory') {
      return { ensure: async () => process.env.SIM_WORKSPACE ?? process.cwd() }
    }
    if (name === 'credentials') {
      return {
        async modifyRecord(key, mutate) {
          const next = await mutate(records.get(key))
          if (next !== undefined) records.set(key, next)
          return records.get(key)
        },
        async readRecord(key) {
          return records.get(key)
        },
        async deleteRecord(key) {
          records.delete(key)
        },
      }
    }
    if (name === 'userQuestions') {
      return {
        async ask(request) {
          const question = request.questions[0]
          const choice = question.options[0].label
          audit.push({ header: question.header, choice })
          console.log(`\n  [审批卡片] ${question.header} → 自动选择「${choice}」`)
          return { answers: [{ selected: [choice] }] }
        },
      }
    }
    return undefined
  },
  tools: { register() {} },
}

const config = {
  stateDir: '.mail-triage',
  scan: { lookbackDays: 30, maxPerRun: 200, mailboxes: ['INBOX'] },
  localModel: { enabled: true, baseURL: 'http://127.0.0.1:11434', model: 'qwen2.5:7b', timeoutMs: 120000, concurrency: 2 },
  safety: { minAgeDays: 7, maxDeletesPerRun: 50, confidenceThreshold: 0.85, protectDomains: ['usm.my', 'uow.edu.my'], protectSenders: [] },
  thunderbird: { enabled: true, profiles: [] },
}

const deps = { ctx, config, tokenCache: createTokenCache() }
const tools = Object.fromEntries(createTools(deps).map((tool) => [tool.name, tool]))
const exec = { agent: { id: 'sim' }, signal: undefined }

function show(label, value) {
  console.log(`\n== ${label} ==`)
  console.log(JSON.stringify(value, null, 2).slice(0, 1800))
}

const accountFilter = (process.env.SIM_ACCOUNTS ?? '').split(',').map((s) => s.trim()).filter(Boolean)

show('import_thunderbird', await tools.mail_triage_accounts.execute({ action: 'import_thunderbird' }, exec))
show('list', await tools.mail_triage_accounts.execute({ action: 'list' }, exec))

const scan = await tools.mail_triage_scan.execute(
  {
    ...(accountFilter.length > 0 ? { accounts: accountFilter } : {}),
    lookbackDays: Number(process.env.SIM_LOOKBACK ?? 30),
    maxPerRun: Number(process.env.SIM_MAX ?? 10),
    ...(process.env.SIM_RESET === '1' ? { resetCursor: true } : {}),
  },
  exec,
)
show('scan', { scanned: scan.scanned, buckets: scan.buckets, reportPath: scan.reportPath, notes: scan.notes })

const review = await tools.mail_triage_review.execute({ limit: 5 }, exec)
show('review pending (前 2 条)', review.pending.slice(0, 2))

const plan = await tools.mail_triage_plan.execute({}, exec)
show('plan', { candidates: plan.candidates, manifestId: plan.manifestId, notes: plan.notes, preview: plan.preview.slice(0, 3) })

if (plan.manifestId) {
  show('apply dryRun', await tools.mail_triage_apply.execute({ manifestId: plan.manifestId, dryRun: true }, exec))
}

show('audit', await tools.mail_triage_audit.execute({ limit: 5 }, exec))


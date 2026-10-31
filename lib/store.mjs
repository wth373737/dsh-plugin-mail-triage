/**
 * Local state for the mail plugin. Everything lives under one workspace
 * directory so the user can read, diff and delete it:
 *
 *   .mail-triage/
 *     config.json      accounts (no secrets) + user overrides
 *     state.json       per account/mailbox incremental cursor
 *     labels.jsonl     one line per triaged message (append-only)
 *     verdicts.jsonl   review decisions coming back from the session model/user
 *     audit.jsonl      one line per mutating action
 *     manifests/       one JSON per prepared batch of deletions
 *     reports/         markdown triage reports
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, appendFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

function readJson(path, fallback) {
  try {
    if (!existsSync(path)) return fallback
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch {
    return fallback
  }
}

function readJsonl(path) {
  try {
    if (!existsSync(path)) return []
    return readFileSync(path, 'utf8')
      .split(/\r?\n/)
      .filter((line) => line.trim())
      .map((line) => {
        try {
          return JSON.parse(line)
        } catch {
          return null
        }
      })
      .filter(Boolean)
  } catch {
    return []
  }
}

export function createStore(rootDir) {
  const root = rootDir
  const paths = {
    root,
    config: join(root, 'config.json'),
    state: join(root, 'state.json'),
    labels: join(root, 'labels.jsonl'),
    verdicts: join(root, 'verdicts.jsonl'),
    audit: join(root, 'audit.jsonl'),
    manifests: join(root, 'manifests'),
    reports: join(root, 'reports'),
  }

  function ensure() {
    mkdirSync(paths.manifests, { recursive: true })
    mkdirSync(paths.reports, { recursive: true })
    return paths
  }

  return {
    paths,
    ensure,

    readConfig(fallback) {
      return readJson(paths.config, fallback ?? { accounts: [] })
    },
    writeConfig(config) {
      ensure()
      writeFileSync(paths.config, `${JSON.stringify(config, null, 2)}\n`, 'utf8')
    },

    readState() {
      return readJson(paths.state, { cursors: {} })
    },
    getCursor(accountId, mailbox) {
      return this.readState().cursors[`${accountId}|${mailbox}`]
    },
    setCursor(accountId, mailbox, cursor) {
      const state = this.readState()
      state.cursors[`${accountId}|${mailbox}`] = cursor
      ensure()
      writeFileSync(paths.state, `${JSON.stringify(state, null, 2)}\n`, 'utf8')
    },
    resetCursor(accountId, mailbox) {
      const state = this.readState()
      delete state.cursors[`${accountId}|${mailbox}`]
      ensure()
      writeFileSync(paths.state, `${JSON.stringify(state, null, 2)}\n`, 'utf8')
    },

    appendLabels(rows) {
      if (rows.length === 0) return
      ensure()
      appendFileSync(paths.labels, `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`, 'utf8')
    },
    readLabels() {
      return readJsonl(paths.labels)
    },

    appendVerdicts(rows) {
      if (rows.length === 0) return
      ensure()
      appendFileSync(paths.verdicts, `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`, 'utf8')
    },
    readVerdicts() {
      return readJsonl(paths.verdicts)
    },

    appendAudit(entry) {
      ensure()
      appendFileSync(paths.audit, `${JSON.stringify(entry)}\n`, 'utf8')
    },
    readAudit(limit = 100) {
      const all = readJsonl(paths.audit)
      return Number(limit) > 0 ? all.slice(-Number(limit)) : all
    },

    writeManifest(manifest) {
      ensure()
      const path = join(paths.manifests, `${manifest.id}.json`)
      writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
      return path
    },
    readManifest(id) {
      if (!/^[A-Za-z0-9._-]+$/.test(String(id ?? ''))) return null
      return readJson(join(paths.manifests, `${id}.json`), null)
    },
    writeReport(name, markdown) {
      ensure()
      const path = join(paths.reports, name)
      writeFileSync(path, markdown, 'utf8')
      return path
    },
    listReports() {
      try {
        return readdirSync(paths.reports).sort()
      } catch {
        return []
      }
    },
    writeJson(name, value) {
      ensure()
      const path = join(root, name)
      writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
      return path
    },
    readJson(name, fallback) {
      return readJson(join(root, name), fallback)
    },
  }
}

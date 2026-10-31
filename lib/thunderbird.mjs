/**
 * Thunderbird credential import.
 *
 * Reads a Thunderbird profile's `key4.db` + `logins.json` and yields the
 * account material we need to talk IMAP: passwords for password-auth servers
 * and OAuth2 refresh tokens for Microsoft 365.
 *
 * Verified approach (no native modules, no external binaries):
 *   - `node:sqlite` reads key4.db (Node >= 22.5; Node 24 has it unflagged)
 *   - `node:crypto` reimplements NSS PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC)
 *   - the NSS IV is the two-byte DER header `04 0e` plus the 14-byte IV body
 *   - the KDF password is SHA1(globalSalt || primaryPassword)
 *
 * A primary password, when set, cannot be guessed: the caller must supply it.
 */
import { DatabaseSync } from 'node:sqlite'
import { createDecipheriv, createHash, pbkdf2Sync } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** The client id Thunderbird itself uses; public clients need no secret. */
export const THUNDERBIRD_MS_CLIENT_ID = '9e5f94bc-e8a4-4e73-b8be-63364c29d753'
/**
 * Thunderbird's Google OAuth client (public in Thunderbird's own source, see
 * mailnews/base/src/OAuth2Providers.sys.mjs). Used only to redeem a refresh
 * token that Thunderbird already holds, so the user needs no new consent.
 * If Google ever rejects it, the fallback is a 16-character app password.
 */
export const THUNDERBIRD_GOOGLE_CLIENT_ID = '406964657835-aq8lmia8j95dhl1a2bvharmfk3t1hgqj.apps.googleusercontent.com'
export const THUNDERBIRD_GOOGLE_CLIENT_SECRET = 'kSmqreRr0qwBWJgbf5Y-PjSU'

const MS_IMAP_SCOPE = 'https://outlook.office.com/IMAP.AccessAsUser.All offline_access'

/* --------------------------------------------------------------- DER scan */

/**
 * Collect every OID, OCTET STRING and INTEGER in document order. The NSS
 * structures are small and fixed-shape, so positional collection is enough and
 * far less code than a full ASN.1 decoder.
 */
function scanDer(buf) {
  const oids = []
  const octs = []
  const ints = []
  const walk = (b, off, end) => {
    while (off < end) {
      const tag = b[off]
      let p = off + 1
      let len = b[p++]
      if (len & 0x80) {
        const n = len & 0x7f
        len = 0
        for (let i = 0; i < n; i++) len = len * 256 + b[p++]
      }
      const val = b.subarray(p, p + len)
      if (tag === 0x30) walk(b, p, p + len)
      else if (tag === 0x06) oids.push(val.toString('hex'))
      else if (tag === 0x04) octs.push(val)
      else if (tag === 0x02) {
        let v = 0
        for (let i = 0; i < len; i++) v = v * 256 + val[i]
        ints.push(v)
      }
      off = p + len
    }
  }
  walk(buf, 0, buf.length)
  return { oids, octs, ints }
}

/** Remove PKCS#7 padding, but only when it is actually valid. */
function stripPad(buf) {
  if (buf.length === 0) return buf
  const pad = buf[buf.length - 1]
  if (pad < 1 || pad > 16 || pad > buf.length) return buf
  for (let i = buf.length - pad; i < buf.length; i++) if (buf[i] !== pad) return buf
  return buf.subarray(0, buf.length - pad)
}

/* ------------------------------------------------------------ key4 / logins */

function openKeyDb(profileDir) {
  const path = join(profileDir, 'key4.db')
  if (!existsSync(path)) throw new Error(`找不到 ${path}`)
  return new DatabaseSync(path, { readOnly: true })
}

function readPasswordCheck(db, primaryPassword) {
  let row
  for (const table of ['metaData', 'metadata']) {
    try {
      row = db.prepare(`SELECT item1, item2 FROM ${table} WHERE id = 'password'`).get()
      if (row) break
    } catch {
      /* try the next spelling */
    }
  }
  if (!row) throw new Error('key4.db 里没有 password 行，可能不是雷鸟/Firefox 的密钥库')

  const globalSalt = Buffer.from(row.item1)
  const seed = createHash('sha1').update(Buffer.concat([globalSalt, Buffer.from(primaryPassword ?? '', 'utf8')])).digest()

  const pbes2 = (blob) => {
    const s = scanDer(blob)
    if (s.oids[0] !== '2a864886f70d01050d') throw new Error(`不支持的 PBE 算法 ${s.oids[0]}`)
    const [salt, ivSuffix, cipherText] = s.octs
    const key = pbkdf2Sync(seed, salt, s.ints[0], s.ints[1], 'sha256')
    const iv = Buffer.concat([Buffer.from([0x04, 0x0e]), ivSuffix])
    const decipher = createDecipheriv('aes-256-cbc', key, iv)
    return stripPad(Buffer.concat([decipher.update(cipherText), decipher.final()]))
  }

  const check = pbes2(Buffer.from(row.item2)).toString('latin1')
  if (check !== 'password-check') {
    throw new Error('主密码不正确，或该密钥库无法用空主密码解开')
  }
  return { globalSalt, pbes2 }
}

/**
 * Decrypt every stored login.
 * @param {string} profileDir Thunderbird profile directory
 * @param {string} [primaryPassword]
 */
export function readThunderbirdLogins(profileDir, primaryPassword = '') {
  const db = openKeyDb(profileDir)
  const { pbes2 } = readPasswordCheck(db, primaryPassword)

  const keys = db
    .prepare('SELECT a11 FROM nssPrivate')
    .all()
    .map((row) => pbes2(Buffer.from(row.a11)))
  const key24 = keys.find((k) => k.length === 24)
  const key32 = keys.find((k) => k.length === 32)
  if (!key32 && !key24) throw new Error('nssPrivate 里没有可用的 SDR 密钥')

  const decryptField = (b64) => {
    const raw = Buffer.from(b64, 'base64')
    if (raw.length === 0) return ''
    if (raw[0] === 0x7e) return raw.subarray(1).toString('utf8')
    const s = scanDer(raw)
    const oid = s.oids[0]
    const tripleDes = oid === '2a864886f70d0307' || oid === '2a864886f70d010c050103'
    const key = tripleDes ? key24 : key32
    if (!key) throw new Error(`缺少 ${oid} 对应长度的密钥`)
    const decipher = createDecipheriv(tripleDes ? 'des-ede3-cbc' : 'aes-256-cbc', key, s.octs[1])
    return stripPad(Buffer.concat([decipher.update(s.octs[2]), decipher.final()])).toString('utf8')
  }

  const json = JSON.parse(readFileSync(join(profileDir, 'logins.json'), 'utf8'))
  const out = []
  for (const entry of json.logins ?? []) {
    const record = { hostname: entry.hostname, httpRealm: entry.httpRealm ?? null }
    try {
      record.username = decryptField(entry.encryptedUsername)
    } catch (error) {
      record.error = String(error?.message ?? error)
    }
    try {
      record.password = decryptField(entry.encryptedPassword)
    } catch (error) {
      record.error = String(error?.message ?? error)
    }
    out.push(record)
  }
  return out
}

/* ------------------------------------------------------- profile discovery */

function thunderbirdRoots() {
  const platform = process.platform
  const roots = []
  if (platform === 'win32') {
    if (process.env.APPDATA) roots.push(join(process.env.APPDATA, 'Thunderbird'))
  } else if (platform === 'darwin') {
    roots.push(join(homedir(), 'Library', 'Thunderbird'))
  } else {
    roots.push(join(homedir(), '.thunderbird'))
  }
  return roots
}

function parseProfileIni(root) {
  const iniPath = join(root, 'profiles.ini')
  if (!existsSync(iniPath)) return []
  const text = readFileSync(iniPath, 'utf8')
  const sections = []
  let current = null
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue
    const section = /^\[(.+)\]$/.exec(trimmed)
    if (section) {
      current = { name: section[1], values: {} }
      sections.push(current)
      continue
    }
    const kv = /^([^=]+)=(.*)$/.exec(trimmed)
    if (kv && current) current.values[kv[1].trim()] = kv[2].trim()
  }
  const profiles = []
  for (const section of sections) {
    if (!section.name.startsWith('Profile')) continue
    const rel = section.values.IsRelative !== '0'
    const path = rel ? join(root, section.values.Path ?? '') : section.values.Path
    if (path && existsSync(path)) profiles.push(path)
  }
  return profiles
}

/**
 * Resolve Thunderbird profile directories.
 * @param {string[]} [explicit] user-configured paths win over discovery
 */
export function findThunderbirdProfiles(explicit = []) {
  const found = []
  const usable = (path) => existsSync(join(path, 'key4.db')) && existsSync(join(path, 'logins.json'))
  const push = (path) => {
    if (path && usable(path) && !found.includes(path)) found.push(path)
  }
  for (const path of explicit) push(path)
  if (found.length > 0) return found
  for (const root of thunderbirdRoots()) {
    for (const profile of parseProfileIni(root)) push(profile)
    if (usable(root)) push(root)
  }
  return found
}

/* --------------------------------------------------------- account shaping */

const PROVIDERS = [
  { match: /^imap\.gmail\.com$/i, provider: 'gmail', port: 993, secure: true, id: false },
  { match: /^imap\.163\.com$/i, provider: '163', port: 993, secure: true, id: true },
  { match: /^imap\.126\.com$/i, provider: '163', port: 993, secure: true, id: true },
  { match: /^imap\.qq\.com$/i, provider: 'qq', port: 993, secure: true, id: true },
  { match: /^outlook\.office365\.com$/i, provider: 'm365', port: 993, secure: true, id: false },
  { match: /^outlook\.office365\.com$/i, provider: 'm365', port: 993, secure: true, id: false },
  { match: /^imap-mail\.outlook\.com$/i, provider: 'm365-personal', port: 993, secure: true, id: false },
]

function providerFor(host) {
  for (const entry of PROVIDERS) if (entry.match.test(host)) return entry
  return { provider: 'imap', port: 993, secure: true, id: false }
}

const IMAP_HOST_HINT = {
  'imap.gmail.com': 'gmail',
  'imap.163.com': '163',
  'imap.126.com': '163',
  'imap.qq.com': 'qq',
  'outlook.office365.com': 'm365',
}

/**
 * Fold Thunderbird's flat login list into per-address account candidates.
 * @param {ReturnType<typeof readThunderbirdLogins>} records
 */
export function accountsFromLogins(records) {
  const byAddress = new Map()
  const ensure = (address) => {
    if (!byAddress.has(address)) {
      byAddress.set(address, { address, passwords: new Map(), oauth: new Map() })
    }
    return byAddress.get(address)
  }

  for (const record of records) {
    const address = (record.username ?? '').trim()
    if (!address || !address.includes('@')) continue
    const host = record.hostname ?? ''
    if (host.startsWith('imap://')) {
      ensure(address).passwords.set(host.slice('imap://'.length), record.password ?? '')
    } else if (host.startsWith('oauth://')) {
      ensure(address).oauth.set(host.slice('oauth://'.length), {
        refreshToken: record.password ?? '',
        realm: record.httpRealm ?? '',
      })
    }
  }

  const accounts = []
  for (const candidate of byAddress.values()) {
    if (candidate.passwords.size === 0 && candidate.oauth.size === 0) continue
    const imapHost = [...candidate.passwords.keys()].find((h) => IMAP_HOST_HINT[h]) ?? [...candidate.passwords.keys()][0] ?? 'outlook.office365.com'
    const meta = providerFor(imapHost)
    const password = candidate.passwords.get(imapHost) ?? [...candidate.passwords.values()][0] ?? ''
    const ms = candidate.oauth.get('login.microsoftonline.com')
    const google = candidate.oauth.get('accounts.google.com')

    const account = {
      id: candidate.address.toLowerCase(),
      address: candidate.address,
      provider: meta.provider,
      imap: { host: imapHost, port: meta.port, secure: meta.secure, sendId: meta.id },
      source: 'thunderbird',
      auth: null,
      needsSecret: false,
      notes: [],
    }

    if (meta.provider === 'm365' || meta.provider === 'm365-personal') {
      if (ms?.refreshToken) {
        account.auth = {
          kind: 'xoauth2',
          oauthProvider: 'microsoft',
          refreshToken: ms.refreshToken,
          clientId: THUNDERBIRD_MS_CLIENT_ID,
          tenant: 'common',
          scope: MS_IMAP_SCOPE,
        }
      } else {
        account.needsSecret = true
        account.notes.push('雷鸟里没有找到 Microsoft 授权令牌，请在雷鸟里重新登录一次该账号')
      }
    } else if (meta.provider === 'gmail') {
      if (password && password.length === 16) {
        account.auth = { kind: 'password', password }
      } else if (google?.refreshToken) {
        account.auth = {
          kind: 'xoauth2',
          oauthProvider: 'google',
          refreshToken: google.refreshToken,
          clientId: THUNDERBIRD_GOOGLE_CLIENT_ID,
          clientSecret: THUNDERBIRD_GOOGLE_CLIENT_SECRET,
          scope: 'https://mail.google.com/',
        }
        account.notes.push('Gmail 使用雷鸟里的 Google 授权，如果刷新失败请改用 16 位应用专用密码')
      } else {
        account.needsSecret = true
        account.notes.push('需要 Gmail 的 16 位应用专用密码（Google 已停用普通密码登录 IMAP）')
      }
    } else {
      if (password) account.auth = { kind: 'password', password }
      else {
        account.needsSecret = true
        account.notes.push('雷鸟里没有存这个账号的密码，需要手动提供')
      }
    }

    // Persisted accounts keep only `authKind`; the secret itself lives in the
    // credential store. Default to xoauth2 for Microsoft so a re-import is not
    // needed if the token is temporarily missing.
    account.authKind =
      account.auth?.kind === 'xoauth2' || meta.provider === 'm365' || meta.provider === 'm365-personal'
        ? 'xoauth2'
        : 'password'

    accounts.push(account)
  }
  return accounts.sort((a, b) => a.address.localeCompare(b.address))
}

/** One-shot: discover profiles, decrypt, shape accounts. */
export function importFromThunderbird({ profiles = [], primaryPassword = '' } = {}) {
  const dirs = findThunderbirdProfiles(profiles)
  if (dirs.length === 0) {
    throw new Error('没有找到雷鸟配置目录（profiles.ini）。可以在插件配置 thunderbird.profiles 里写绝对路径。')
  }
  const results = []
  for (const dir of dirs) {
    try {
      const records = readThunderbirdLogins(dir, primaryPassword)
      results.push({ profile: dir, accounts: accountsFromLogins(records), recordCount: records.length })
    } catch (error) {
      results.push({ profile: dir, accounts: [], error: String(error?.message ?? error) })
    }
  }
  return results
}

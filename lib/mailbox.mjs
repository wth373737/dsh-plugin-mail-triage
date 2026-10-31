/**
 * IMAP transport.
 *
 * One dependency: `imapflow`. Everything here is read-only except
 * `moveMessagesToTrash`, which performs MOVE to the server's \Trash mailbox and
 * never expunges anything.
 */
import { ImapFlow } from 'imapflow'

const num = (value) => (value === undefined || value === null ? 0 : Number(value))

const CLIENT_INFO = { name: 'DSH Mail Triage', version: '0.1.0' }

/** Build a client from a stored account descriptor plus resolved secrets. */
export function createClient(account, secrets) {
  const auth = { user: account.address }
  // Stored accounts carry `authKind`, never the secret itself.
  const isOauth = account.authKind === 'xoauth2' || account.auth?.kind === 'xoauth2'
  if (isOauth) auth.accessToken = secrets.accessToken
  else auth.pass = secrets.password

  return new ImapFlow({
    host: account.imap.host,
    port: account.imap.port ?? 993,
    secure: account.imap.secure !== false,
    auth,
    clientInfo: CLIENT_INFO,
    logger: false,
    tls: { rejectUnauthorized: true },
    // Fail fast instead of hanging a tool call for minutes.
    socketTimeout: 60_000,
    greetingTimeout: 20_000,
  })
}

function describeError(error, account) {
  const text = [error?.message, error?.responseText].filter(Boolean).join(' · ')
  if (error?.authenticationFailed || /AUTHENTICATIONFAILED|AUTHENTICATE failed|invalid credentials|LOGIN failed|AUTHORIZATIONFAILED/i.test(text)) {
    return `${account.address} 认证被服务器拒绝（${text.slice(0, 120)}）。请先在雷鸟里确认该账号仍能正常收发；若雷鸟也失败，需要在雷鸟里重新登录该账号，或在邮箱服务商处检查 IMAP 是否开放。`
  }
  if (/ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|socket hang up/i.test(text)) {
    return `${account.address} 连接 ${account.imap.host} 失败：${text}`
  }
  return text || String(error)
}

/**
 * Open a connection, run `fn`, always close.
 * @template T
 * @param {object} account
 * @param {object} secrets
 * @param {(client: ImapFlow) => Promise<T>} fn
 * @returns {Promise<T>}
 */
export async function withClient(account, secrets, fn) {
  const client = createClient(account, secrets)
  try {
    await client.connect()
  } catch (error) {
    try {
      await client.close()
    } catch {
      /* ignore */
    }
    throw new Error(describeError(error, account))
  }
  try {
    return await fn(client)
  } finally {
    try {
      await client.logout()
    } catch {
      try {
        await client.close()
      } catch {
        /* ignore */
      }
    }
  }
}

/** List mailboxes, normalising special-use flags into a plain shape. */
export async function listMailboxes(client) {
  const boxes = await client.list()
  return boxes.map((box) => ({
    path: box.path,
    name: box.name,
    specialUse: box.specialUse ?? null,
    flags: Array.isArray(box.flags) ? [...box.flags] : [],
  }))
}

const TRASH_HINTS = [/\\Trash/i, /^(trash|deleted|deleted items|bin)$/i, /(已删除|垃圾箱|回收站|垃圾桶)/]

/** Pick the Trash mailbox; refuse to guess when nothing matches. */
export function resolveTrashMailbox(boxes) {
  const flagged = boxes.find((box) => /\\Trash/i.test(box.specialUse ?? '') || box.flags.includes('\\Trash'))
  if (flagged) return flagged.path
  const hinted = boxes.find((box) => TRASH_HINTS.some((re) => re.test(box.name ?? '') || re.test(box.path ?? '')))
  return hinted?.path ?? null
}

/* ------------------------------------------------------------- body snippet */

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' }

function decodeEntities(text) {
  return text.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (all, body) => {
    if (body[0] === '#') {
      const code = body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10)
      return Number.isFinite(code) ? String.fromCodePoint(code) : all
    }
    return ENTITIES[body.toLowerCase()] ?? all
  })
}

function decodeQuotedPrintable(text) {
  return text
    .replace(/=\r?\n/g, '')
    .replace(/=([0-9A-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
}

function stripHtml(html) {
  return decodeEntities(
    html
      .replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ')
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
      .replace(/<[^>]+>/g, ' '),
  )
}

function splitHeadersAndBody(raw) {
  const match = /\r?\n\r?\n/.exec(raw)
  if (!match) return { headers: '', body: raw }
  return { headers: raw.slice(0, match.index), body: raw.slice(match.index + match[0].length) }
}

function decodePart(part) {
  let body = part.body
  const encoding = /content-transfer-encoding:\s*([\w-]+)/i.exec(part.headers)?.[1]?.toLowerCase() ?? ''
  if (encoding === 'base64') {
    const compact = body.replace(/[^A-Za-z0-9+/=]/g, '')
    const usable = compact.slice(0, compact.length - (compact.length % 4))
    try {
      body = Buffer.from(usable, 'base64').toString('utf8')
    } catch {
      /* keep the raw text */
    }
  } else if (encoding === 'quoted-printable') {
    body = decodeQuotedPrintable(body)
  }
  const isHtml = /content-type:\s*text\/html/i.test(part.headers)
  if (isHtml || /^\s*<(?:html|body|div|p|table)/i.test(body)) body = stripHtml(body)
  return body
}

/**
 * Pick the first readable text part out of a (possibly truncated) MIME body.
 * Multipart nesting is followed a few levels deep; when nothing matches we fall
 * back to the raw body after removing boundary and header noise.
 */
function selectTextPart(headers, body, depth = 0) {
  const boundary = /boundary\s*=\s*"?([^";\r\n]+)"?/i.exec(headers)?.[1]
  if (!boundary || depth > 3) return { headers, body }
  const segments = body.split(`--${boundary}`)
  const parts = []
  for (const segment of segments.slice(1)) {
    if (/^--/.test(segment.trim())) break
    const cleaned = segment.replace(/^\r?\n/, '')
    const split = splitHeadersAndBody(cleaned)
    if (!split.headers.trim()) continue
    parts.push(split)
  }
  const plain = parts.find((part) => /content-type:\s*text\/plain/i.test(part.headers))
  if (plain) return plain
  const html = parts.find((part) => /content-type:\s*text\/html/i.test(part.headers))
  if (html) return html
  for (const part of parts) {
    if (/content-type:\s*multipart\//i.test(part.headers)) {
      const nested = selectTextPart(part.headers, part.body, depth + 1)
      if (nested.body && !/boundary\s*=/i.test(nested.headers)) return nested
    }
  }
  return parts[0] ?? { headers, body }
}

/**
 * Turn a (possibly truncated) RFC822 source into a short plain-text snippet.
 * Deliberately forgiving: the source is cut at 8 KB, so a truncated part is
 * expected and a rough snippet is enough for classification.
 */
export function snippetFromSource(source, limit = 320) {
  if (!source) return ''
  const text = Buffer.isBuffer(source) ? source.toString('utf8') : String(source)
  // RFC822 always separates headers from the body with a blank line. Without one
  // the fetch was truncated inside the headers: return nothing so the caller can
  // re-fetch deeper instead of treating header lines as body text.
  if (!/\r?\n\r?\n/.test(text)) return ''
  const top = splitHeadersAndBody(text)
  const part = selectTextPart(top.headers, top.body)
  let body = decodePart(part)

  // Drop leftover MIME scaffolding and header lines that leaked into the text.
  body = body
    .replace(/^--[-\w=]+.*$/gm, '')
    .replace(/^(content-type|content-transfer-encoding|content-disposition|mime-version|boundary):.*$/gim, '')
    .replace(/=+/g, ' ')

  return body
    .replace(/[^\S\r\n]+/g, ' ')
    .replace(/\r/g, '')
    .replace(/\n{2,}/g, '\n')
    .trim()
    .slice(0, limit)
}

/* ------------------------------------------------------------ mail reading */

function envelopeToFields(envelope) {
  const first = (list) => (Array.isArray(list) && list.length > 0 ? list[0] : undefined)
  const from = first(envelope?.from) ?? {}
  const to = first(envelope?.to) ?? {}
  return {
    subject: String(envelope?.subject ?? ''),
    fromName: String(from.name ?? ''),
    fromAddress: String(from.address ?? '').toLowerCase(),
    toAddress: String(to.address ?? '').toLowerCase(),
    messageId: String(envelope?.messageId ?? ''),
    inReplyTo: String(envelope?.inReplyTo ?? ''),
    date: envelope?.date ? new Date(envelope.date).toISOString() : null,
  }
}

/**
 * Walk an IMAP BODYSTRUCTURE tree and list real attachments (filename or an
 * explicit attachment disposition). Inline images without a filename are not
 * listed: they are part of the message body, not a file the user saved.
 */
export function collectAttachments(structure) {
  const out = []
  const walk = (node) => {
    if (!node) return
    const filename = node.dispositionParameters?.filename ?? node.parameters?.name
    const disposition = String(node.disposition ?? '')
    const isAttachment = /attachment/i.test(disposition) || (filename && !/^inline$/i.test(disposition))
    if (isAttachment && filename) {
      out.push({ filename: String(filename).slice(0, 160), size: Number(node.size ?? 0) })
    }
    for (const child of node.childNodes ?? []) walk(child)
  }
  walk(structure)
  return out
}

/**
 * Fetch messages for triage: envelope, flags, size, and a short body snippet.
 * @param {ImapFlow} client
 * @param {object} options
 */
export async function fetchMessages(client, options) {
  const mailbox = options.mailbox ?? 'INBOX'
  const max = Math.max(1, Math.min(2000, Number(options.max) || 200))
  const lock = await client.getMailboxLock(mailbox)
  try {
    const box = client.mailbox
    let uids = []
    if (Number(options.sinceUid) > 0) {
      const start = Number(options.sinceUid) + 1
      if (start > (num(box.uidNext) || 1)) {
        return { messages: [], cursor: { uidNext: num(box.uidNext) || 1, uidValidity: num(box.uidValidity) }, mailbox, total: num(box.exists) }
      }
      uids = (await client.search({ uid: `${start}:*` }, { uid: true })).map(num)
    } else {
      const since = new Date(Date.now() - (Number(options.lookbackDays) || 30) * 86_400_000)
      uids = (await client.search({ since }, { uid: true })).map(num)
      if (uids.length > max) uids = uids.slice(-max)
    }
    if (uids.length === 0) {
      return { messages: [], cursor: { uidNext: num(box.uidNext) || 1, uidValidity: num(box.uidValidity) }, mailbox, total: num(box.exists) }
    }
    if (uids.length > max) uids = uids.slice(-max)

    const messages = []
    const needsDeeperFetch = []
    // One round trip per batch: metadata, body structure and a truncated source
    // all come from the same FETCH. The prefix is deliberately small; messages
    // whose header block (DKIM/ARC chains) exceeds it are re-fetched below.
    for await (const message of client.fetch(
      uids.join(','),
      { uid: true, envelope: true, flags: true, size: true, internalDate: true, bodyStructure: true, source: { maxLength: 8192 } },
      { uid: true },
    )) {
      const fields = envelopeToFields(message.envelope)
      const flags = message.flags ? [...message.flags] : []
      const attachments = collectAttachments(message.bodyStructure)
      const raw = message.source ? String(message.source) : ''
      const snippet = snippetFromSource(raw)
      const record = {
        uid: num(message.uid),
        ...fields,
        size: num(message.size),
        internalDate: message.internalDate ? new Date(message.internalDate).toISOString() : fields.date,
        flags,
        seen: flags.includes('\\Seen'),
        flagged: flags.includes('\\Flagged'),
        attachments,
        hasAttachment: attachments.length > 0,
        snippet,
      }
      // No blank line means the 8 KB prefix never reached the body.
      if (raw.length > 0 && !/\r?\n\r?\n/.test(raw)) needsDeeperFetch.push(record)
      messages.push(record)
    }

    for (const record of needsDeeperFetch) {
      try {
        const full = await client.fetchOne(record.uid, { source: { maxLength: 131072 } }, { uid: true })
        record.snippet = snippetFromSource(full?.source ?? '')
      } catch {
        /* keep the empty snippet */
      }
    }

    return {
      messages,
      mailbox,
      total: num(box.exists),
      cursor: { uidNext: num(box.uidNext) || 1, uidValidity: num(box.uidValidity) },
    }
  } finally {
    lock.release()
  }
}

/**
 * Move messages to the Trash mailbox. Never deletes permanently and never
 * expunges: on servers without MOVE this becomes COPY + \Deleted, which the user
 * can still undo from Trash.
 * @returns {Promise<{moved: number[], failed: {uid: number, error: string}[]}>}
 */
export async function moveMessagesToTrash(client, mailbox, uids, trashPath) {
  const moved = []
  const failed = []
  const lock = await client.getMailboxLock(mailbox)
  try {
    // Servers accept a sequenced command, so send UIDs in chunks of 40 instead of
    // one round trip per message. A failing chunk falls back to per-message moves
    // so a single bad message cannot block the rest.
    const chunkSize = 40
    for (let index = 0; index < uids.length; index += chunkSize) {
      const chunk = uids.slice(index, index + chunkSize)
      try {
        await client.messageMove(chunk.join(','), trashPath, { uid: true })
        moved.push(...chunk)
        continue
      } catch {
        /* fall through to per-message retry */
      }
      for (const uid of chunk) {
        try {
          await client.messageMove(String(uid), trashPath, { uid: true })
          moved.push(uid)
        } catch (error) {
          failed.push({ uid, error: String(error?.message ?? error).slice(0, 200) })
        }
      }
    }
  } finally {
    lock.release()
  }
  return { moved, failed }
}



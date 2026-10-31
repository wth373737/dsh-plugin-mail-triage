import { importFromThunderbird } from '../lib/thunderbird.mjs'
import { refreshMicrosoftToken } from '../lib/oauth.mjs'
import { listMailboxes, withClient } from '../lib/mailbox.mjs'

const acc = importFromThunderbird({}).flatMap(r => r.accounts).find(a => a.address === 'wutianhao@student.usm.my')
const tok = await refreshMicrosoftToken({ refreshToken: acc.auth.refreshToken, clientId: acc.auth.clientId, tenant: acc.auth.tenant, scope: acc.auth.scope })
const secrets = { accessToken: tok.accessToken }

await withClient(acc, secrets, async (client) => {
  const boxes = await listMailboxes(client)
  const rows = []
  for (const box of boxes) {
    try {
      const lock = await client.getMailboxLock(box.path)
      let count = 0, bytes = 0
      const top = []
      for await (const m of client.fetch('1:*', { uid: true, size: true, envelope: true }, { uid: false })) {
        count++
        const size = Number(m.size ?? 0)
        bytes += size
        if (size > 200_000) top.push({ size, subject: String(m.envelope?.subject ?? '').slice(0, 60), from: String(m.envelope?.from?.[0]?.address ?? '') })
      }
      lock.release()
      rows.push({ path: box.path, special: box.specialUse ?? '', count, mb: +(bytes / 1048576).toFixed(1), big: top.sort((a,b)=>b.size-a.size).slice(0,5) })
    } catch (e) {
      rows.push({ path: box.path, error: String(e.message).slice(0, 60) })
    }
  }
  rows.sort((a, b) => (b.mb ?? 0) - (a.mb ?? 0))
  let total = 0
  console.log('folder'.padEnd(28) + 'count'.padStart(7) + '   MB')
  for (const r of rows) {
    if (r.error) { console.log(`${r.path.padEnd(28)} ERROR ${r.error}`); continue }
    total += r.mb
    console.log(`${(r.path + (r.special ? ' ' + r.special : '')).padEnd(28)}${String(r.count).padStart(7)}${String(r.mb).padStart(8)}`)
  }
  console.log(`\n合计约 ${total.toFixed(1)} MB`)
  const big = rows.flatMap(r => (r.big ?? []).map(b => ({ ...b, folder: r.path }))).sort((a, b) => b.size - a.size).slice(0, 12)
  console.log('\n最大的附件类邮件：')
  for (const b of big) console.log(`  ${(b.size/1048576).toFixed(1)}MB  ${b.folder}  ${b.from.slice(0,28)}  ${b.subject}`)
})

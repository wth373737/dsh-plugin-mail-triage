# dsh-plugin-mail-triage

Mail triage and safe cleanup for **DeepSeek Harness**.

Read-only incremental triage first, an explicit approval second, and only then a
move to Trash. Reading and writing are separate tools with separate code paths,
and there is no expunge anywhere in this plugin.

简体中文说明见 [README.zh.md](README.zh.md).

## Pipeline

```
IMAP (incremental, metadata + a short body snippet)
  → hard-protection rule layer (OTP, invoices, attachments, phishing, school/official, sent, whitelist)
  → optional local Ollama classification
  → green (delete candidate) / yellow (needs review) / red (never auto-deleted)
  → Markdown triage report + local label list
  → manifest with a content hash
  → approval card
  → MOVE to the Trash mailbox
  → audit log
```

The first run only reads and labels. Nothing in the mailbox changes.

## Tools

| Tool | Access | Purpose |
| --- | --- | --- |
| `mail_triage_accounts` | metadata | `list`, `import_thunderbird`, `set_secret`, `test`, `remove` |
| `mail_triage_scan` | read-only | incremental scan, rules, local model, report |
| `mail_triage_review` | local | read the yellow queue / record verdicts |
| `mail_triage_plan` | read-only | build the delete list and manifest |
| `mail_triage_apply` | **write** | after approval, move to Trash |
| `mail_triage_audit` | read-only | audit log, reports, manifests |

## Credentials come from Thunderbird

No manual typing: the plugin decrypts the local Thunderbird profile
(`key4.db` + `logins.json`) and stores the account secrets in the DSH credential
store. Decryption happens locally with `node:sqlite` and `node:crypto` — no
Python, no NSS DLL, no native modules. Nothing is written to the workspace in
plaintext and nothing is uploaded.

## Install

In the DSH UI, **Plugins → + Add plugin**:

```
github:<your-account>/dsh-plugin-mail-triage
```

`imapflow` (the single dependency, pure JavaScript) is installed by pnpm.

## Safety properties enforced in code

- The rule layer can only protect; it never creates a deletion on its own.
- Low confidence, an invalid model schema, a timeout or a missing model all fall
  to the yellow bucket.
- OTP, invoice, phishing, attachment, official, academic, personal and
  sent/draft categories are never auto-deleted.
- Deletion is MOVE to `\Trash`; if no Trash mailbox resolves, the plugin refuses
  instead of guessing.
- The manifest carries a content hash that is re-verified before execution.
- Every move is audited.

## State

Workspace `.mail-triage/`: `config.json`, `state.json` (cursors), `labels.jsonl`,
`verdicts.jsonl`, `audit.jsonl`, `manifests/`, `reports/`. Plain text, yours to
inspect or delete.

## Development

```bash
npm test    # offline smoke tests: rules, decision matrix, schema validation, decoding, store, report
```

## Known limitations

- If a Gmail account's Thunderbird Google grant cannot be refreshed, store a
  16-character app password with `set_secret`.
- Non-UTF-8 bodies (e.g. windows-1256) render as mojibake in snippets;
  classification still works, the summary text is just ugly.
- When a header block exceeds 8 KB (long DKIM/ARC chains) the body is fetched a
  second time; if it is still unavailable the snippet stays empty.
- If a Thunderbird OAuth grant has expired, the plugin reports it honestly:
  sign in again in Thunderbird, then re-run `import_thunderbird`.
- Only INBOX is scanned by default (configurable); sub-folders are not expanded.

## Development note

After editing plugin code the Host still holds the previous module instance:
toggle the plugin off and on in the Plugins panel to load the new code (no full
restart needed).

## License

MIT © 2026 wth373737

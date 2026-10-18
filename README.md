# Clearbox

**A privacy guard for Claude Code. Your secrets stay yours, and you can see everything Claude touched.**

Claude Code is great at working in your project. It is also very good at finding your `.env`
file, reading it, and repeating your API keys back into the conversation. Clearbox sits between
Claude and your files and stops that, without getting in the way of normal work.

## What it does

- **Knows the name, never the value.** When Claude tries to read a protected `.env` file, Clearbox
  blocks the read and tells Claude which variables exist (`STRIPE_SECRET_KEY`, `DATABASE_URL`, ...)
  but not their values. Claude keeps coding with `process.env.STRIPE_SECRET_KEY` and never sees the key.
- **Hides secrets that leak anyway.** If a secret value shows up in a command's output, a search
  result or a file Claude reads, Clearbox replaces it with `[hidden by Clearbox]` before Claude sees it.
  It also catches well-known key formats (OpenAI, Anthropic, Stripe, GitHub, Slack, AWS, Google, private keys).
- **Blocks commands that would spill secrets.** `cat .env`, `Get-Content .env`, `cp .env ...`,
  `git add .env`, `printenv`, `env | grep ...` and similar are stopped before they run.
- **Protects you from the first second.** When a session starts, Clearbox scans the project and tells
  you which sensitive files it is protecting. No setup needed.
- **Gives you a privacy receipt.** `/clearbox:receipt` lists what Claude read, changed and ran in the
  session, and what Clearbox blocked or hid. `/clearbox:check` shows which files are hidden from Claude.

## Privacy

- **No network.** Clearbox makes no outbound connections of any kind.
- **No telemetry.** It collects nothing about you and sends nothing anywhere.
- **Local audit log only.** The receipt is built from a log kept on your computer, in the plugin's
  data folder. It stores file paths and commands (with secret values removed), never file contents
  or tool output. Logs older than 30 days are deleted automatically.
- **Readable.** The whole plugin is one small JavaScript file with no dependencies. Read it.

## What is protected by default

`.env`, `.env.*`, `*.env`, private keys (`*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`,
`*.ppk`, `id_rsa`, `id_ed25519`, ...), `~/.ssh`, `~/.aws`, `~/.azure`, `~/.gnupg`, gcloud and kube
configs, Docker credentials, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `credentials.json`,
service-account JSON files and Terraform state and variable files.

Templates and public keys stay visible: `*.example`, `*.sample`, `*.template`, `*.dist`, `*.pub`.

## Customize

Add a `.clearbox` file to your project root, one pattern per line (same style as `.gitignore`):

```text
# protect more
notes/private/**
C:/Users/me/Documents/finance/**

# allow something that is protected by default
!.env.test
```

## Install

Requires **Node.js 18 or newer** (Clearbox's hooks run with `node`).

From this repository:

```text
/plugin marketplace add Digital-Technology/clearbox
/plugin install clearbox@clearbox
```

Start a new session after installing. You should see a message saying how many sensitive files
Clearbox is protecting.

## Limits (please read)

Clearbox is a guard, not a sandbox. It is honest about what it cannot do:

- It protects what goes **through Claude's tools**. Programs you or Claude run (your app, your tests)
  can still read `.env` themselves. That is usually what you want.
- Shell command checks are **best effort**. A command that builds a file name in a way Clearbox
  cannot read (for example from variables) can slip through. Value hiding in the output is the
  second line of defence for those cases.
- Values are hidden when Clearbox knows them (from your protected `.env` files) or recognises their
  format. A secret it has never seen, in a format it does not know, cannot be hidden.
- When a hidden value appears in a file Claude is editing, Claude sees the marker instead of the
  value, so it may need you to make that specific edit yourself.
- It runs where Claude Code plugin hooks run: **Claude Code** and **Cowork**. Not in claude.ai chat.
- If Node.js is not installed, the hooks cannot run and nothing is protected.

## Platform support

Built and tested on **Windows first** (including PowerShell commands and Git Bash paths), where
Claude Code has no native sandbox. macOS and Linux use the same code and are covered by the same tests.

## Tests

```bash
node --test
```

## License

[MIT](./LICENSE)

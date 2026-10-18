#!/usr/bin/env node
/**
 * Clearbox: a privacy guard and audit trail for Claude Code.
 *
 * What this file does, and nothing else:
 *   session-start  scan the project for sensitive files, tell the user what is protected
 *   pre            before a tool runs: block reads/changes of protected files and
 *                  shell commands that would print them (dotenv files: share names, never values)
 *   post           after a tool runs: replace secret values in the output with a marker,
 *                  and append a line to the local audit log
 *   receipt        print what Claude read, changed and ran in the latest session
 *   check          print which files in this project are protected
 *
 * Promises enforced here: no network calls, no telemetry, no dependencies.
 * The audit log stays on this machine, stores paths and commands (with secret
 * values removed), never file contents or tool output, and is pruned after 30 days.
 */
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");

const IS_WIN = process.platform === "win32";
const MARK = "[hidden by Clearbox]";
const AUDIT_RETENTION_DAYS = 30;

// --- Policy ----------------------------------------------------------------

/** Files Clearbox protects out of the box. Same syntax as a .clearbox file. */
const DEFAULT_RULES = [
  ".env", ".env.*", "*.env",
  "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.ppk",
  "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
  "**/.ssh/**", "**/.aws/**", "**/.azure/**", "**/.gnupg/**",
  "**/.config/gcloud/**", "**/.kube/config", "**/.docker/config.json",
  ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials",
  "credentials.json", "service-account*.json",
  "*.tfstate", "*.tfstate.*", "*.tfvars",
];

/** Never protected: templates and public keys are meant to be shared. */
const DEFAULT_ALLOW = ["*.example", "*.sample", "*.template", "*.dist", "*.pub"];

/** Folders skipped when scanning a project (large, generated, never secret sources). */
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".hg", ".svn", ".venv", "venv", "__pycache__",
  ".next", ".nuxt", ".turbo", ".cache", "dist", "build", "target", "vendor",
]);

function toSlash(p) {
  return String(p).replace(/\\/g, "/");
}

/** Git Bash style "/c/Users/x" becomes "c:/Users/x" on Windows. */
function fromPosixDrive(p) {
  if (IS_WIN) {
    const m = /^\/([a-zA-Z])\/(.*)$/.exec(p);
    if (m) return `${m[1]}:/${m[2]}`;
  }
  return p;
}

function expandHome(p) {
  if (p === "~") return os.homedir();
  if (p.startsWith("~/") || p.startsWith("~\\")) return path.join(os.homedir(), p.slice(2));
  return p;
}

function isAbsoluteLike(p) {
  return /^([a-zA-Z]:)?\//.test(toSlash(p));
}

function globToRegExp(glob) {
  let re = "";
  for (let i = 0; i < glob.length; ) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        if (glob[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 3;
        } else {
          re += ".*";
          i += 2;
        }
        continue;
      }
      re += "[^/]*";
      i++;
      continue;
    }
    if (c === "?") {
      re += "[^/]";
      i++;
      continue;
    }
    re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    i++;
  }
  return new RegExp(`^${re}$`, IS_WIN ? "i" : "");
}

function compileRule(raw) {
  let pattern = raw.trim();
  if (pattern.endsWith("/")) pattern += "**";
  pattern = toSlash(expandHome(pattern));
  const absolute = isAbsoluteLike(pattern);
  const hasSlash = pattern.includes("/");
  return { raw: raw.trim(), absolute, basenameOnly: !hasSlash, re: globToRegExp(pattern) };
}

/** Defaults plus the project's optional .clearbox file ("!" un-protects, "#" comments). */
function loadPolicy(projectDir) {
  const protect = DEFAULT_RULES.map(compileRule);
  const allow = DEFAULT_ALLOW.map(compileRule);
  const file = path.join(projectDir, ".clearbox");
  let custom = false;
  try {
    for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      custom = true;
      if (t.startsWith("!")) allow.push(compileRule(t.slice(1)));
      else protect.push(compileRule(t));
    }
  } catch {
    // no .clearbox file: defaults only
  }
  return { protect, allow, custom };
}

function ruleMatches(rule, absPath, relPath) {
  if (rule.basenameOnly) return rule.re.test(path.posix.basename(absPath));
  if (rule.absolute || rule.raw.startsWith("**/")) return rule.re.test(absPath);
  return relPath !== null && rule.re.test(relPath);
}

/** Returns the rule that protects this path, or null. */
function protectingRule(target, policy, projectDir) {
  const abs = toSlash(path.resolve(fromPosixDrive(toSlash(expandHome(target)))));
  const rel = toSlash(path.relative(projectDir, abs));
  const relPath = rel.startsWith("..") || isAbsoluteLike(rel) ? null : rel;
  if (policy.allow.some((r) => ruleMatches(r, abs, relPath))) return null;
  const hit = policy.protect.find((r) => ruleMatches(r, abs, relPath));
  return hit ? hit.raw : null;
}

function displayPath(target, projectDir) {
  const abs = path.resolve(fromPosixDrive(toSlash(expandHome(target))));
  const rel = path.relative(projectDir, abs);
  return toSlash(rel && !rel.startsWith("..") && !path.isAbsolute(rel) ? rel : abs);
}

// --- Dotenv and secret values ------------------------------------------------

function isDotenv(file) {
  const b = path.basename(file).toLowerCase();
  return b === ".env" || b.startsWith(".env.") || b.endsWith(".env");
}

const ENV_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/;
const SECRET_NAME = /(KEY|SECRET|TOKEN|PASS|PWD|AUTH|CREDENTIAL|PRIVATE|SIGNATURE|SALT|DSN|DATABASE_URL|CONNECTION|_URI$|_URL$)/i;

function parseDotenv(content) {
  const entries = [];
  for (const line of content.split(/\r?\n/)) {
    const m = ENV_LINE.exec(line);
    if (!m) continue;
    let value = m[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    } else {
      value = value.replace(/\s+#.*$/, "");
    }
    entries.push({ name: m[1], value });
  }
  return entries;
}

function charClasses(v) {
  return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(v)).length;
}

/** A value is treated as secret if its name says so, or if it looks like a random token. */
function isSecretValue(name, value) {
  if (!value || value.length < 6) return false;
  if (/^(true|false|null|none|yes|no|localhost|development|production|test|staging)$/i.test(value)) return false;
  if (SECRET_NAME.test(name)) return true;
  return value.length >= 16 && charClasses(value) >= 3;
}

/** Well-known credential formats, hidden wherever they appear. */
const TOKEN_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}/g,
  /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{30,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{30,}/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
];

function redactText(text, values) {
  let count = 0;
  let out = text;
  for (const v of values) {
    if (out.includes(v)) {
      count += out.split(v).length - 1;
      out = out.split(v).join(MARK);
    }
  }
  for (const re of TOKEN_PATTERNS) {
    out = out.replace(re, () => {
      count++;
      return MARK;
    });
  }
  return { text: out, count };
}

/** Walk any JSON value, redacting every string, keeping the exact shape. */
function redactDeep(value, values) {
  let total = 0;
  const walk = (v) => {
    if (typeof v === "string") {
      const r = redactText(v, values);
      total += r.count;
      return r.text;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      const o = {};
      for (const [k, x] of Object.entries(v)) o[k] = walk(x);
      return o;
    }
    return v;
  };
  return { value: walk(value), count: total };
}

// --- Project scan and cache ----------------------------------------------------

function scanProject(projectDir, policy, limit = 20000) {
  const found = [];
  let seen = 0;
  const walk = (dir, depth) => {
    if (depth > 6 || seen > limit) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (++seen > limit) return;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) walk(full, depth + 1);
      } else if (e.isFile() && protectingRule(full, policy, projectDir)) {
        found.push(full);
      }
    }
  };
  walk(projectDir, 0);
  return found;
}

function dataDir() {
  const base = process.env.CLAUDE_PLUGIN_DATA || path.join(os.homedir(), ".clearbox");
  return base;
}

function ensureDir(d) {
  fs.mkdirSync(d, { recursive: true });
  return d;
}

function cacheFile(projectDir) {
  const h = crypto.createHash("sha1").update(toSlash(projectDir).toLowerCase()).digest("hex").slice(0, 16);
  return path.join(ensureDir(path.join(dataDir(), "cache")), `${h}.json`);
}

function protectedFiles(projectDir, policy, fresh = false) {
  const file = cacheFile(projectDir);
  if (!fresh) {
    try {
      const c = JSON.parse(fs.readFileSync(file, "utf8"));
      if (Date.now() - c.at < 10 * 60 * 1000) return c.files;
    } catch {
      // no cache yet
    }
  }
  const files = scanProject(projectDir, policy);
  try {
    fs.writeFileSync(file, JSON.stringify({ at: Date.now(), files }));
  } catch {
    // cache is an optimisation only
  }
  return files;
}

function secretValues(projectDir, policy) {
  const values = new Set();
  for (const f of protectedFiles(projectDir, policy)) {
    if (!isDotenv(f)) continue;
    try {
      for (const { name, value } of parseDotenv(fs.readFileSync(f, "utf8"))) {
        if (isSecretValue(name, value)) values.add(value);
      }
    } catch {
      // unreadable file: nothing to hide from it
    }
  }
  // Longest first, so a value that contains another is hidden whole.
  return [...values].sort((a, b) => b.length - a.length);
}

// --- Audit log ---------------------------------------------------------------

function auditDir() {
  return ensureDir(path.join(dataDir(), "audit"));
}

function audit(sessionId, entry) {
  try {
    const safeId = String(sessionId || "unknown").replace(/[^A-Za-z0-9_-]/g, "");
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry });
    fs.appendFileSync(path.join(auditDir(), `${safeId}.jsonl`), line + "\n");
  } catch {
    // auditing must never break the user's session
  }
}

function pruneAudit() {
  try {
    const cutoff = Date.now() - AUDIT_RETENTION_DAYS * 24 * 3600 * 1000;
    for (const f of fs.readdirSync(auditDir())) {
      const p = path.join(auditDir(), f);
      if (fs.statSync(p).mtimeMs < cutoff) fs.unlinkSync(p);
    }
  } catch {
    // best effort
  }
}

// --- Tool inspection -----------------------------------------------------------

const FILE_TOOLS = new Set(["Read", "Edit", "Write", "MultiEdit", "NotebookEdit", "NotebookRead"]);
const CHANGE_TOOLS = new Set(["Edit", "Write", "MultiEdit", "NotebookEdit"]);

/** Shell commands that print every environment variable (which may hold loaded secrets). */
const ENV_DUMP =
  /(^|[;&|(]\s*)(printenv|env|set|export\s+-p|(?:get-childitem|gci|dir|ls)\s+env:\\?)\s*($|[;&|)])/i;

function bashFindings(command, cwd, policy, projectDir) {
  if (ENV_DUMP.test(command)) return { what: "environment variables", rule: "environment dump" };
  const tokens = command.split(/[\s'"`<>|;&()=,]+/).filter((t) => t && !t.startsWith("-"));
  for (const t of tokens) {
    const candidate = t.startsWith("~") || path.isAbsolute(fromPosixDrive(t)) ? t : path.join(cwd, t);
    const rule = protectingRule(candidate, policy, projectDir);
    if (rule) return { what: displayPath(candidate, projectDir), rule };
  }
  return null;
}

function targetOf(toolName, input) {
  if (FILE_TOOLS.has(toolName)) return input.file_path || input.notebook_path || null;
  if (toolName === "Grep" || toolName === "Glob") return input.path || null;
  return null;
}

function summarize(toolName, input, projectDir, values) {
  const t = targetOf(toolName, input);
  if (t) return displayPath(t, projectDir);
  if (toolName === "Bash") return redactText(String(input.command || ""), values).text.slice(0, 200);
  if (toolName === "Grep" || toolName === "Glob") return String(input.pattern || "").slice(0, 120);
  if (toolName === "WebFetch") return String(input.url || "").slice(0, 200);
  if (toolName === "WebSearch") return String(input.query || "").slice(0, 120);
  return "";
}

// --- Hook handlers -------------------------------------------------------------

function projectDirOf(input) {
  return path.resolve(process.env.CLAUDE_PROJECT_DIR || input.cwd || process.cwd());
}

function emit(obj) {
  process.stdout.write(JSON.stringify(obj));
}

function onSessionStart(input) {
  const projectDir = projectDirOf(input);
  const policy = loadPolicy(projectDir);
  pruneAudit();
  const files = protectedFiles(projectDir, policy, true);
  const names = files.map((f) => displayPath(f, projectDir));
  audit(input.session_id, { ev: "start", project: toSlash(projectDir), protected: names.length });

  const list = names.length ? `: ${names.slice(0, 5).join(", ")}${names.length > 5 ? ", ..." : ""}` : "";
  emit({
    systemMessage:
      `Clearbox is protecting ${names.length} sensitive file${names.length === 1 ? "" : "s"} in this project${list}. ` +
      "Nothing leaves your machine.",
    hookSpecificOutput: {
      hookEventName: "SessionStart",
      additionalContext:
        "Clearbox, a local privacy plugin installed by the user, is active in this session. " +
        "Files covered by the user's privacy policy (such as .env files and private keys) are not readable through Claude's tools. " +
        "When a dotenv file is protected, Clearbox reports its variable names but not their values, so code can reference them by name. " +
        `Secret values that appear in tool output are replaced with ${MARK}.`,
    },
  });
}

function deny(reason, userNote) {
  emit({
    systemMessage: userNote,
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  });
}

function onPre(input) {
  const tool = input.tool_name;
  const ti = input.tool_input || {};
  const projectDir = projectDirOf(input);
  const cwd = path.resolve(input.cwd || projectDir);
  const policy = loadPolicy(projectDir);

  const target = targetOf(tool, ti);
  if (target && tool !== "Glob") {
    const abs = path.resolve(cwd, fromPosixDrive(toSlash(expandHome(target))));
    let isDir = false;
    try {
      isDir = fs.statSync(abs).isDirectory();
    } catch {
      // a file that does not exist yet is checked by name
    }
    const rule = isDir ? null : protectingRule(abs, policy, projectDir);
    if (rule) {
      const shown = displayPath(abs, projectDir);
      audit(input.session_id, { ev: "blocked", tool, target: shown, rule });
      if (CHANGE_TOOLS.has(tool)) {
        return deny(
          `Clearbox blocked changing ${shown}: it is protected by the user's privacy policy (rule "${rule}"). ` +
            "The user can edit this file themselves.",
          `Clearbox blocked Claude from changing ${shown}.`
        );
      }
      if (isDotenv(abs)) {
        let names = [];
        try {
          names = parseDotenv(fs.readFileSync(abs, "utf8")).map((e) => e.name);
        } catch {
          // unreadable: no names to share
        }
        const listed = names.length ? names.join(", ") : "(none found)";
        return deny(
          `Clearbox blocked reading ${shown}: it is protected by the user's privacy policy. ` +
            `It defines these variables (values hidden): ${listed}. ` +
            "Code can reference them by name, for example process.env.NAME or os.environ['NAME']. " +
            `To allow reading it, the user can add "!${shown}" to a .clearbox file in the project.`,
          `Clearbox blocked Claude from reading ${shown} (variable names shared, values hidden).`
        );
      }
      return deny(
        `Clearbox blocked reading ${shown}: it is protected by the user's privacy policy (rule "${rule}"). ` +
          `To allow it, the user can add "!${shown}" to a .clearbox file in the project.`,
        `Clearbox blocked Claude from reading ${shown}.`
      );
    }
  }

  if (tool === "Bash" && typeof ti.command === "string") {
    const hit = bashFindings(ti.command, cwd, policy, projectDir);
    if (hit) {
      const values = secretValues(projectDir, policy);
      audit(input.session_id, {
        ev: "blocked",
        tool,
        target: redactText(ti.command, values).text.slice(0, 200),
        rule: hit.rule,
      });
      return deny(
        `Clearbox blocked this command because it would expose ${hit.what}, which the user's privacy policy protects. ` +
          "If a secret is needed, reference it by its variable name instead of reading its value.",
        `Clearbox blocked a command that would expose ${hit.what}.`
      );
    }
  }
  // Not protected: say nothing and let the normal permission flow decide.
}

function onPost(input) {
  const tool = input.tool_name;
  const ti = input.tool_input || {};
  const projectDir = projectDirOf(input);
  const policy = loadPolicy(projectDir);
  const values = secretValues(projectDir, policy);

  let hidden = 0;
  if (input.tool_response !== undefined) {
    const r = redactDeep(input.tool_response, values);
    hidden = r.count;
    if (hidden > 0) {
      emit({
        systemMessage: `Clearbox hid ${hidden} secret value${hidden === 1 ? "" : "s"} from Claude.`,
        hookSpecificOutput: {
          hookEventName: "PostToolUse",
          updatedToolOutput: r.value,
          additionalContext: `Clearbox replaced ${hidden} secret value${hidden === 1 ? "" : "s"} in this output with ${MARK}.`,
        },
      });
    }
  }
  audit(input.session_id, { ev: "done", tool, target: summarize(tool, ti, projectDir, values), hidden });
}

// --- Commands ------------------------------------------------------------------

function latestAuditFile() {
  const files = fs
    .readdirSync(auditDir())
    .filter((f) => f.endsWith(".jsonl"))
    .map((f) => ({ f, t: fs.statSync(path.join(auditDir(), f)).mtimeMs }))
    .sort((a, b) => b.t - a.t);
  return files.length ? path.join(auditDir(), files[0].f) : null;
}

function sessionAuditFile(sessionId) {
  const safeId = String(sessionId).replace(/[^A-Za-z0-9_-]/g, "");
  const file = path.join(auditDir(), `${safeId}.jsonl`);
  return fs.existsSync(file) ? file : null;
}

function receipt(sessionId) {
  const file = sessionId ? sessionAuditFile(sessionId) : latestAuditFile();
  if (!file) {
    console.log("Clearbox has nothing recorded for this session yet.");
    return;
  }
  const rows = fs
    .readFileSync(file, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  const uniq = (xs) => [...new Set(xs.filter(Boolean))];
  const done = rows.filter((r) => r.ev === "done");
  const read = uniq(done.filter((r) => r.tool === "Read" || r.tool === "NotebookRead").map((r) => r.target));
  const changed = uniq(done.filter((r) => CHANGE_TOOLS.has(r.tool)).map((r) => r.target));
  const ran = done.filter((r) => r.tool === "Bash").map((r) => r.target);
  const searched = done.filter((r) => r.tool === "Grep" || r.tool === "Glob").length;
  const web = uniq(done.filter((r) => r.tool === "WebFetch" || r.tool === "WebSearch").map((r) => r.target));
  const blocked = rows.filter((r) => r.ev === "blocked");
  const hidden = done.reduce((n, r) => n + (r.hidden || 0), 0);
  const start = rows.find((r) => r.ev === "start");

  const out = [];
  out.push("# Clearbox privacy receipt");
  out.push("");
  out.push(`Session started: ${new Date(start ? start.ts : rows[0].ts).toLocaleString()}`);
  if (start) out.push(`Project: ${start.project}`);
  out.push("");
  out.push(`- Protected by Clearbox: ${blocked.length} blocked action(s), ${hidden} secret value(s) hidden from output`);
  out.push(`- Files read: ${read.length}`);
  out.push(`- Files changed: ${changed.length}`);
  out.push(`- Commands run: ${ran.length}`);
  out.push(`- Searches: ${searched}`);
  out.push(`- Web requests: ${web.length}`);
  const section = (title, items) => {
    if (!items.length) return;
    out.push("", `## ${title}`);
    for (const i of items.slice(0, 50)) out.push(`- ${i}`);
    if (items.length > 50) out.push(`- ... and ${items.length - 50} more`);
  };
  section("Blocked by Clearbox", blocked.map((b) => `${b.tool}: ${b.target} (rule: ${b.rule})`));
  section("Files read", read);
  section("Files changed", changed);
  section("Commands run", ran);
  section("Web", web);
  out.push("", "Recorded only on this computer. No file contents or outputs are stored.");
  console.log(out.join("\n"));
}

function check(projectDirArg) {
  const projectDir = path.resolve(projectDirArg || process.env.CLAUDE_PROJECT_DIR || process.cwd());
  const policy = loadPolicy(projectDir);
  const files = protectedFiles(projectDir, policy, true).map((f) => displayPath(f, projectDir));
  const out = ["# What Claude can see", "", `Project: ${toSlash(projectDir)}`, ""];
  if (files.length) {
    out.push(`Protected (hidden from Claude's tools): ${files.length}`);
    for (const f of files.slice(0, 100)) out.push(`- ${f}`);
  } else {
    out.push("No sensitive files found in this project.");
  }
  out.push("");
  out.push(
    `Rules: ${DEFAULT_RULES.length} built in${policy.custom ? ", plus your .clearbox file" : " (add a .clearbox file to protect more, or \"!path\" to allow one)"}.`
  );
  out.push("Also protected anywhere on disk: ~/.ssh, ~/.aws, ~/.azure, ~/.gnupg, cloud and package-registry credentials.");
  out.push("Everything else is visible to Claude as usual.");
  console.log(out.join("\n"));
}

// --- Entry point ---------------------------------------------------------------

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", () => resolve(data));
  });
}

/** Command arguments come from ${...} substitutions; ignore any that were left unsubstituted. */
function arg(i) {
  const v = process.argv[i];
  return v && !v.includes("${") ? v : "";
}

async function main() {
  const mode = process.argv[2];
  if (mode === "receipt" || mode === "check") {
    // receipt <session-id> <data-dir> | check <project-dir> <data-dir>
    if (arg(4) && !process.env.CLAUDE_PLUGIN_DATA) process.env.CLAUDE_PLUGIN_DATA = arg(4);
    return mode === "receipt" ? receipt(arg(3)) : check(arg(3));
  }

  const raw = await readStdin();
  let input = {};
  try {
    input = raw ? JSON.parse(raw) : {};
  } catch {
    return; // malformed input: do nothing rather than break the session
  }
  if (mode === "session-start") return onSessionStart(input);
  if (mode === "pre") return onPre(input);
  if (mode === "post") return onPost(input);
}

main().catch((err) => {
  process.stderr.write(`clearbox: ${err && err.message ? err.message : String(err)}\n`);
  process.exit(1); // non-blocking error: the session continues
});

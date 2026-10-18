// Clearbox test suite. Run from the repository root with: node --test
// Uses only Node's built-in test runner. Creates a throwaway project in the OS temp folder.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const SCRIPT = path.join(__dirname, "..", "scripts", "clearbox.js");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "clearbox-test-"));
const project = path.join(root, "project");
const data = path.join(root, "data");

const STRIPE = "sk_live_abc123def456ghi789";
const DB_URL = "postgres://app:p4ssw0rd@db:5432/shop";

function write(rel, content) {
  const f = path.join(project, rel);
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, content);
  return f;
}

write(".env", `STRIPE_SECRET_KEY=${STRIPE}\nDATABASE_URL="${DB_URL}"\nPORT=3000\nDB_HOST=localhost\n`);
write(".env.example", "STRIPE_SECRET_KEY=\nDATABASE_URL=\n");
write("config/app.js", "module.exports = { port: process.env.PORT };\n");
write("keys/server.pem", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n");
write("keys/id_rsa.pub", "ssh-ed25519 AAAA public\n");
write("node_modules/pkg/.env", "IGNORED=1\n");

function run(mode, input, extraEnv = {}) {
  const r = spawnSync(process.execPath, [SCRIPT, mode], {
    input: input === undefined ? "" : typeof input === "string" ? input : JSON.stringify(input),
    encoding: "utf8",
    env: { ...process.env, CLAUDE_PLUGIN_DATA: data, CLAUDE_PROJECT_DIR: project, ...extraEnv },
  });
  assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
  return r.stdout ? JSON.parse(r.stdout) : null;
}

/** Runs a command the way the plugin's slash commands do: values passed as arguments, not env. */
function runText(mode, args = []) {
  const env = { ...process.env };
  delete env.CLAUDE_PLUGIN_DATA;
  delete env.CLAUDE_PROJECT_DIR;
  const r = spawnSync(process.execPath, [SCRIPT, mode, ...args], { encoding: "utf8", env });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout;
}

const pre = (tool_name, tool_input) =>
  run("pre", { session_id: "s1", cwd: project, hook_event_name: "PreToolUse", tool_name, tool_input });
const decision = (out) => out && out.hookSpecificOutput && out.hookSpecificOutput.permissionDecision;
const reason = (out) => out.hookSpecificOutput.permissionDecisionReason;

test("session start finds the sensitive files and skips templates, public keys and node_modules", () => {
  const out = run("session-start", { session_id: "s1", cwd: project, source: "startup" });
  assert.match(out.systemMessage, /protecting 2 sensitive files/);
  assert.match(out.systemMessage, /\.env/);
  assert.match(out.systemMessage, /server\.pem/);
  assert.doesNotMatch(out.systemMessage, /example|id_rsa\.pub|node_modules/);
  assert.equal(out.hookSpecificOutput.hookEventName, "SessionStart");
});

test("reading .env is blocked, but the variable names are shared and the values are not", () => {
  const out = pre("Read", { file_path: path.join(project, ".env") });
  assert.equal(decision(out), "deny");
  for (const name of ["STRIPE_SECRET_KEY", "DATABASE_URL", "PORT", "DB_HOST"]) assert.match(reason(out), new RegExp(name));
  assert.ok(!reason(out).includes(STRIPE));
  assert.ok(!reason(out).includes("p4ssw0rd"));
});

test("templates and normal files are not touched", () => {
  assert.equal(pre("Read", { file_path: path.join(project, ".env.example") }), null);
  assert.equal(pre("Read", { file_path: path.join(project, "config/app.js") }), null);
  assert.equal(pre("Read", { file_path: path.join(project, "keys/id_rsa.pub") }), null);
});

test("private keys and edits to protected files are blocked", () => {
  assert.equal(decision(pre("Read", { file_path: path.join(project, "keys/server.pem") })), "deny");
  const edit = pre("Edit", { file_path: path.join(project, ".env"), old_string: "a", new_string: "b" });
  assert.equal(decision(edit), "deny");
  assert.match(reason(edit), /blocked changing/);
});

test("Windows backslash paths and Git Bash drive paths are recognised", () => {
  assert.equal(decision(pre("Read", { file_path: path.join(project, ".env").replace(/\//g, "\\") })), "deny");
  if (process.platform === "win32") {
    const posix = "/" + project[0].toLowerCase() + project.slice(2).replace(/\\/g, "/") + "/.env";
    assert.equal(decision(pre("Bash", { command: `cat ${posix}` })), "deny");
  }
});

test("shell commands that would print secrets are blocked", () => {
  for (const command of [
    "cat .env",
    "type .env",
    "Get-Content .env",
    "source .env && npm start",
    "cp .env backup.txt",
    "git add .env",
    "cat ~/.ssh/id_rsa",
    "printenv",
    "env | grep KEY",
    "export -p",
    "Get-ChildItem env:",
  ]) {
    assert.equal(decision(pre("Bash", { command })), "deny", command);
  }
});

test("ordinary shell commands are allowed", () => {
  for (const command of ["npm test", "NODE_ENV=production node app.js", "cross-env NODE_ENV=x node a.js", "git status", "set -e", "ls keys"]) {
    assert.equal(pre("Bash", { command }), null, command);
  }
});

test("grep on a protected file is blocked, grep on a folder is allowed", () => {
  assert.equal(decision(pre("Grep", { pattern: "KEY", path: path.join(project, ".env") })), "deny");
  assert.equal(pre("Grep", { pattern: "KEY", path: project }), null);
});

test("secret values in tool output are hidden, harmless values stay, and the output shape is kept", () => {
  const tool_response = {
    stdout: `key=${STRIPE} db=${DB_URL} port=3000 host=localhost`,
    stderr: "",
    interrupted: false,
    isImage: false,
  };
  const out = run("post", { session_id: "s1", cwd: project, tool_name: "Bash", tool_input: { command: "x" }, tool_response });
  const updated = out.hookSpecificOutput.updatedToolOutput;
  assert.deepEqual(Object.keys(updated), Object.keys(tool_response));
  assert.ok(!updated.stdout.includes(STRIPE));
  assert.ok(!updated.stdout.includes("p4ssw0rd"));
  assert.match(updated.stdout, /\[hidden by Clearbox\]/);
  assert.match(updated.stdout, /port=3000 host=localhost/);
  assert.equal(updated.interrupted, false);
});

test("well-known token formats are hidden even when they are not in any .env", () => {
  const token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
  const out = run("post", {
    session_id: "s1",
    cwd: project,
    tool_name: "Read",
    tool_input: { file_path: path.join(project, "config/app.js") },
    tool_response: { file: { content: `const t = "${token}";` } },
  });
  assert.ok(!JSON.stringify(out.hookSpecificOutput.updatedToolOutput).includes(token));
});

test("clean output produces no change", () => {
  const out = run("post", {
    session_id: "s1",
    cwd: project,
    tool_name: "Bash",
    tool_input: { command: "echo hi" },
    tool_response: { stdout: "hi", stderr: "", interrupted: false, isImage: false },
  });
  assert.equal(out, null);
});

test("malformed input never breaks the session", () => {
  assert.equal(run("pre", "{not json"), null);
  assert.equal(run("post", ""), null);
});

test("the receipt for another session shows nothing from this one", () => {
  assert.match(runText("receipt", ["some-other-session", data]), /nothing recorded for this session/);
});

test("the receipt reports blocked actions and hidden values, without secret values", () => {
  const text = runText("receipt", ["s1", data]);
  assert.match(text, /Clearbox privacy receipt/);
  assert.match(text, /blocked action/);
  assert.match(text, /secret value\(s\) hidden/);
  assert.ok(!text.includes(STRIPE));
  assert.ok(!text.includes("p4ssw0rd"));
});

test("the audit log never contains secret values", () => {
  const dir = path.join(data, "audit");
  const all = fs.readdirSync(dir).map((f) => fs.readFileSync(path.join(dir, f), "utf8")).join("\n");
  assert.ok(all.length > 0);
  assert.ok(!all.includes(STRIPE));
  assert.ok(!all.includes("p4ssw0rd"));
});

test("check lists protected files", () => {
  const text = runText("check", [project, data]);
  assert.match(text, /Protected \(hidden from Claude's tools\): 2/);
});

test("a .clearbox file can protect more and allow exceptions", () => {
  write("notes/private.md", "my diary\n");
  write(".clearbox", "notes/**\n!.env\n");
  try {
    assert.equal(decision(pre("Read", { file_path: path.join(project, "notes/private.md") })), "deny");
    assert.equal(pre("Read", { file_path: path.join(project, ".env") }), null);
  } finally {
    fs.unlinkSync(path.join(project, ".clearbox"));
  }
});

test.after(() => fs.rmSync(root, { recursive: true, force: true }));

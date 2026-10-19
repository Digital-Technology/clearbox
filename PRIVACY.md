# Clearbox privacy policy

Clearbox is a local plugin for Claude Code. This page describes everything it does with data.

## Data collection

Clearbox collects no personal data and sends nothing anywhere. It contains no network code, no
analytics and no telemetry.

## What Clearbox reads, and why

- **File paths and commands** that Claude is about to use, to decide whether they touch a protected
  file.
- **Your protected `.env` files**, on your own computer, to learn the variable names (shared with
  Claude) and the secret values (only so Clearbox can recognise and hide them in tool output). Secret
  values are kept in memory for a single hook call and are never written to disk, logged or sent.

## What Clearbox stores

A local activity log, used to build the privacy receipt (`/clearbox:receipt`), kept in the plugin's
data folder on your computer. It contains file paths, tool names, commands with secret values removed,
and counts of blocked and hidden items. It never contains file contents or tool output.

Clearbox also keeps a short-lived local cache of which files in a project are protected (paths only).

## Sharing with third parties

None. Nothing leaves your computer.

## Retention

Activity logs older than 30 days are deleted automatically. You can delete the plugin's data folder at
any time; uninstalling the plugin stops all activity.

## Contact

Questions or concerns: open an issue at https://github.com/Digital-Technology/clearbox/issues

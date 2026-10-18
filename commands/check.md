---
description: Show which files in this project Clearbox keeps hidden from Claude, and what stays visible
allowed-tools: Bash(node:*)
---

!`node "${CLAUDE_PLUGIN_ROOT}/scripts/clearbox.js" check "${CLAUDE_PROJECT_DIR}" "${CLAUDE_PLUGIN_DATA}"`

Show the report above to the user, translated into the language they are using, keeping every path exactly as written.

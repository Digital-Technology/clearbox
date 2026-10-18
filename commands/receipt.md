---
description: Privacy receipt for this session, listing what Claude read, changed and ran, and what Clearbox blocked or hid
allowed-tools: Bash(node:*)
---

!`node "${CLAUDE_PLUGIN_ROOT}/scripts/clearbox.js" receipt "${CLAUDE_SESSION_ID}" "${CLAUDE_PLUGIN_DATA}"`

Show the receipt above to the user, translated into the language they are using, keeping every number and path exactly as written.

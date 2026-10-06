# ThunderSend MCP

A compose-only [MCP](https://modelcontextprotocol.io) server for Thunderbird and Betterbird.
An AI assistant connected through it can do exactly two things with your mailbox:

- **saveDraft** -- write a message to the Drafts folder.
- **sendMail** -- open a compose window for you to review and send (or, only if you
  explicitly disable the safety setting, send directly).

Two helper tools exist so a client can pick a sender identity: **listAccounts** and
**getAccountAccess**. That is the whole surface. There is no tool to read, search,
move, tag, delete, forward or reply to mail, and no contact, calendar, folder or
filter access. The code for those features was removed from the extension, not
merely hidden behind a flag.

ThunderSend is a minimal fork of
[TKasperczyk/thunderbird-mcp](https://github.com/TKasperczyk/thunderbird-mcp)
(MIT). The compose, draft, attachment-safety and authentication code is taken
verbatim from upstream v0.9.0; see `LICENSE`.

## How it works

```
MCP client (Claude, etc.)  <-- stdio -->  mcp-bridge.cjs  <-- HTTP 127.0.0.1 -->  ThunderSend extension
```

- The extension runs an HTTP server bound to `127.0.0.1` on port 8765 (or the next
  free port). Every request needs a `Bearer` token that is generated randomly on
  each start with the XPCOM random generator.
- Port and token are written to `<temp>/thundersend-mcp/connection.json` with
  mode 0600 and `O_EXCL`; the bridge reads that file. Nothing is sent anywhere else.
- The bridge and the extension each enforce a hard allow-list of the four tools.
- The manifest has **no `update_url`**: the add-on never fetches updates from a
  third-party server. Rebuild and reinstall to upgrade.

## Safety defaults

| Setting | Default | Effect |
| --- | --- | --- |
| Block `skipReview` | on | `sendMail` always opens a compose window; direct sends are rejected. |
| Account access | all | Restrict which accounts may be used as sender in the options page. |
| Listen on all interfaces | off | Keep off unless you need LAN access and understand the token travels in clear text. |

Attachments are subject to the same deny-list as upstream: credential stores,
SSH/GPG/cloud keys, browser and Thunderbird profile files, symlinks and junctions
are refused on both the bridge and the extension side.

## Install

1. Build the XPI:

   ```bash
   node scripts/build-xpi.cjs
   ```

2. In Thunderbird/Betterbird: Add-ons and Themes > gear icon > Install Add-on From File,
   pick `dist/thundersend-mcp.xpi`, then restart.
3. Add the bridge to your MCP client:

   ```json
   {
     "mcpServers": {
       "thundersend": {
         "command": "node",
         "args": ["C:\\git-local\\betterbird-mcp\\thundersend-mcp\\mcp-bridge.cjs"]
       }
     }
   }
   ```

Set `THUNDERBIRD_MCP_CONNECTION_FILE` if the bridge cannot find `connection.json`
automatically.

ThunderSend uses its own add-on id, preference branch and temp directory, so it can
be installed next to the full thunderbird-mcp add-on without the two interfering.

## Tools

### saveDraft

`to`, `subject`, `body`, `cc`, `bcc`, `isHtml`, `from`, `attachments`,
`inReplyTo`, `references`, `replaceMessageId` + `replaceFolderPath`, `includeSignature`.
All optional. Writes to the selected identity's Drafts folder and returns its URI.

### sendMail

`to`, `subject`, `body` required; `cc`, `bcc`, `isHtml`, `from`, `attachments`,
`skipReview`, `includeSignature` optional. With the default settings this opens a
compose window and returns immediately; the human presses Send.

### listAccounts / getAccountAccess

Read-only lists of accounts and identities the server is allowed to send from.

## Development

```bash
npm install
npm run lint
npm test
npm run build
```

Tests load production code by `// BEGIN ... // END` markers and run it in a VM
with Thunderbird services mocked, exactly as upstream does.

// XPCOM globals (ExtensionCommon, ChromeUtils, Services, Cc, Ci) are
// declared in eslint.config.mjs's extension/ file group. Per-file
// /* global */ comment triggered no-redeclare.
"use strict";

// BEGIN EXPERIMENT GLOBAL IMPORTS
// addon_parent is a sandbox, not a window or a system ES module. These names
// are supported by xpc::GlobalProperties in js/xpconnect/src/Sandbox.cpp.
try {
  Cu.importGlobalProperties(["DOMParser", "atob", "TextDecoder"]);
} catch (e) {
  console.warn("thundersend-mcp: failed to import Experiment globals:", e);
}
// END EXPERIMENT GLOBAL IMPORTS

/**
 * ThunderSend MCP (compose-only fork of TKasperczyk/thunderbird-mcp)
 * Exposes exactly four MCP tools over HTTP: listAccounts, getAccountAccess,
 * sendMail and saveDraft. All mailbox read, delete, folder, filter, contact
 * and calendar code from upstream has been removed, not just hidden.
 *
 * Architecture: MCP Client <-> mcp-bridge.cjs (stdio<->HTTP) <-> This extension (port 8765)
 *
 * Key quirks documented inline:
 * - MIME header decoding (mime2Decoded* properties)
 * - HTML body charset handling (emojis require HTML entity encoding)
 * - Compose window body preservation (must use New type, not Reply)
 * - IMAP folder sync (msgDatabase may be stale)
 */

const resProto = Cc[
  "@mozilla.org/network/protocol;1?name=resource"
].getService(Ci.nsISubstitutingProtocolHandler);

const MCP_DEFAULT_PORT = 8765;
const MCP_MAX_PORT_ATTEMPTS = 10;
const CONNECTION_FILE_REFRESH_MS = 30 * 1000;

// Versions of the MCP protocol this server understands. Behavior never depends
// on the negotiated version inside Thunderbird (the bridge intercepts initialize
// for clients), but for the rare case a client talks directly to the HTTP server
// we still need a spec-compliant negotiated value. Keep in sync with mcp-bridge.cjs.
const MCP_SUPPORTED_PROTOCOL_VERSIONS = new Set([
  "2024-10-07",
  "2024-11-05",
  "2025-03-26",
  "2025-06-18",
  "2025-11-25",
]);
const MCP_LATEST_PROTOCOL_VERSION = "2025-11-25";

// Bridged into serverInfo.version on initialize. Resolved lazily from the
// extension manifest so a single bump in extension/manifest.json propagates here.
let _cachedExtVersion = null;
function isListenAllEnabled() {
  try { return Services.prefs.getBoolPref(PREF_LISTEN_ALL, false); } catch { return false; }
}

// BEGIN CONNECTION INFO REFRESH HELPERS
function stopConnectionInfoRefreshTimer() {
  if (globalThis.__tbMcpConnectionInfoRefreshTimer) {
    try {
      globalThis.__tbMcpConnectionInfoRefreshTimer.cancel();
    } catch (e) {
      console.warn("thundersend-mcp: failed to stop connection info refresh timer:", e);
    }
    globalThis.__tbMcpConnectionInfoRefreshTimer = null;
  }
}

function ensureFreshConnectionInfo({
  port,
  token,
  expectedPid,
  readConnectionInfo,
  writeConnectionInfo,
  onCheckError,
}) {
  try {
    const current = readConnectionInfo();
    const data = current && current.data;
    if (
      data &&
      data.port === port &&
      data.token === token &&
      data.pid === expectedPid
    ) {
      return current.path;
    }
  } catch (e) {
    if (typeof onCheckError === "function") {
      onCheckError(e);
    }
  }
  return writeConnectionInfo(port, token);
}
// END CONNECTION INFO REFRESH HELPERS
function getExtVersion() {
  if (_cachedExtVersion) return _cachedExtVersion;
  try {
    const uri = Services.io.newURI("resource://thundersend-mcp/manifest.json");
    const channel = Services.io.newChannelFromURI(uri, null,
      Services.scriptSecurityManager.getSystemPrincipal(), null,
      Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
      Ci.nsIContentPolicy.TYPE_OTHER);
    const sis = Cc["@mozilla.org/scriptableinputstream;1"]
      .createInstance(Ci.nsIScriptableInputStream);
    sis.init(channel.open());
    const text = sis.read(sis.available());
    sis.close();
    _cachedExtVersion = JSON.parse(text).version || "0.0.0";
  } catch (e) {
    console.warn("thundersend-mcp: could not read extension manifest version:", e);
    _cachedExtVersion = "0.0.0";
  }
  return _cachedExtVersion;
}
// Track temp files created for inline base64 attachments (cleaned up on shutdown).
const _tempAttachFiles = new Set();
// BEGIN INLINE ATTACHMENT BASE64 HELPERS
// Require canonical RFC 4648 base64: complete quartets with padding only in
// the final quartet. In particular, do not silently discard invalid bytes.
// Character-class-only pattern: a group quantifier like (?:[...]{4})* pushes a
// backtrack frame per quartet, and SpiderMonkey throws "InternalError: too
// much recursion" once the input exceeds a few hundred KB — which any real
// attachment does. Quartet alignment is enforced by the length % 4 check.
const STRICT_BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
function isValidBase64(value) {
  return typeof value === "string"
    && value.length > 0
    && value.length % 4 === 0
    && STRICT_BASE64_PATTERN.test(value);
}
// END INLINE ATTACHMENT BASE64 HELPERS
// BEGIN OUTBOUND ATTACHMENT LIMITS
const MAX_BASE64_SIZE = 25 * 1024 * 1024; // 25 MB limit for inline base64 data (encoded)
// Cap file-path attachments to the same magnitude as saved-message attachments.
// Prevents an MCP caller from attaching multi-GB files to a single outgoing message.
const MAX_FILE_PATH_ATTACHMENT_BYTES = 50 * 1024 * 1024;
const MAX_TOTAL_ATTACHMENT_BYTES = 50 * 1024 * 1024;
const MAX_ATTACHMENTS_PER_MESSAGE = 20;
// END OUTBOUND ATTACHMENT LIMITS
// Must be large enough to carry MAX_BASE64_SIZE plus JSON-RPC framing overhead.
// The httpd.sys.mjs pre-buffer cap uses the same value.
const MAX_REQUEST_BODY = 32 * 1024 * 1024; // 32 MB limit for incoming HTTP request bodies

// BEGIN TOOL RESULT CONTENT
function buildToolResultContent(toolResult) {
  return [{
    type: "text",
    text: JSON.stringify(toolResult, null, 2),
  }];
}
// END TOOL RESULT CONTENT

// File paths that an MCP caller must never be allowed to attach to outbound
// mail. Protects against the LLM-confused-deputy chain where attacker-controlled
// email content prompt-injects an assistant into running
// sendMail({attachments: ["/home/user/.ssh/id_rsa"], skipReview: true}).
//
// Patterns match the path AFTER backslashes are normalized to forward slashes
// and the whole string is lower-cased, so a single set covers POSIX and Windows.
// This is a deny-list, not an allow-list -- it intentionally errs toward
// blocking known-sensitive locations rather than restricting users to a
// downloads-only sandbox. Extend it as new high-value targets surface.
// BEGIN SENSITIVE ATTACHMENT PATH HELPERS
// Keep in sync with mcp-bridge.cjs isSensitiveFilePath.
const SENSITIVE_ATTACHMENT_PATTERNS = [
  // Network/device namespaces must be rejected before any filesystem access.
  /^\/\//,
  // macOS user Library remains denied even when used as a temp directory.
  /^\/users\/[^/]+\/library(\/|$)/,
  /\/thundersend-mcp\/(?:[^/]+\/)?connection\.json$/,
  // Credential names also occur outside the usual profile directories.
  /(^|\/)id_[^/]+$/,
  /(^|\/)private[-_ ]?keys?(\.[^/]+)?$/,
  /\.(keychain|keychain-db)$/,
  /(^|\/)(web data|local state|signons\.sqlite|cert[89]\.db|pkcs11\.txt|secmod\.db|prefs\.js|profiles\.ini)$/,
  // SSH / PGP / cloud / kube / docker credentials
  /\/\.ssh(\/|$)/,
  /\/\.gnupg(\/|$)/,
  /\/\.aws(\/|$)/,
  /\/\.azure(\/|$)/,
  /\/\.config\/gcloud(\/|$)/,
  /\/\.kube(\/|$)/,
  /\/\.docker(\/|$)/,
  /\/\.netrc$/,
  /\/\.npmrc$/,
  /\/\.pypirc$/,
  // Common key / secret file extensions anywhere on disk
  /\/id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/,
  /\.pem$/,
  /\.pfx$/,
  /\.p12$/,
  /\.kdbx$/,
  /\.key$/,
  /\.asc$/,
  /\.gpg$/,
  // Linux / macOS system directories
  /^\/etc\//,
  /^\/proc\//,
  /^\/sys\//,
  /^\/root\//,
  /^\/var\/log\//,
  /^\/var\/lib\/sudo\//,
  // macOS keychain locations
  /\/library\/keychains\//,
  // Windows system directories
  /^[a-z]:\/windows\//,
  /^[a-z]:\/programdata\/microsoft\/(crypto|protect)\//,
  /\/appdata\/(local|roaming)\/microsoft\/(credentials|crypto|protect|vault)(\/|$)/,
  // Browser credential stores (Firefox / Chrome / Edge)
  /\/(logins\.json|key3\.db|key4\.db|cookies(\.sqlite)?|login data)$/,
  // Thunderbird's own profile (contains the user's entire mail store + prefs).
  // Linux profile directories and profiles.ini live directly under
  // ~/.thunderbird (or ~/.icedove), while macOS and Windows use the platform
  // application-data directories below. Block each profile root in full.
  /\/\.(?:thunderbird|icedove)(\/|$)/,
  /\/library\/thunderbird(\/|$)/,
  /\/appdata\/roaming\/thunderbird(\/|$)/,
];

function getAttachmentExportPathInfo(attachmentPath, exportRoots = [], windows = false) {
  // Backslashes are literal filename characters on POSIX, not separators.
  const nativePath = windows ? attachmentPath.replace(/\\/g, '/') : attachmentPath;
  if (nativePath.startsWith('//') || nativePath.split('/').some(part => part === '.' || part === '..')) return null;
  // getMessage exports exactly one sanitized message-id directory and one file.
  // The sibling "attachments" directory is outbound inline staging, not exports.
  const match = /^(.*\/thundersend-mcp)\/([a-zA-Z0-9_]+)\/([^/]+)$/.exec(nativePath);
  if (!match || match[2].toLowerCase() === 'attachments' ||
      match[3].startsWith('.') || match[3].toLowerCase() === 'connection.json') return null;
  const roots = typeof exportRoots === 'function' ? exportRoots() : exportRoots;
  const root = roots.find(candidate => {
    const nativeRoot = (windows ? candidate.replace(/\\/g, '/') : candidate).replace(/\/$/, '');
    return windows ? nativeRoot.toLowerCase() === match[1].toLowerCase() : nativeRoot === match[1];
  });
  return root ? { root, parts: [match[2], match[3]] } : null;
}

function isSensitiveFilePath(attachmentPath, { windows = false, exportRoots = [] } = {}) {
  if (typeof attachmentPath !== 'string' || !attachmentPath) return false;
  const normalized = attachmentPath.replace(/\\/g, '/').toLowerCase();
  if (windows && (normalized.replace(/^[a-z]:/, '').includes(':') ||
      normalized.split('/').some(part => /[. ]$/.test(part)))) return true;
  // Traversal must never gain the export-directory exemption.
  if (normalized.split('/').some(part => part === '.' || part === '..')) return true;
  if (SENSITIVE_ATTACHMENT_PATTERNS.some(re => re.test(normalized))) return true;
  // Only inherited dot-directory/AppData restrictions may be waived for exports.
  if (/(^|\/)(\.[^/]*|appdata)(\/|$)/.test(normalized)) {
    return !getAttachmentExportPathInfo(attachmentPath, exportRoots, windows);
  }
  return false;
}
// END SENSITIVE ATTACHMENT PATH HELPERS
let _tempFileCounter = 0;
const PREF_ALLOWED_ACCOUNTS = "extensions.thundersend-mcp-minimal.allowedAccounts";
const PREF_DISABLED_TOOLS = "extensions.thundersend-mcp-minimal.disabledTools";
const PREF_BLOCK_SKIPREVIEW = "extensions.thundersend-mcp-minimal.blockSkipReview";
const PREF_STABLE_AUTH_TOKEN = "extensions.thundersend-mcp-minimal.stableAuthToken";
const PREF_LISTEN_ALL = "extensions.thundersend-mcp-minimal.listenAll";
const AUTH_TOKEN_PATTERN = /^[0-9a-f]{64}$/;
// Valid group and CRUD values for tool metadata validation
const VALID_GROUPS = ["messages", "system"];
const VALID_CRUD = ["create", "read"];
// CRUD sort order: read first, then create
const CRUD_ORDER = { read: 0, create: 1 };
// Tools that cannot be disabled via the settings page (infrastructure tools)
const UNDISABLEABLE_TOOLS = new Set(["listAccounts", "getAccountAccess"]);
// Hard allow-list: tools/list and tools/call never expose anything else.
const MINIMAL_TOOL_NAMES = new Set(["listAccounts", "getAccountAccess", "sendMail", "saveDraft"]);

// BEGIN PRIVACY PREFERENCE HELPERS
function readAccessListPref(prefName) {
  try {
    const prefType = Services.prefs.getPrefType(prefName);
    if (prefType === Ci.nsIPrefBranch.PREF_INVALID) return { values: [], corrupt: false };
    if (prefType !== Ci.nsIPrefBranch.PREF_STRING) return { values: [], corrupt: true };
    const raw = Services.prefs.getStringPref(prefName);
    const values = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(values) || !values.every(value => typeof value === "string")) {
      return { values: [], corrupt: true };
    }
    return { values, corrupt: false };
  } catch {
    return { values: [], corrupt: true };
  }
}

// END PRIVACY PREFERENCE HELPERS

// BEGIN MCP TEXT SANITIZATION
function stripInvisibleCharacters(text) {
  return text.replace(/[\u200B\u2060\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}]/gu, "");
}

function sanitizeToolResultText(value, key = "") {
  if (typeof value === "string") {
    // Preserve identifiers, paths, URLs and encoded payloads for round trips.
    return !key || /^(body|bodyNote|preview|subject|author|recipients|ccList|name|displayName|firstName|lastName|accountName|calendarName|folderName|folder|title|description|note|organization|addressBook|location|categories|message|error)$/.test(key)
      ? stripInvisibleCharacters(value) : value;
  }
  if (Array.isArray(value)) return value.map(item => sanitizeToolResultText(item, key));
  if (!value || typeof value !== "object") return value;
  if (Array.isArray(value.columns) && Array.isArray(value.rows)) {
    value.rows = value.rows.map(row => row.map((cell, index) => sanitizeToolResultText(cell, value.columns[index])));
  }
  // Keep non-enumerable metadata (including extra MCP content blocks) intact.
  for (const [field, item] of Object.entries(value)) {
    if (field === "rawSource" || (field === "body" && value.bodyIsHtml)) continue;
    value[field] = sanitizeToolResultText(item, field);
  }
  return value;
}
// END MCP TEXT SANITIZATION

var mcpServer = class extends ExtensionCommon.ExtensionAPI {
  getAPI(context) {
    const extensionRoot = context.extension.rootURI;
    const resourceName = "thundersend-mcp";

    // BEGIN UNINSTALL LISTENER REGISTRATION
    if (!this._uninstallListener) {
      try {
        let AddonManager;
        try {
          ({ AddonManager } = ChromeUtils.importESModule("resource://gre/modules/AddonManager.sys.mjs"));
        } catch {
          ({ AddonManager } = ChromeUtils.import("resource://gre/modules/AddonManager.jsm"));
        }
        const addonId = context.extension.id;
        const listener = {
          onUninstalling(addon) {
            if (addon.id !== addonId) return;
            try { Services.prefs.clearUserPref(PREF_STABLE_AUTH_TOKEN); } catch { /* best effort */ }
          },
        };
        AddonManager.addAddonListener(listener);
        this._uninstallListener = listener;
        this._addonManager = AddonManager;
      } catch (e) {
        console.warn("thundersend-mcp: could not register token uninstall cleanup:", e);
      }
    }
    // END UNINSTALL LISTENER REGISTRATION

    resProto.setSubstitutionWithFlags(
      resourceName,
      extensionRoot,
      resProto.ALLOW_CONTENT_ACCESS
    );

// BEGIN TOOL SCHEMA BUILDER
    function buildTools() {
      return [
      {
        name: "listAccounts",
        group: "system", crud: "read",
        title: "List Accounts",
        description: "List all email accounts and their identities",
        inputSchema: { type: "object", properties: {}, required: [] },
      },
      {
        name: "sendMail",
        group: "messages", crud: "create",
        title: "Compose Mail",
        description: "Compose a new email in a review window. The skipReview safety block is on by default; direct sending is honored only when the user explicitly disables that preference. Direct sending includes the identity signature unless includeSignature is false.",
        inputSchema: {
          type: "object",
          properties: {
            to: { type: "string", description: "Recipient email address" },
            subject: { type: "string", description: "Email subject line" },
            body: { type: "string", description: "Email body text" },
            cc: { type: "string", description: "CC recipients (comma-separated)" },
            bcc: { type: "string", description: "BCC recipients (comma-separated)" },
            isHtml: { type: "boolean", description: "Set to true if body contains HTML markup (default: false)" },
            from: { type: "string", description: "Sender identity (email address or identity ID from listAccounts)" },
            skipReview: { type: "boolean", description: "Request direct sending without a compose window. Honored only when the user explicitly disables the default-on skipReview safety block (default: false)." },
            includeSignature: { type: "boolean", default: true, description: "Append the identity signature when skipReview is true (default: true). Set false if the body already includes it. Compose review windows use Thunderbird's signature preferences." },
            attachments: {
              type: "array",
              maxItems: MAX_ATTACHMENTS_PER_MESSAGE,
              description: "Attachments: file paths (strings) or inline objects ({name, contentType, base64})",
              items: {
                oneOf: [
                  { type: "string", description: "Absolute file path to attach" },
                  {
                    type: "object",
                    properties: {
                      name: { type: "string", minLength: 1, description: "Attachment filename" },
                      contentType: { type: "string", description: "MIME type, e.g. application/pdf" },
                      base64: { type: "string", minLength: 1, contentEncoding: "base64", description: "Base64-encoded file content" },
                      content: { type: "string", minLength: 1, contentEncoding: "base64", description: "Alias for base64 (accepted for backwards compatibility); base64 takes precedence when both are set" },
                    },
                    required: ["name"],
                    anyOf: [
                      { type: "object", required: ["base64"] },
                      { type: "object", required: ["content"] },
                    ],
                    additionalProperties: false,
                  },
                ],
              },
            },
          },
          required: ["to", "subject", "body"],
        },
      },
      {
        name: "saveDraft",
        group: "messages", crud: "create",
        title: "Save Draft",
        description: "Save a composed message to the identity's Drafts folder without sending or opening a compose window. Returns folderPath when the destination is accessible under account restrictions. Supports threading headers and replacing an existing draft in the selected identity's accessible Drafts folder. Includes the identity signature by default for new drafts, but not replacements.",
        inputSchema: {
          type: "object",
          properties: {
            replaceMessageId: { type: "string", minLength: 1, description: "Message ID of an existing draft to REPLACE (from searchMessages). The new draft carries the full content given here -- nothing is merged from the old one, so pass every field you want kept. Omit to create a new draft." },
            replaceFolderPath: { type: "string", minLength: 1, description: "Folder URI holding the draft named by replaceMessageId (from searchMessages). Required with replaceMessageId. Must be accessible under account restrictions, carry the Drafts flag, and match the selected identity's configured drafts folder; other folders are rejected." },
            to: { type: "string", description: "Recipient email address(es), comma-separated. Optional -- a draft can have no recipient." },
            subject: { type: "string", description: "Email subject line (optional)" },
            body: { type: "string", description: "Email body (optional)" },
            cc: { type: "string", description: "CC recipients (comma-separated)" },
            bcc: { type: "string", description: "BCC recipients (comma-separated)" },
            isHtml: { type: "boolean", description: "Set to true if body contains HTML markup (default: false)" },
            from: { type: "string", description: "Sender identity (email address or identity ID from listAccounts)" },
            includeSignature: { type: "boolean", description: "Append the identity signature. Defaults to true for a new draft and false when replacing a draft, whose body may already include it. Set false for a body with its own signature, or true to append one explicitly." },
            inReplyTo: { type: "string", minLength: 5, maxLength: 998, description: "One bracketed Message-ID, e.g. <id@example.com>, at most 998 characters, without whitespace or control characters. Invalid input is rejected, never repaired. Sets In-Reply-To and defaults References to this ID. Subject and quoted text remain the caller's responsibility." },
            references: { type: "string", minLength: 5, maxLength: 16384, description: "Up to 100 bracketed Message-IDs separated by single ASCII spaces, oldest first; at most 998 characters per ID and 16384 total. No whitespace within IDs or control characters. Invalid input is rejected. Defaults to inReplyTo when omitted; may also be supplied independently." },
            attachments: {
              type: "array",
              maxItems: MAX_ATTACHMENTS_PER_MESSAGE,
              description: "Attachments: file paths (strings) or inline objects ({name, contentType, base64})",
              items: {
                oneOf: [
                  { type: "string", description: "Absolute file path to attach" },
                  {
                    type: "object",
                    properties: {
                      name: { type: "string", minLength: 1, description: "Attachment filename" },
                      contentType: { type: "string", description: "MIME type, e.g. application/pdf" },
                      base64: { type: "string", minLength: 1, contentEncoding: "base64", description: "Base64-encoded file content" },
                      content: { type: "string", minLength: 1, contentEncoding: "base64", description: "Alias for base64 (accepted for backwards compatibility); base64 takes precedence when both are set" },
                    },
                    required: ["name"],
                    anyOf: [
                      { type: "object", required: ["base64"] },
                      { type: "object", required: ["content"] },
                    ],
                    additionalProperties: false,
                  },
                ],
              },
            },
          },
          required: [],
        },
      },
      {
        name: "getAccountAccess",
        group: "system", crud: "read",
        title: "Get Account Access",
        description: "Get the current account access control list. Shows which accounts the MCP server can access. Account access is configured by the user in the extension settings page (Tools > Add-ons > Thunderbird MCP > Options) and cannot be changed via MCP tools.",
        inputSchema: { type: "object", properties: {}, required: [] },
      },
      ];
    }
    // END TOOL SCHEMA BUILDER

    const tools = buildTools();

    // Validate tool metadata: every tool must have valid group and crud fields.
    // This prevents tools from being silently hidden in the settings UI.
    const toolErrors = [];
    for (const tool of tools) {
      if (!tool.group || !VALID_GROUPS.includes(tool.group)) {
        toolErrors.push(`Tool "${tool.name}" has invalid or missing group: "${tool.group}" (valid: ${VALID_GROUPS.join(", ")})`);
      }
      if (!tool.crud || !VALID_CRUD.includes(tool.crud)) {
        toolErrors.push(`Tool "${tool.name}" has invalid or missing crud: "${tool.crud}" (valid: ${VALID_CRUD.join(", ")})`);
      }
    }
    if (toolErrors.length > 0) {
      console.error("thundersend-mcp: Tool metadata validation failed:\n  " + toolErrors.join("\n  "));
    }

    // Derive ALL_TOOL_NAMES from the tools array (single source of truth)
    const ALL_TOOL_NAMES = tools.map(t => t.name);

    // Group display order for settings UI
    const GROUP_ORDER = { system: 0, messages: 1 };
    // Group display labels
    const GROUP_LABELS = { system: "System", messages: "Messages" };

    /**
     * Generate a cryptographically random auth token (hex string).
     * Used to authenticate bridge requests to the HTTP server.
     */
    function generateAuthToken() {
      const bytes = new Uint8Array(32);
      // crypto.getRandomValues is not available in Thunderbird experiment API scope;
      // use the XPCOM random generator instead.
      const rng = Cc["@mozilla.org/security/random-generator;1"]
        .createInstance(Ci.nsIRandomGenerator);
      const randomBytes = rng.generateRandomBytes(32);
      for (let i = 0; i < 32; i++) bytes[i] = randomBytes[i];
      return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
    }

    function getStableAuthTokenPref() {
      try {
        const pref = Services.prefs.getStringPref(PREF_STABLE_AUTH_TOKEN, "");
        const token = pref.trim();
        if (!token) {
          if (pref) {
            console.warn("thundersend-mcp: stableAuthToken preference is malformed; expected 64 lowercase hex characters, ignoring stored value");
          }
          return "";
        }
        if (!AUTH_TOKEN_PATTERN.test(token)) {
          console.warn("thundersend-mcp: stableAuthToken preference is malformed; expected 64 lowercase hex characters, ignoring stored value");
          return "";
        }
        return token;
      } catch {
        return "";
      }
    }

    function readConnectionInfo() {
      const tmpDir = Services.dirsvc.get("TmpD", Ci.nsIFile);
      tmpDir.append("thundersend-mcp");
      const connFile = tmpDir.clone();
      connFile.append("connection.json");
      if (!connFile.exists()) {
        return { path: connFile.path, data: null };
      }
      const fis = Cc["@mozilla.org/network/file-input-stream;1"]
        .createInstance(Ci.nsIFileInputStream);
      fis.init(connFile, 0x01, 0, 0);
      const sis = Cc["@mozilla.org/scriptableinputstream;1"]
        .createInstance(Ci.nsIScriptableInputStream);
      sis.init(fis);
      const text = sis.read(sis.available());
      sis.close();
      return { path: connFile.path, data: JSON.parse(text) };
    }

    /**
     * Remove the connection info file during startup or shutdown cleanup.
     */
    function removeConnectionInfo() {
      try {
        const tmpDir = Services.dirsvc.get("TmpD", Ci.nsIFile);
        tmpDir.append("thundersend-mcp");
        const connFile = tmpDir.clone();
        connFile.append("connection.json");
        if (connFile.exists()) {
          connFile.remove(false);
        }
      } catch {
        // Best-effort cleanup
      }
    }

    return {
      mcpServer: {
        // BEGIN SERVER LIFECYCLE
        start: async function() {
          // Guard against double-start on extension reload (port conflict)
          if (globalThis.__tbMcpStartPromise) {
            return await globalThis.__tbMcpStartPromise;
          }
          const startPromise = (async () => {
          let startedServer = null;
          try {
            // Stop any previously running server (e.g. extension reload)
            if (globalThis.__tbMcpServer) {
              try { globalThis.__tbMcpServer.stop(() => {}); } catch { /* ignore */ }
              globalThis.__tbMcpServer = null;
              stopConnectionInfoRefreshTimer();
            }
            const { HttpServer } = ChromeUtils.importESModule(
              "resource://thundersend-mcp/httpd.sys.mjs?" + Date.now()
            );
            const { NetUtil } = ChromeUtils.importESModule(
              "resource://gre/modules/NetUtil.sys.mjs"
            );
            const { MailServices } = ChromeUtils.importESModule(
              "resource:///modules/MailServices.sys.mjs"
            );
            /**
             * CRITICAL: Must specify { charset: "UTF-8" } or emojis/special chars
             * will be corrupted. NetUtil defaults to Latin-1.
             */
            function readRequestBody(request) {
              const stream = request.bodyInputStream;
              return NetUtil.readInputStreamToString(stream, stream.available(), { charset: "UTF-8" });
            }

            // BEGIN CONNECTION INFO WRITER
            /**
             * Write connection info (port + auth token) to a well-known file
             * so the bridge can discover how to connect.
             * File: <TmpD>/thundersend-mcp/connection.json
             */
            function writeConnectionInfo(port, token) {
              const tmpDir = Services.dirsvc.get("TmpD", Ci.nsIFile);
              tmpDir.append("thundersend-mcp");
              if (!tmpDir.exists()) {
                tmpDir.create(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
              } else if (tmpDir.isSymlink()) {
                throw new Error("thundersend-mcp tmp directory is a symlink — refusing to write connection info");
              } else if (Services.appinfo.OS !== "WINNT") {
                // POSIX hardening: on a shared /tmp another local user could
                // pre-create the directory with group/world bits set, then race
                // the connection file. The O_EXCL on the file itself blocks a
                // straight overwrite, but a permissive directory still lets the
                // attacker read or rename our file. Force perms back to 0o700.
                //
                // Skipped on Windows: nsIFile.permissions synthesises group/
                // other bits (0o666/0o777 have been observed) that assigning
                // 0o700 cannot clear. Access is governed by inherited ACLs;
                // these mode bits neither describe nor enforce ACL privacy.
                try {
                  const mode = tmpDir.permissions;
                  if (mode && (mode & 0o077) !== 0) {
                    try { tmpDir.permissions = 0o700; } catch { /* best-effort */ }
                    if ((tmpDir.permissions & 0o077) !== 0) {
                      throw new Error("thundersend-mcp tmp directory has group/world permissions — refusing to write connection info");
                    }
                  }
                } catch (e) {
                  if (e && e.message && e.message.startsWith("thundersend-mcp tmp directory")) throw e;
                  // ignore: permissions accessor unsupported on this platform
                }
              }
              const connFile = tmpDir.clone();
              connFile.append("connection.json");
              // Symlink defense: remove any existing file first, then create
              // with O_CREAT|O_EXCL (0x08|0x80) to fail if a symlink appeared
              // between remove and create.
              if (connFile.exists()) {
                connFile.remove(false);
              }
              const data = JSON.stringify({ port, token, pid: Services.appinfo.processID });
              const ostream = Cc["@mozilla.org/network/file-output-stream;1"]
                .createInstance(Ci.nsIFileOutputStream);
              // 0x02 = O_WRONLY, 0x08 = O_CREAT, 0x80 = O_EXCL
              ostream.init(connFile, 0x02 | 0x08 | 0x80, 0o600, 0);
              const converter = Cc["@mozilla.org/intl/converter-output-stream;1"]
                .createInstance(Ci.nsIConverterOutputStream);
              converter.init(ostream, "UTF-8");
              converter.writeString(data);
              converter.close();
              return connFile.path;
            }
            // END CONNECTION INFO WRITER

            function ensureConnectionInfo(port, token) {
              return ensureFreshConnectionInfo({
                port,
                token,
                expectedPid: Services.appinfo.processID,
                readConnectionInfo,
                writeConnectionInfo,
                onCheckError: (e) => {
                  console.warn("thundersend-mcp: connection info check failed; rewriting:", e);
                },
              });
            }

            function startConnectionInfoRefresh(port, token) {
              stopConnectionInfoRefreshTimer();
              const timer = Cc["@mozilla.org/timer;1"].createInstance(Ci.nsITimer);
              // Track it before initialization so failed startup can cancel it.
              globalThis.__tbMcpConnectionInfoRefreshTimer = timer;
              timer.initWithCallback(() => {
                try {
                  ensureConnectionInfo(port, token);
                } catch (e) {
                  console.warn("thundersend-mcp: failed to refresh connection info:", e);
                }
              }, CONNECTION_FILE_REFRESH_MS, Ci.nsITimer.TYPE_REPEATING_SLACK);
            }

            const authToken = getStableAuthTokenPref() || generateAuthToken();

            /**
             * Constant-time string comparison to prevent timing side-channel attacks.
             */
            function timingSafeEqual(a, b) {
              const aStr = String(a);
              const bStr = String(b);
              const len = Math.max(aStr.length, bStr.length);
              let result = aStr.length ^ bStr.length;
              for (let i = 0; i < len; i++) {
                result |= (aStr.charCodeAt(i) || 0) ^ (bStr.charCodeAt(i) || 0);
              }
              return result === 0;
            }

            /**
             * Get the list of allowed account IDs from preferences.
             * Returns an empty array if no restriction is set (all accounts allowed).
             */
            // BEGIN SERVER ACCESS HELPERS
            function getAllowedAccountIds() {
              const { values, corrupt } = readAccessListPref(PREF_ALLOWED_ACCOUNTS);
              return corrupt ? ["__invalid__"] : values;
            }

            /**
             * Check if an account is accessible based on the allowed accounts list.
             * When the list is empty, all accounts are accessible (default).
             */
            function isAccountAllowed(accountKey) {
              const allowed = getAllowedAccountIds();
              if (allowed.length === 0) return true;
              return allowed.includes(accountKey);
            }

            /**
             * Check if the user has disabled the skipReview shortcut.
             * When true, send/reply/forward/createEvent/createTask tools must open
             * the review window/dialog even if the caller passed skipReview: true.
             * Adding calendar attendees is blocked, and meetings with other
             * attendees are read-only: any write can send without review.
             *
             * Default is true: an LLM that reads attacker-controlled email content
             * can be prompt-injected into invoking sendMail with skipReview, so the
             * safe default is to require human review. Users can explicitly opt
             * into silent sends from the options page.
             */
            function isSkipReviewBlocked() {
              try {
                return Services.prefs.getBoolPref(PREF_BLOCK_SKIPREVIEW, true);
              } catch {
                // Fail closed: if we can't read the pref, assume blocked so the
                // user retains ability to review before send.
                return true;
              }
            }

            /**
             * Get the list of disabled tool names from preferences.
             * Returns an empty array if no tools are disabled (all enabled).
             * Fails closed: corrupt pref disables all tools.
             */
            function getDisabledTools() {
              const { values, corrupt } = readAccessListPref(PREF_DISABLED_TOOLS);
              return corrupt ? ["__all__"] : values;
            }

            /**
             * Check if a tool is enabled.
             * Undisableable tools (listAccounts, listFolders, getAccountAccess) always return true.
             */
            function isToolEnabled(toolName) {
              if (UNDISABLEABLE_TOOLS.has(toolName)) return true;
              const disabled = getDisabledTools();
              if (disabled.includes("__all__")) return false;
              return !disabled.includes(toolName);
            }

            // END SERVER ACCESS HELPERS

            /**
             * Check if a resolved folder belongs to an allowed account.
             * Returns true if the folder's account is accessible, false otherwise.
             */
            function isFolderAccessible(folder) {
              if (!folder || !folder.server) return false;
              const account = MailServices.accounts.findAccountForServer(folder.server);
              return account ? isAccountAllowed(account.key) : false;
            }

            /**
             * Lookup a folder by URI and verify it exists and is accessible.
             * Returns { folder } on success, or { error } if not found or restricted.
             */
            function getAccessibleFolder(folderPath) {
              const folder = MailServices.folderLookup.getFolderForURL(folderPath);
              if (!folder) return { error: `Folder not found: ${folderPath}` };
              if (!isFolderAccessible(folder)) return { error: `Account not accessible for folder: ${folderPath}` };
              return { folder };
            }

            /**
             * Get all accessible Thunderbird accounts, filtered by allowed list.
             */
            function getAccessibleAccounts() {
              const result = [];
              for (const account of MailServices.accounts.accounts) {
                if (isAccountAllowed(account.key)) {
                  result.push(account);
                }
              }
              return result;
            }

            /**
             * Best-effort refresh for IMAP folders. updateFolder starts async work
             * and may not complete before callers read from Thunderbird's cache.
             */
            function refreshImapFolderSync(folder) {
              if (folder.server && folder.server.type === "imap") {
                try {
                  folder.updateFolder(null);
                } catch {
                  // updateFolder may fail, continue anyway
                }
              }
            }

            function listAccounts() {
              const accounts = [];
              for (const account of getAccessibleAccounts()) {
                const server = account.incomingServer;
                const identities = [];
                for (const identity of account.identities) {
                  identities.push({
                    id: identity.key,
                    email: identity.email,
                    name: identity.fullName,
                    isDefault: identity === account.defaultIdentity
                  });
                }
                accounts.push({
                  id: account.key,
                  name: server.prettyName,
                  type: server.type,
                  identities
                });
              }
              return accounts;
            }

            /**
             * Get the current account access control list.
             */
            function getAccountAccess() {
              const allowed = getAllowedAccountIds();
              // Only return accessible accounts — restricted accounts are hidden
              const accessibleAccounts = [];
              for (const account of MailServices.accounts.accounts) {
                if (!isAccountAllowed(account.key)) continue;
                const server = account.incomingServer;
                accessibleAccounts.push({
                  id: account.key,
                  name: server.prettyName,
                  type: server.type,
                });
              }
              return {
                mode: allowed.length === 0 ? "all" : "restricted",
                accounts: accessibleAccounts,
              };
            }

            /**
             * Searches the given accounts for an identity matching emailOrId
             * (by key or case-insensitive email).
             * Returns the identity object, or null if not found.
             */
            function findIdentityIn(accounts, emailOrId) {
              if (!emailOrId) return null;
              const lowerInput = emailOrId.toLowerCase();
              for (const account of accounts) {
                for (const identity of account.identities) {
                  if (identity.key === emailOrId || (identity.email || "").toLowerCase() === lowerInput) {
                    return identity;
                  }
                }
              }
              return null;
            }

            /**
             * Finds an identity by email address or identity ID
             * among accessible accounts only.  Returns null if not found.
             */
            function findIdentity(emailOrId) {
              return findIdentityIn(getAccessibleAccounts(), emailOrId);
            }

            /** Creates an nsIFile instance for the given path. */
            function createLocalFile(path) {
              const file = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
              file.initWithPath(path);
              return file;
            }

            // BEGIN MESSAGE STREAM READER
            const MESSAGE_STREAM_READ_CHUNK_BYTES = 64 * 1024;
            // Reads a message stream fully, looping on stream.available() to handle
            // mbox-stored messages where msgHdr.offlineMessageSize/messageSize can
            // underreport (observed at ~56% of true size for locally-injected mbox
            // entries). Returns the raw Latin-1 bytestring or throws. Caller must
            // close the stream.
            function readMessageStreamFully(stream, maxBytes) {
              let raw = "";
              const hasByteLimit = typeof maxBytes === "number" && Number.isFinite(maxBytes);
              while (true) {
                let available;
                try {
                  available = stream.available();
                } catch (e) {
                  if (e === Cr.NS_BASE_STREAM_CLOSED || e?.result === Cr.NS_BASE_STREAM_CLOSED) break;
                  throw e;
                }
                if (available <= 0) break;

                let bytesToRead = Math.min(available, MESSAGE_STREAM_READ_CHUNK_BYTES);
                if (hasByteLimit) {
                  // Reading one byte beyond the remaining budget proves overflow
                  // from returned data, rather than from the available byte count.
                  bytesToRead = Math.min(bytesToRead, Math.max(1, maxBytes - raw.length + 1));
                }
                const chunk = NetUtil.readInputStreamToString(stream, bytesToRead);
                if (!chunk || chunk.length === 0) {
                  throw new Error("message stream read made no progress");
                }
                raw += chunk;
                if (hasByteLimit && raw.length > maxBytes) {
                  const error = new Error(`message too large (> ${maxBytes} bytes)`);
                  error.isStreamSizeLimit = true;
                  throw error;
                }
              }
              return raw;
            }

            // END MESSAGE STREAM READER

            /**
             * Converts attachment entries to attachment descriptors.
             * Each entry can be:
             *   - A string (file path) — resolved from disk
             *   - An object { name, contentType, base64 } — decoded and written
             *     to a temp file under <TmpD>/thundersend-mcp/attachments/
             * Returns { descs: [{url, name, size, contentType?}], failed: [] }.
             * Any refused entry throws before a send/draft/window can proceed,
             * and removes temporary files created by this conversion.
             */
            // BEGIN OUTBOUND ATTACHMENT CONVERSION
            function filePathsToAttachDescs(filePaths) {
              const descs = [];
              const failed = [];
              if (filePaths === undefined || filePaths === null) return { descs, failed };
              if (!Array.isArray(filePaths)) throw new Error("Attachments must be an array");
              if (filePaths.length > MAX_ATTACHMENTS_PER_MESSAGE) {
                throw new Error(`Attachment count ${filePaths.length} exceeds the ${MAX_ATTACHMENTS_PER_MESSAGE} attachment limit`);
              }
              const createdTempFiles = [];
              let totalAttachmentBytes = 0;
              for (const entry of filePaths) {
                try {
                  if (typeof entry === "string") {
                    // File path attachment.
                    //
                    // SECURITY: reject paths that point at credentials, system
                    // files, or browser/mail profile data BEFORE touching the
                    // filesystem. This is the LLM-confused-deputy defense:
                    // attacker-controlled email content can prompt-inject an
                    // assistant into calling sendMail with attachments=["/path/to/id_rsa"]
                    // and we never want that to succeed regardless of skipReview.
                    let exportRoots;
                    let canonicalExportRoot;
                    const attachmentPolicy = {
                      windows: Services.appinfo?.OS === "WINNT",
                      // Evaluated only for an otherwise-safe export-shaped path.
                      exportRoots: () => {
                        if (!exportRoots) {
                          const root = Services.dirsvc.get("TmpD", Ci.nsIFile);
                          canonicalExportRoot = root.clone();
                          // Trust TmpD's canonical location, not symlinks below it.
                          canonicalExportRoot.normalize();
                          root.append("thundersend-mcp");
                          canonicalExportRoot.append("thundersend-mcp");
                          exportRoots = [root.path, canonicalExportRoot.path];
                        }
                        return exportRoots;
                      },
                    };
                    if (isSensitiveFilePath(entry, attachmentPolicy)) {
                      failed.push(`${entry} (sensitive path blocked)`);
                      continue;
                    }
                    const file = createLocalFile(entry);
                    if (!file.exists()) {
                      failed.push(entry);
                      continue;
                    }
                    let isSymlink;
                    try {
                      isSymlink = file.isSymlink();
                    } catch {
                      failed.push(`${entry} (symlink check failed)`);
                      continue;
                    }
                    if (isSymlink) {
                      failed.push(`${entry} (symlinked path blocked)`);
                      continue;
                    }
                    // POSIX normalize resolves parent symlinks. Windows only
                    // normalizes syntax, so inspect resolved ancestors there too.
                    try {
                      file.normalize();
                    } catch {
                      failed.push(`${entry} (path normalization failed)`);
                      continue;
                    }
                    if (isSensitiveFilePath(file.path, attachmentPolicy)) {
                      failed.push(`${entry} (sensitive path blocked)`);
                      continue;
                    }
                    const exportInfo = getAttachmentExportPathInfo(entry, attachmentPolicy.exportRoots, attachmentPolicy.windows);
                    const resolvedExportInfo = getAttachmentExportPathInfo(file.path, attachmentPolicy.exportRoots, attachmentPolicy.windows);
                    if (exportInfo || resolvedExportInfo) {
                      let expectedPath = entry;
                      if (exportInfo) {
                        const expectedFile = canonicalExportRoot.clone();
                        for (const part of exportInfo.parts) expectedFile.append(part);
                        expectedPath = expectedFile.path;
                      }
                      const expected = attachmentPolicy.windows ? expectedPath.replace(/\\/g, "/").toLowerCase() : expectedPath;
                      const resolved = attachmentPolicy.windows ? file.path.replace(/\\/g, "/").toLowerCase() : file.path;
                      if (expected !== resolved) {
                        failed.push(`${entry} (export path is redirected)`);
                        continue;
                      }
                    }
                    if (Services.appinfo?.OS === "WINNT") {
                      // Windows isSymlink() does not identify junctions. On a
                      // fresh nsIFile, isReadable() forces ResolveAndStat, which
                      // resolves a reparse point before target is read. Check
                      // every ancestor: a regular leaf below a junction is not
                      // itself a reparse point. Refuse redirected paths.
                      for (let component = file.clone(); component; component = component.parent) {
                        // Parents already have normalized syntax. Normalizing a
                        // drive root ("C:" in nsIFile) would expand it to its cwd.
                        if (!component.isReadable()) throw new Error("path resolution failed");
                        const target = component.target;
                        if (!target ||
                            target.replace(/\\/g, "/").toLowerCase() !== component.path.replace(/\\/g, "/").toLowerCase()) {
                          throw new Error("symlinked or junction path blocked");
                        }
                      }
                    }
                    let isRegularFile;
                    try {
                      isRegularFile = file.isFile();
                    } catch {
                      failed.push(`${entry} (file type check failed)`);
                      continue;
                    }
                    if (!isRegularFile) {
                      failed.push(`${entry} (not a regular file)`);
                      continue;
                    }
                    // Size cap mirrors the saved-attachment ceiling and avoids
                    // ballooning outgoing messages when a caller points at a huge file.
                    let fileSize;
                    try {
                      fileSize = file.fileSize;
                    } catch {
                      failed.push(`${entry} (file size check failed)`);
                      continue;
                    }
                    if (!Number.isSafeInteger(fileSize) || fileSize < 0) {
                      failed.push(`${entry} (invalid file size)`);
                      continue;
                    }
                    if (fileSize > MAX_FILE_PATH_ATTACHMENT_BYTES) {
                      failed.push(`${entry} (exceeds ${MAX_FILE_PATH_ATTACHMENT_BYTES / 1024 / 1024}MB size limit)`);
                      continue;
                    }
                    if (fileSize > MAX_TOTAL_ATTACHMENT_BYTES - totalAttachmentBytes) {
                      failed.push(`${entry} (exceeds ${MAX_TOTAL_ATTACHMENT_BYTES / 1024 / 1024}MB aggregate attachment limit)`);
                      continue;
                    }
                    const desc = { url: Services.io.newFileURI(file).spec, name: file.leafName, size: fileSize };
                    descs.push(desc);
                    totalAttachmentBytes += fileSize;
                  } else if (entry && typeof entry === "object" && (entry.base64 || entry.content) && entry.name) {
                    // Inline base64 attachment — decode and write to temp file
                    const b64Data = entry.base64 || entry.content;
                    if (!isValidBase64(b64Data)) {
                      failed.push(`${entry.name} (invalid base64 data)`);
                      continue;
                    }
                    if (b64Data.length > MAX_BASE64_SIZE) {
                      failed.push(`${entry.name} (exceeds ${MAX_BASE64_SIZE / 1024 / 1024}MB size limit)`);
                      continue;
                    }
                    // Decode base64 to binary bytes
                    let bytes;
                    try {
                      // Use the global atob when available, otherwise fall back
                      const raw = typeof atob === "function" ? atob(b64Data) : ChromeUtils.base64Decode(b64Data);
                      bytes = new Uint8Array(raw.length);
                      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
                    } catch {
                      // Fallback: manual base64 decode (atob may not be available in XPCOM context)
                      try {
                        const lookup = new Uint8Array(256);
                        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                        for (let i = 0; i < chars.length; i++) lookup[chars.charCodeAt(i)] = i;
                        // Shape was validated above; remove only legal trailing
                        // padding rather than stripping arbitrary invalid bytes.
                        const clean = b64Data.replace(/=+$/, "");
                        const len = clean.length;
                        const outLen = (len * 3) >> 2;
                        bytes = new Uint8Array(outLen);
                        let p = 0;
                        for (let i = 0; i < len; i += 4) {
                          const a = lookup[clean.charCodeAt(i)];
                          const b = lookup[clean.charCodeAt(i + 1)];
                          const c = lookup[clean.charCodeAt(i + 2)];
                          const d = lookup[clean.charCodeAt(i + 3)];
                          bytes[p++] = (a << 2) | (b >> 4);
                          if (i + 2 < len) bytes[p++] = ((b & 15) << 4) | (c >> 2);
                          if (i + 3 < len) bytes[p++] = ((c & 3) << 6) | d;
                        }
                        bytes = bytes.subarray(0, p);
                      } catch {
                        failed.push(`${entry.name} (invalid base64 data)`);
                        continue;
                      }
                    }
                    if (bytes.length > MAX_TOTAL_ATTACHMENT_BYTES - totalAttachmentBytes) {
                      failed.push(`${entry.name} (exceeds ${MAX_TOTAL_ATTACHMENT_BYTES / 1024 / 1024}MB aggregate attachment limit)`);
                      continue;
                    }
                    const tmpDir = Services.dirsvc.get("TmpD", Ci.nsIFile);
                    tmpDir.append("thundersend-mcp");
                    tmpDir.append("attachments");
                    if (!tmpDir.exists()) {
                      tmpDir.create(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
                    }
                    const tmpFile = tmpDir.clone();
                    let safeName = (entry.name || entry.filename || "attachment").replace(/[^a-zA-Z0-9._-]/g, "_");
                    if (!safeName || safeName === "." || safeName === "..") safeName = "attachment";
                    tmpFile.append(`${Date.now()}_${++_tempFileCounter}_${safeName}`);
                    // Write via XPCOM binary stream
                    const ostream = Cc["@mozilla.org/network/file-output-stream;1"]
                      .createInstance(Ci.nsIFileOutputStream);
                    // Exclusive creation ensures cleanup only removes this call's files.
                    ostream.init(tmpFile, 0x02 | 0x08 | 0x80, 0o600, 0);
                    createdTempFiles.push(tmpFile);
                    _tempAttachFiles.add(tmpFile.path);
                    let bstream;
                    try {
                      bstream = Cc["@mozilla.org/binaryoutputstream;1"]
                        .createInstance(Ci.nsIBinaryOutputStream);
                      bstream.setOutputStream(ostream);
                      bstream.writeByteArray(bytes, bytes.length);
                    } finally {
                      try { if (bstream) bstream.close(); } finally { ostream.close(); }
                    }
                    const desc = { url: Services.io.newFileURI(tmpFile).spec, name: entry.name || entry.filename, size: tmpFile.fileSize };
                    if (entry.contentType) desc.contentType = entry.contentType;
                    descs.push(desc);
                    totalAttachmentBytes += bytes.length;
                  } else {
                    failed.push(typeof entry === "object" ? JSON.stringify(entry) : String(entry));
                  }
                } catch (e) {
                  const label = entry && typeof entry === "object" ? (entry.name || JSON.stringify(entry)) : String(entry);
                  failed.push(`${label} (${e.message || e})`);
                }
              }
              // Materialize native attachments before any send/draft/window.
              // The helper caches them on the private descriptors for later use.
              if (!failed.length) {
                try { descsToMsgAttachments(descs); } catch (e) { failed.push(e.message || String(e)); }
              }
              if (failed.length) {
                for (const tmpFile of createdTempFiles) {
                  try {
                    tmpFile.remove(false);
                    _tempAttachFiles.delete(tmpFile.path);
                  } catch (e) {
                    // Retain it in the shutdown cleanup set if removal failed.
                    console.warn("thundersend-mcp: temporary attachment cleanup failed:", e);
                  }
                }
                throw new Error(`Attachments refused: ${failed.join(", ")}`);
              }
              return { descs, failed };
            }
            // END OUTBOUND ATTACHMENT CONVERSION

            /**
             * Converts attachment descriptors to nsIMsgAttachment objects.
             * Shared by the new-compose path (composeFields.addAttachment),
             * the reply/forward observer path (addAttachmentsToComposeWindow),
             * and sendMessageDirectly (headless send).
             */
            // BEGIN NATIVE ATTACHMENT CONVERSION
            function descsToMsgAttachments(attachDescs) {
              const result = [];
              for (const desc of attachDescs) {
                if (desc.msgAttachment) {
                  result.push(desc.msgAttachment);
                  continue;
                }
                try {
                  const att = Cc["@mozilla.org/messengercompose/attachment;1"]
                    .createInstance(Ci.nsIMsgAttachment);
                  att.url = desc.url;
                  att.name = desc.name;
                  if (desc.size != null) att.size = desc.size;
                  if (desc.contentType) att.contentType = desc.contentType;
                  desc.msgAttachment = att;
                  result.push(att);
                } catch (e) {
                  throw new Error(`Attachment refused: ${desc.url || desc.name} (${e.message || e})`, { cause: e });
                }
              }
              return result;
            }

            // END NATIVE ATTACHMENT CONVERSION

            /**
             * Sends a message directly via nsIMsgSend without opening a compose window.
             * Used by composeMail, replyToMessage, forwardMessage when skipReview=true.
             *
             * Handles two createAndSendMessage signatures:
             * - TB 102-127 (C++): 18 args, includes aAttachments + aPreloadedAttachments
             * - TB 128+   (JS):  16 args, attachments via composeFields only
             * Attachments are always added to composeFields (works in both).
             * We try the modern 16-arg call first; if TB throws
             * NS_ERROR_XPC_NOT_ENOUGH_ARGS, fall back to the legacy 18-arg call.
             */
            // BEGIN DIRECT SEND HELPER
            function sendMessageDirectly(composeFields, identity, attachDescs, originalMsgURI, compType, deliverMode, bodyType, msgToReplace) {
              if (!identity) {
                return Promise.resolve({ error: "No identity available for direct send" });
              }

              const mode = deliverMode ?? Ci.nsIMsgCompDeliverMode.Now;
              const bodyMimeType = bodyType || "text/html";
              const SEND_TIMEOUT_MS = 120000; // 2 min safety timeout

              return new Promise((resolve) => {
                let settled = false;
                const settle = (result) => {
                  if (!settled) {
                    settled = true;
                    resolve(result);
                  }
                };

                // Safety timeout -- if neither listener callback nor error fires
                const timer = Cc["@mozilla.org/timer;1"].createInstance(Ci.nsITimer);
                timer.initWithCallback({
                  notify() {
                    settle({ error: mode === Ci.nsIMsgCompDeliverMode.Now
                      ? "Send timed out after 120s. The outcome is unknown; check Sent and the Outbox before retrying."
                      : "Save timed out after 120s. The outcome is unknown; check Drafts and the Outbox before retrying." });
                  }
                }, SEND_TIMEOUT_MS, Ci.nsITimer.TYPE_ONE_SHOT);

                try {
                  const msgSend = Cc["@mozilla.org/messengercompose/send;1"]
                    .createInstance(Ci.nsIMsgSend);

                  // Populate sender fields from identity (normally done by compose window)
                  if (identity.email) {
                    const name = identity.fullName || "";
                    composeFields.from = name
                      ? `"${name}" <${identity.email}>`
                      : identity.email;
                  }
                  if (identity.organization) {
                    composeFields.organization = identity.organization;
                  }

                  // Add attachments to composeFields (works in all TB versions)
                  for (const att of descsToMsgAttachments(attachDescs)) {
                    composeFields.addAttachment(att);
                  }

                  // Extract body -- createAndSendMessage takes it as a separate param
                  const body = composeFields.body || "";

                  // Resolve account key from identity
                  let accountKey = "";
                  try {
                    for (const account of MailServices.accounts.accounts) {
                      for (let i = 0; i < account.identities.length; i++) {
                        if (account.identities[i].key === identity.key) {
                          accountKey = account.key;
                          break;
                        }
                      }
                      if (accountKey) break;
                    }
                  } catch {}

                  // SaveAsDraft mode routes through _mimeDoFcc() which does not
                  // call onStopSending. Completion is signaled via the copy
                  // service's onStopCopy after the message lands in the Drafts
                  // folder, so the listener also QIs nsIMsgCopyServiceListener.
                  const listener = {
                    QueryInterface: ChromeUtils.generateQI(["nsIMsgSendListener", "nsIMsgCopyServiceListener"]),
                    // nsIMsgSendListener -- fires for SMTP send paths
                    onStartSending() {},
                    onProgress() {},
                    onSendProgress() {},
                    onStatus() {},
                    onStopSending(msgID, status) {
                      timer.cancel();
                      if (Components.isSuccessCode(status)) {
                        settle({ success: true, message: "Message sent" });
                      } else {
                        settle({ error: `Send failed (status: 0x${status.toString(16)})` });
                      }
                    },
                    onGetDraftFolderURI() {},
                    onSendNotPerformed(msgID, status) {
                      timer.cancel();
                      settle({ error: "Send was not performed" });
                    },
                    onTransportSecurityError(msgID, status, secInfo, location) {
                      timer.cancel();
                      settle({ error: `Transport security error${location ? ": " + location : ""}` });
                    },
                    // nsIMsgCopyServiceListener -- fires for SaveAsDraft / Sent-folder copy
                    onStartCopy() {},
                    setMessageKey() {},
                    onStopCopy(status) {
                      // A Sent-folder copy says nothing about SMTP delivery and
                      // must not cancel the delivery timeout, even on failure.
                      if (mode === Ci.nsIMsgCompDeliverMode.Now) return;
                      timer.cancel();
                      if (Components.isSuccessCode(status)) {
                        settle({ success: true, message: "Saved" });
                      } else {
                        settle({ error: `Save failed (status: 0x${status.toString(16)})` });
                      }
                    },
                  };

                  // Common args shared by both signatures (positions 1-10)
                  const commonArgs = [
                    null,                           // editor
                    identity,                       // identity
                    accountKey,                     // account key
                    composeFields,                  // fields
                    false,                          // isDigest
                    false,                          // dontDeliver
                    mode,                           // deliver mode
                    msgToReplace || null,           // msgToReplace
                    bodyMimeType,                   // body type
                    body,                           // body
                  ];

                  // Tail args shared by both (parentWindow..compType)
                  const tailArgs = [
                    null,                           // parent window
                    null,                           // progress
                    listener,                       // listener
                    "",                             // password
                    originalMsgURI || "",           // original msg URI
                    compType,                       // compose type
                  ];

                  // Try modern 16-arg signature first (TB 128+).
                  // On TB 102-127, XPCOM throws NS_ERROR_XPC_NOT_ENOUGH_ARGS
                  // (0x80570001), so we fall back to legacy 18-arg with null
                  // attachment params (attachments already on composeFields).
                  // Modern TB may return a Promise -- catch async rejections.
                  let sendResult;
                  try {
                    sendResult = msgSend.createAndSendMessage(...commonArgs, ...tailArgs);
                  } catch (e) {
                    const isArgError = (e && e.result === 0x80570001) ||
                      String(e).includes("Not enough arguments");
                    if (isArgError) {
                      sendResult = msgSend.createAndSendMessage(...commonArgs, null, null, ...tailArgs);
                    } else {
                      throw e;
                    }
                  }
                  // Modern TB (128+) returns a Promise from createAndSendMessage.
                  // For immediate sends this fulfills when delivery starts, so
                  // only onStopSending may report success. Saves/queued mail
                  // still support promise completion as well as onStopCopy.
                  if (sendResult && typeof sendResult.then === "function") {
                    sendResult.then(
                      () => {
                        if (mode !== Ci.nsIMsgCompDeliverMode.Now) {
                          timer.cancel();
                          settle({ success: true });
                        }
                      },
                      e => {
                        timer.cancel();
                        settle({ error: e.toString() });
                      }
                    );
                  }
                } catch (e) {
                  timer.cancel();
                  settle({ error: e.toString() });
                }
              });
            }

            // END DIRECT SEND HELPER

            // BEGIN HTML ESCAPE HELPER
            function escapeHtml(s) {
              return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
            }

            // END HTML ESCAPE HELPER

            /**
             * Converts body text to HTML for compose fields.
             * Handles both HTML input (entity-encodes non-ASCII) and plain text.
             */
            // BEGIN COMPOSE SIGNATURE HELPERS
            function formatBodyHtml(body, isHtml) {
              if (isHtml) {
                let text = (body || "").replace(/\n/g, '');
                text = [...text].map(c => c.codePointAt(0) > 127 ? `&#${c.codePointAt(0)};` : c).join('');
                return text;
              }
              return escapeHtml(body || "").replace(/\n/g, '<br>');
            }

            /**
             * Reads the identity's signature: either the sig_file on disk
             * (attach_signature=true) or the inline htmlSigText.
             *
             * Returns { content, isHtmlSig } or null when the identity has none.
             */
            function readSignatureFileText(file) {
              const MAX_SIGNATURE_FILE_BYTES = 1024 * 1024;
              const size = file.fileSize;
              if (!Number.isSafeInteger(size) || size < 0 || size > MAX_SIGNATURE_FILE_BYTES) {
                throw new Error("Signature file exceeds the 1 MiB limit or has an invalid size");
              }
              const fstream = Cc["@mozilla.org/network/file-input-stream;1"]
                .createInstance(Ci.nsIFileInputStream);
              try {
                fstream.init(file, -1, 0, 0);
                // Bound actual bytes too, in case the file grows after stat.
                const raw = readMessageStreamFully(fstream, MAX_SIGNATURE_FILE_BYTES);
                return new TextDecoder("utf-8").decode(Uint8Array.from(raw, c => c.charCodeAt(0)));
              } finally {
                try { fstream.close(); } catch (e) { /* already closed */ }
              }
            }

            function getIdentitySignature(identity) {
              if (!identity) return null;
              try {
                if (identity.attachSignature) {
                  const file = identity.signature;
                  if (file && file.exists() && file.isFile()) {
                    const content = readSignatureFileText(file);
                    if (content && content.trim()) {
                      return { content, isHtmlSig: /\.html?$/i.test(file.leafName) };
                    }
                  }
                }
                const inline = identity.htmlSigText;
                if (inline && inline.trim()) {
                  return { content: inline, isHtmlSig: identity.htmlSigFormat === true };
                }
              } catch (error) {
                console.warn("thundersend-mcp: could not read identity signature", error);
              }
              return null;
            }

            /**
             * Signatures are often stored as a whole document (htmlSigText from
             * a signature generator keeps <!DOCTYPE><html><head>...). Embedding
             * that inside our <body> would nest documents, so keep the body's
             * inner HTML only -- which is what Thunderbird's compose editor
             * effectively does when it inserts the signature.
             */
            function unwrapHtmlDocument(html) {
              if (!/<(?:html|body|head)\b/i.test(html)) return html;

              // NOTE: DOMParser is NOT reliably available in this ExtensionAPI
              // scope (see the globals comment at the top of this file, and the
              // stripHtml fallback in htmlToMarkdown). Guard on typeof -- a bare
              // `new DOMParser()` throws ReferenceError, and swallowing it in a
              // catch would silently return the document unwrapped.
              try {
                if (typeof DOMParser !== "undefined") {
                  const doc = new DOMParser().parseFromString(html, "text/html");
                  if (doc && doc.body) return doc.body.innerHTML;
                }
              } catch (error) {
                console.warn("thundersend-mcp: DOMParser unwrap failed, stripping envelope textually", error);
              }

              const body = /<body\b[^>]*>([\s\S]*)<\/body>/i.exec(html);
              if (body) return body[1];
              return html
                .replace(/<!DOCTYPE[^>]*>/gi, "")
                .replace(/<head\b[^>]*>[\s\S]*?<\/head>/gi, "")
                .replace(/<\/?(?:html|body)\b[^>]*>/gi, "");
            }

            function htmlSignatureToPlainText(html) {
              try {
                const parserUtils = Cc["@mozilla.org/parserutils;1"].getService(Ci.nsIParserUtils);
                return parserUtils.convertToPlainText(
                  html,
                  Ci.nsIDocumentEncoder.OutputFormatted | Ci.nsIDocumentEncoder.OutputLFLineBreak,
                  0
                ).replace(/\s+$/, "");
              } catch (error) {
                console.warn("thundersend-mcp: parserUtils unavailable, stripping tags", error);
                return html.replace(/<br\s*\/?>/gi, "\n").replace(/<[^>]*>/g, "").trim();
              }
            }

            /**
             * Builds the trailing signature fragment for a body we compose
             * ourselves.
             *
             * Thunderbird inserts signatures from its compose window only
             * (gMsgCompose reads htmlSigText/sig_file and honours sig_bottom).
             * The createAndSendMessage path behind saveDraft and skipReview
             * sends never opens that window, so without this the message ships
             * with no signature at all. New messages carry no quote, so
             * sig_bottom does not apply: the signature always goes last.
             *
             * Returns "" when the identity has no signature.
             */
            function buildSignatureFragment(identity, useHtml) {
              const sig = getIdentitySignature(identity);
              if (!sig) return "";

              const asText = sig.isHtmlSig ? htmlSignatureToPlainText(sig.content) : sig.content;
              // Thunderbird prepends the "-- " separator unless the signature
              // already opens with one (mail.compose.dont_add_signature_separator).
              const hasSeparator = /^\s*--\s*$/m.test(asText.split("\n")[0] || "");

              if (useHtml) {
                const sigHtml = sig.isHtmlSig
                  ? formatBodyHtml(unwrapHtmlDocument(sig.content), true)
                  : formatBodyHtml(sig.content, false);
                const separator = hasSeparator ? "" : "-- <br>";
                return `<br><div class="moz-signature">${separator}${sigHtml}</div>`;
              }

              const separator = hasSeparator ? "" : "-- \n";
              return `\n\n${separator}${asText}`;
            }

            /**
             * Shapes composeFields.body for the direct-send paths, appending the
             * identity signature. Mirrors the plain/HTML envelope rules used by
             * the compose-window paths.
             */
            function buildBodyWithSignature(body, identity, useHtml, isHtml, includeSignature = true) {
              const sigFragment = includeSignature ? buildSignatureFragment(identity, useHtml) : "";

              if (!useHtml) {
                return (body || "") + sigFragment;
              }

              const formatted = formatBodyHtml(body, isHtml);
              if (isHtml && formatted.includes('<html')) {
                if (!sigFragment) return formatted;
                return /<\/body>/i.test(formatted)
                  ? formatted.replace(/<\/body>/i, () => `${sigFragment}</body>`)
                  : formatted + sigFragment;
              }
              return `<html><head><meta charset="UTF-8"></head><body>${formatted}${sigFragment}</body></html>`;
            }
            // END COMPOSE SIGNATURE HELPERS

            /**
             * Decides whether a compose operation will (or should) run in HTML
             * mode, and returns the matching msgComposeParams.format value.
             *
             * The caller's explicit isHtml wins (true/false). When isHtml is
             * omitted, the identity's compose-format preference is consulted.
             *
             * ForwardInline is a special case: Thunderbird's compose service
             * only passes format through when it's Default or OppositeOfDefault
             * for that compType, so when the caller's explicit isHtml conflicts
             * with the identity pref on a forward, we have to ask for
             * OppositeOfDefault instead of HTML/PlainText.
             *
             * Identity must be resolved (setComposeIdentity) before calling this.
             */
            function resolveComposeFormat(identity, isHtml, compType) {
              const identityUsesHtml = identity?.composeHtml !== false;
              const useHtml = isHtml === true || (isHtml !== false && identityUsesHtml);
              const isForward = compType === Ci.nsIMsgCompType.ForwardInline
                             || compType === Ci.nsIMsgCompType.ForwardAsAttachment;

              let format;
              if (isHtml === undefined) {
                format = Ci.nsIMsgCompFormat.Default;
              } else if (isForward) {
                const explicitMatchesPref = (isHtml === true) === identityUsesHtml;
                format = explicitMatchesPref
                  ? Ci.nsIMsgCompFormat.Default
                  : Ci.nsIMsgCompFormat.OppositeOfDefault;
              } else {
                format = isHtml === true ? Ci.nsIMsgCompFormat.HTML : Ci.nsIMsgCompFormat.PlainText;
              }
              return { useHtml, format };
            }

            /**
             * Sets compose identity from `from` param or falls back to default.
             * Returns "" on success, or { error } if `from` was explicitly
             * provided but not found / restricted.  Fallback to default only
             * applies when `from` is omitted.
             */
            function setComposeIdentity(msgComposeParams, from, fallbackServer) {
              if (from) {
                // Explicit `from` -- must resolve or fail, never silently substitute
                const identity = findIdentity(from);
                if (identity) {
                  // findIdentity searches accessible accounts, so this is safe
                  msgComposeParams.identity = identity;
                  return "";
                }
                // Not found in accessible accounts -- check ALL accounts to
                // distinguish "restricted" from "genuinely unknown"
                if (findIdentityIn(MailServices.accounts.accounts, from)) {
                  return { error: `identity ${from} belongs to a restricted account` };
                }
                return { error: `unknown identity: ${from} -- no matching account configured in Thunderbird` };
              }
              // No explicit `from` -- fall back to contextual default
              if (fallbackServer) {
                const account = MailServices.accounts.findAccountForServer(fallbackServer);
                if (account && isAccountAllowed(account.key)) {
                  msgComposeParams.identity = account.defaultIdentity;
                }
              } else {
                const defaultAccount = MailServices.accounts.defaultAccount;
                if (defaultAccount && isAccountAllowed(defaultAccount.key)) {
                  msgComposeParams.identity = defaultAccount.defaultIdentity;
                }
              }
              // If no identity was set (all fallbacks restricted), explicitly set
              // the first accessible identity. Without this, Thunderbird's
              // OpenComposeWindowWithParams fills identity from defaultAccount
              // internally, bypassing account restrictions.
              if (!msgComposeParams.identity) {
                for (const account of getAccessibleAccounts()) {
                  if (account.defaultIdentity) {
                    msgComposeParams.identity = account.defaultIdentity;
                    break;
                  }
                }
                if (!msgComposeParams.identity) {
                  return { error: "No accessible identity found -- all accounts are restricted" };
                }
              }
              return "";
            }

	            /**
	             * Opens a folder and its message database.
	             * Best-effort refresh for IMAP folders (db may be stale).
	             * Returns { folder, db } or { error }.
	             */
	            function openFolder(folderPath) {
	              try {
	                const result = getAccessibleFolder(folderPath);
	                if (result.error) return result;
	                const folder = result.folder;

	                refreshImapFolderSync(folder);

	                const db = folder.msgDatabase;
	                if (!db) {
	                  return { error: "Could not access folder database" };
	                }

	                return { folder, db };
	              } catch (e) {
	                return { error: e.toString() };
	              }
	            }

	            /**
	             * Finds a single message header by messageId within a folderPath.
	             * Returns { msgHdr, folder, db } or { error }.
	             */
	            function findMessage(messageId, folderPath) {
	              const opened = openFolder(folderPath);
	              if (opened.error) return opened;

	              const { folder, db } = opened;
	              let msgHdr = null;

	              const hasDirectLookup = typeof db.getMsgHdrForMessageID === "function";
	              if (hasDirectLookup) {
	                try {
	                  msgHdr = db.getMsgHdrForMessageID(messageId);
	                } catch {
	                  msgHdr = null;
	                }
	              }

	              if (!msgHdr) {
	                for (const hdr of db.enumerateMessages()) {
	                  if (hdr.messageId === messageId) {
	                    msgHdr = hdr;
	                    break;
	                  }
	                }
	              }

	              if (!msgHdr) {
	                return { error: `Message not found: ${messageId}` };
	              }

	              return { msgHdr, folder, db };
	            }

            // BEGIN OUTBOUND MAIL TOOLS
            function composeMail(to, subject, body, cc, bcc, isHtml, from, attachments, skipReview, includeSignature = true) {
              try {
                if (skipReview && isSkipReviewBlocked()) {
                  return { error: "User preference blocks skipReview. Retry with skipReview: false (or omitted) to open the review window instead." };
                }
                const msgComposeParams = Cc["@mozilla.org/messengercompose/composeparams;1"]
                  .createInstance(Ci.nsIMsgComposeParams);

                const composeFields = Cc["@mozilla.org/messengercompose/composefields;1"]
                  .createInstance(Ci.nsIMsgCompFields);

                composeFields.to = to || "";
                composeFields.cc = cc || "";
                composeFields.bcc = bcc || "";
                composeFields.subject = subject || "";

                msgComposeParams.type = Ci.nsIMsgCompType.New;
                msgComposeParams.composeFields = composeFields;

                const identityResult = setComposeIdentity(msgComposeParams, from, null);
                if (identityResult && identityResult.error) return identityResult;

                // Match body shape and format to caller intent / identity pref.
                // When the resolved mode is plain, ship a plain body -- the HTML
                // envelope would otherwise render as literal text in plain-mode
                // editors and recipients.
                const { useHtml, format } = resolveComposeFormat(msgComposeParams.identity, isHtml, Ci.nsIMsgCompType.New);
                msgComposeParams.format = format;
                if (useHtml) {
                  const formatted = formatBodyHtml(body, isHtml);
                  composeFields.body = isHtml && formatted.includes('<html')
                    ? formatted
                    : `<html><head><meta charset="UTF-8"></head><body>${formatted}</body></html>`;
                } else {
                  composeFields.body = body || "";
                }

                const { descs: fileDescs } = filePathsToAttachDescs(attachments);

                if (skipReview) {
                  // Direct send bypasses the compose window, so the identity
                  // signature has to be appended here. The review path below
                  // must NOT get it -- Thunderbird adds it when the window
                  // opens, and doing both would duplicate it.
                  composeFields.body = buildBodyWithSignature(body, msgComposeParams.identity, useHtml, isHtml, includeSignature);
                  return sendMessageDirectly(composeFields, msgComposeParams.identity, fileDescs, null, Ci.nsIMsgCompType.New, Ci.nsIMsgCompDeliverMode.Now, useHtml ? "text/html" : "text/plain").then(result => {
                    if (result.success) {
                      let msg = "Message sent";
                      result.message = msg;
                    }
                    return result;
                  });
                }

                // Attach via composeFields BEFORE opening the window so it
                // renders with the attachments already present. This avoids the
                // old getMostRecentWindow("msgcompose") race: that helper returns
                // the most recently *focused* compose window, so a second
                // sendMail call -- or the user simply clicking an older compose
                // window while this one opens -- would steal or drop the
                // attachments. composeFields binds them to this exact message,
                // exactly like the direct-send path (sendMessageDirectly).
                for (const att of descsToMsgAttachments(fileDescs)) {
                  composeFields.addAttachment(att);
                }

                const msgComposeService = Cc["@mozilla.org/messengercompose;1"]
                  .getService(Ci.nsIMsgComposeService);
                msgComposeService.OpenComposeWindowWithParams(null, msgComposeParams);

                let msg = "Compose window opened";
                return { success: true, message: msg };
              } catch (e) {
                return { error: e.toString() };
              }
            }

            // BEGIN DRAFT HELPERS
            function getIdentityDraftFolderURI(identity) {
              // ESR 128 uses draftFolder; newer Thunderbird uses draftsFolderURI.
              for (const prop of ["draftsFolderURI", "draftFolder"]) {
                try {
                  const value = identity?.[prop];
                  const uri = typeof value === "string" ? value : value?.URI;
                  if (typeof uri === "string" && /^[a-z]+:\/\//i.test(uri)) return uri;
                } catch {
                  // A missing property may be undefined or throw on older versions.
                }
              }
              return null;
            }

            function isValidMessageIdList(value, maxCount) {
              // Reject rather than trim, bracket, or unfold caller-supplied headers.
              if (typeof value !== "string" || !value || value.length > 16384 || /[\x00-\x1f\x7f-\x9f]/.test(value)) return false;
              const ids = value.split(" ");
              return ids.length <= maxCount && ids.every(id => id.length <= 998 && /^<[^<>\s@]+@[^<>\s@]+>$/.test(id));
            }
            // END DRAFT HELPERS

            /**
             * Saves a composed message to the identity's Drafts folder without
             * sending or opening a compose window. The destination folder is
             * resolved by Thunderbird from the identity's draft-folder pref.
             *
             * With replaceMessageId set, the named draft is REPLACED rather than
             * a second one added: the resolved header goes to createAndSendMessage
             * as msgToReplace, which is what makes Thunderbird drop the original
             * once the new draft is written. A draft body cannot be edited in
             * place through this API surface, so without that argument every
             * correction of a saved draft would accumulate one more copy in the
             * Drafts folder, and the caller has no way to remove the stale one.
             */
            // BEGIN SAVE DRAFT TOOL
            function saveDraft(to, subject, body, cc, bcc, isHtml, from, attachments, inReplyTo, references, replaceMessageId, replaceFolderPath, includeSignature) {
              try {
                if (inReplyTo !== undefined && !isValidMessageIdList(inReplyTo, 1)) {
                  return { error: "inReplyTo must be one bracketed Message-ID (<id@example.com>), at most 998 characters, without whitespace or control characters" };
                }
                if (references !== undefined && !isValidMessageIdList(references, 100)) {
                  return { error: "references must be up to 100 bracketed Message-IDs separated by single spaces, at most 998 characters per ID and 16384 total, without control characters" };
                }
                if (replaceMessageId !== undefined && (typeof replaceMessageId !== "string" || !replaceMessageId.trim())) {
                  return { error: "replaceMessageId must be a non-empty message ID" };
                }
                const msgComposeParams = Cc["@mozilla.org/messengercompose/composeparams;1"]
                  .createInstance(Ci.nsIMsgComposeParams);

                const composeFields = Cc["@mozilla.org/messengercompose/composefields;1"]
                  .createInstance(Ci.nsIMsgCompFields);

                composeFields.to = to || "";
                composeFields.cc = cc || "";
                composeFields.bcc = bcc || "";
                composeFields.subject = subject || "";

                // Direct draft saves have no originalMsgURI to derive threading.
                if (inReplyTo !== undefined) {
                  composeFields.setHeader("In-Reply-To", inReplyTo);
                  composeFields.references = inReplyTo;
                }
                if (references !== undefined) composeFields.references = references;

                // Resolve the draft to replace BEFORE composing anything: an
                // unresolvable id must fail the whole call, never silently fall
                // back to appending a second draft -- that failure mode is
                // indistinguishable from success at the call site.
                let msgToReplace = null;
                let replaceFolder = null;
                if (replaceMessageId) {
                  // findMessage is folder-scoped; without a folder the lookup
                  // fails as "Folder not found: undefined", which reads like a
                  // broken folder rather than a missing argument.
                  if (!replaceFolderPath) {
                    return { error: "replaceMessageId requires replaceFolderPath (the folder URI from searchMessages)" };
                  }
                  const found = findMessage(replaceMessageId, replaceFolderPath);
                  if (found.error) return { error: found.error };
                  // The send API deletes via the header's own folder, which must
                  // be the same accessible folder checked by findMessage.
                  const sourceFolder = found.msgHdr?.folder;
                  if (!sourceFolder?.URI || sourceFolder.URI !== found.folder?.URI) {
                    return { error: "Cannot replace draft: the message is not stored in the requested Drafts folder" };
                  }
                  let isDrafts = false;
                  try { isDrafts = typeof sourceFolder.getFlag === "function" && sourceFolder.getFlag(Ci.nsMsgFolderFlags.Drafts); } catch { /* fail closed */ }
                  if (!isDrafts) {
                    return { error: "replaceMessageId must name a message in an accessible folder with the Drafts flag" };
                  }
                  msgToReplace = found.msgHdr;
                  replaceFolder = sourceFolder;
                }

                msgComposeParams.type = replaceMessageId
                  ? Ci.nsIMsgCompType.Draft
                  : Ci.nsIMsgCompType.New;
                msgComposeParams.composeFields = composeFields;

                const identityResult = setComposeIdentity(msgComposeParams, from, null);
                if (identityResult && identityResult.error) return identityResult;

                if (msgToReplace) {
                  const draftURI = getIdentityDraftFolderURI(msgComposeParams.identity);
                  if (!draftURI) return { error: "Cannot replace draft: the selected identity has no configured Drafts folder" };
                  let destination;
                  try { destination = getAccessibleFolder(draftURI); } catch { /* fail closed below */ }
                  if (!destination || destination.error) return { error: "Cannot replace draft: the selected identity's Drafts folder is not accessible" };
                  if (destination.folder.URI !== replaceFolder.URI) {
                    return { error: "Cannot replace draft outside the selected identity's configured Drafts folder; select the matching from identity" };
                  }
                }

                const { useHtml, format } = resolveComposeFormat(msgComposeParams.identity, isHtml, msgComposeParams.type);
                msgComposeParams.format = format;
                // saveDraft always builds the message directly, so Thunderbird's
                // compose window never runs and never inserts the signature --
                // we have to append it ourselves. A fetched draft normally has
                // its signature already, so replacements default to preserving it.
                composeFields.body = buildBodyWithSignature(body, msgComposeParams.identity, useHtml, isHtml, includeSignature ?? !msgToReplace);

                const { descs: fileDescs } = filePathsToAttachDescs(attachments);

                return sendMessageDirectly(
                  composeFields,
                  msgComposeParams.identity,
                  fileDescs,
                  null,
                  msgComposeParams.type,
                  Ci.nsIMsgCompDeliverMode.SaveAsDraft,
                  useHtml ? "text/html" : "text/plain",
                  msgToReplace
                ).then(result => {
                  if (result.success) {
                    let msg = msgToReplace ? "Draft replaced" : "Draft saved";
                    result.message = msg;

                    // Thunderbird can populate the identity's folder during save.
                    // Report it only if accessible; lookup errors may contain a
                    // restricted URI, so keep them out of this successful result.
                    const folderPath = getIdentityDraftFolderURI(msgComposeParams.identity);
                    try {
                      if (folderPath && !getAccessibleFolder(folderPath).error) result.folderPath = folderPath;
                    } catch { /* best-effort destination reporting */ }
                  }
                  return result;
                });
              } catch (e) {
                return { error: e.toString() };
              }
            }
            // END SAVE DRAFT TOOL
            // END OUTBOUND MAIL TOOLS

            // BEGIN TOOL SCHEMA VALIDATOR
            function validateAgainstSchema(value, schema, path, errors) {
              if (!schema || value === undefined || value === null) return;

              const expectedType = schema.type;
              if (expectedType === "array") {
                if (!Array.isArray(value)) {
                  errors.push(`Parameter '${path}' must be an array, got ${typeof value}`);
                  return;
                }
                if (schema.items) {
                  for (let i = 0; i < value.length; i++) {
                    // Array items are never nullable: validateAgainstSchema
                    // returns early on null/undefined, so a null item would
                    // otherwise skip the item schema entirely. Reject explicitly.
                    if (value[i] === null || value[i] === undefined) {
                      errors.push(`Parameter '${path}[${i}]' must not be null`);
                      continue;
                    }
                    validateAgainstSchema(value[i], schema.items, `${path}[${i}]`, errors);
                  }
                }
              } else if (expectedType === "object") {
                if (typeof value !== "object" || Array.isArray(value)) {
                  errors.push(`Parameter '${path}' must be an object, got ${Array.isArray(value) ? "array" : typeof value}`);
                  return;
                }
                const nestedProps = schema.properties || {};
                const nestedRequired = schema.required || [];
                // Inline attachment objects accept `content` as a legacy alias,
                // but runtime uses `base64` whenever it is present. Do not reject
                // an ignored `content` value after the preferred payload validates.
                const hasPreferredBase64 = value.base64 !== undefined
                  && value.base64 !== null
                  && nestedProps.base64?.contentEncoding === "base64"
                  && nestedProps.content?.contentEncoding === "base64";
                for (const r of nestedRequired) {
                  if (value[r] === undefined || value[r] === null) {
                    errors.push(`Missing required parameter: ${path}.${r}`);
                  }
                }
                for (const [k, v] of Object.entries(value)) {
                  if (k === "content" && hasPreferredBase64) continue;
                  const has = Object.prototype.hasOwnProperty.call(nestedProps, k);
                  if (!has) {
                    if (schema.additionalProperties === false) {
                      errors.push(`Unknown parameter: ${path}.${k}`);
                    }
                    continue;
                  }
                  validateAgainstSchema(v, nestedProps[k], `${path}.${k}`, errors);
                }
              } else if (expectedType === "integer") {
                if (typeof value !== "number" || !Number.isInteger(value)) {
                  errors.push(`Parameter '${path}' must be an integer, got ${typeof value === "number" ? "non-integer number" : typeof value}`);
                  return;
                }
              } else if (expectedType && typeof value !== expectedType) {
                errors.push(`Parameter '${path}' must be ${expectedType}, got ${typeof value}`);
                return;
              }

              if (expectedType === "string") {
                if (schema.minLength !== undefined && value.length < schema.minLength) {
                  errors.push(`Parameter '${path}' must contain at least ${schema.minLength} character(s)`);
                }
                if (schema.contentEncoding === "base64" && !isValidBase64(value)) {
                  errors.push(`Parameter '${path}' must contain valid base64 data`);
                }
              }

              // anyOf: accept the value when one or more branches validate.
              if (Array.isArray(schema.anyOf) && schema.anyOf.length > 0) {
                let matched = 0;
                const branchFailures = [];
                for (const branch of schema.anyOf) {
                  const branchErrors = [];
                  validateAgainstSchema(value, branch, path, branchErrors);
                  if (branchErrors.length === 0) matched++;
                  else branchFailures.push(branchErrors);
                }
                if (matched === 0) {
                  const details = [...new Set(branchFailures.flat())].join("; ");
                  errors.push(`Parameter '${path}' did not match any required schema alternative${details ? `: ${details}` : ""}`);
                }
              }

              // oneOf: accept the value if exactly one branch validates clean.
              // Used by the attachments array items (string | object).
              if (Array.isArray(schema.oneOf) && schema.oneOf.length > 0) {
                let matched = 0;
                const branchFailures = [];
                for (const branch of schema.oneOf) {
                  const branchErrors = [];
                  validateAgainstSchema(value, branch, path, branchErrors);
                  if (branchErrors.length === 0) matched++;
                  else branchFailures.push(branchErrors);
                }
                if (matched === 0) {
                  const details = [...new Set(branchFailures.flat())].join("; ");
                  errors.push(`Parameter '${path}' did not match any allowed schema variant${details ? `: ${details}` : ""}`);
                } else if (matched > 1) {
                  errors.push(`Parameter '${path}' matched more than one schema variant`);
                }
              }

              // enum: explicit value allow-list (e.g. bodyFormat).
              if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
                errors.push(`Parameter '${path}' must be one of ${JSON.stringify(schema.enum)}, got ${JSON.stringify(value)}`);
              }
            }
            // END TOOL SCHEMA VALIDATOR

            // BEGIN TOOL CALL DISPATCH
            function validateToolArgs(name, args) {
              const tool = buildTools().find(t => t.name === name);
              const schema = tool?.inputSchema;
              if (!schema) return [`Unknown tool: ${name}`];

              const errors = [];
              const props = schema.properties || {};
              const required = schema.required || [];

              // Check required fields
              for (const key of required) {
                if (args[key] === undefined || args[key] === null) {
                  errors.push(`Missing required parameter: ${key}`);
                }
              }

              // Check types and reject unknown properties
              for (const [key, value] of Object.entries(args)) {
                // Use hasOwnProperty to prevent inherited properties like
                // 'constructor' or 'toString' from bypassing unknown-param checks.
                const propSchema = Object.prototype.hasOwnProperty.call(props, key) ? props[key] : undefined;
                if (!propSchema) {
                  errors.push(`Unknown parameter: ${key}`);
                  continue;
                }
                if (value === undefined || value === null) continue;

                validateAgainstSchema(value, propSchema, key, errors);
                // minItems/maxItems sit outside validateAgainstSchema (which covers
                // type/items/object/integer/oneOf/enum); keep the array-length bounds
                // so the v0.6.0 getMessages-batch caps stay enforced.
                if (propSchema.type === "array" && Array.isArray(value)) {
                  if (propSchema.minItems !== undefined && value.length < propSchema.minItems) {
                    errors.push(`Parameter '${key}' must contain at least ${propSchema.minItems} item(s)`);
                  }
                  if (propSchema.maxItems !== undefined && value.length > propSchema.maxItems) {
                    errors.push(`Parameter '${key}' must contain at most ${propSchema.maxItems} item(s)`);
                  }
                }
              }

              return errors;
            }

            /**
             * Coerce tool arguments to match expected schema types.
             * MCP clients may send "true"/"false" as strings for booleans,
             * "50" as strings for numbers, or JSON-encoded arrays as strings.
             * Mutates and returns the args object.
             */
            function coerceToolArgs(name, args) {
              const tool = buildTools().find(t => t.name === name);
              const schema = tool?.inputSchema;
              if (!schema) return args;
              const props = schema.properties || {};
              for (const [key, value] of Object.entries(args)) {
                if (value === undefined || value === null) continue;
                const propSchema = Object.prototype.hasOwnProperty.call(props, key) ? props[key] : undefined;
                if (!propSchema) continue;
                const expected = propSchema.type;
                if (expected === "boolean" && typeof value === "string") {
                  if (value === "true") args[key] = true;
                  else if (value === "false") args[key] = false;
                } else if (expected === "number" && typeof value === "string") {
                  // Reject blank/whitespace strings -- Number("") is 0 which
                  // would silently coerce empty input into a valid number.
                  if (value.trim() === "") continue;
                  const n = Number(value);
                  if (Number.isFinite(n)) args[key] = n;
                } else if (expected === "integer" && typeof value === "string") {
                  if (value.trim() === "") continue;
                  const n = Number(value);
                  if (Number.isFinite(n) && Number.isInteger(n)) args[key] = n;
                } else if (expected === "array" && typeof value === "string") {
                  try {
                    const parsed = JSON.parse(value);
                    if (Array.isArray(parsed)) args[key] = parsed;
                  } catch (e) {
                    // Leave value as-is so validator surfaces a typed error to the client.
                    console.warn(`thundersend-mcp: coerceToolArgs JSON.parse failed for key=${key}:`, e.message);
                  }
                }
              }
              return args;
            }

            // BEGIN TOOL DISPATCH
            async function callTool(name, args) {
              return sanitizeToolResultText(await dispatchTool(name, args));
            }

            async function dispatchTool(name, args) {
              switch (name) {
                case "listAccounts":
                  return listAccounts();
                case "getAccountAccess":
                  return getAccountAccess();
                case "sendMail":
                  return await composeMail(args.to, args.subject, args.body, args.cc, args.bcc, args.isHtml, args.from, args.attachments, args.skipReview, args.includeSignature);
                case "saveDraft":
                  return await saveDraft(args.to, args.subject, args.body, args.cc, args.bcc, args.isHtml, args.from, args.attachments, args.inReplyTo, args.references, args.replaceMessageId, args.replaceFolderPath, args.includeSignature);
                default:
                  throw new Error(`Unknown tool: ${name}`);
              }
            }

            // END TOOL CALL DISPATCH
            // END TOOL DISPATCH

            const server = new HttpServer();

            // BEGIN MCP HTTP HANDLER
            server.registerPathHandler("/", (req, res) => {
              res.processAsync();

              // Verify auth token on ALL requests (including non-POST) to
              // prevent unauthenticated probing of the server.
              let reqToken = "";
              try {
                reqToken = req.getHeader("Authorization") || "";
              } catch {
                // getHeader throws if header is missing in httpd.sys.mjs
              }
              if (!timingSafeEqual(reqToken, `Bearer ${authToken}`)) {
                res.setStatusLine("1.1", 403, "Forbidden");
                res.setHeader("Content-Type", "application/json; charset=utf-8", false);
                res.write(JSON.stringify({
                  jsonrpc: "2.0",
                  id: null,
                  error: { code: -32600, message: "Invalid or missing auth token" }
                }));
                res.finish();
                return;
              }

              if (req.method !== "POST") {
                res.setStatusLine("1.1", 405, "Method Not Allowed");
                res.setHeader("Allow", "POST", false);
                res.setHeader("Content-Type", "application/json; charset=utf-8", false);
                res.write(JSON.stringify({
                  jsonrpc: "2.0",
                  id: null,
                  error: { code: -32600, message: "Method not allowed" }
                }));
                res.finish();
                return;
              }

              // Reject oversized request bodies to prevent memory exhaustion
              let contentLength = 0;
              try {
                contentLength = parseInt(req.getHeader("Content-Length"), 10) || 0;
              } catch {
                // Header missing — will be 0
              }
              if (contentLength > MAX_REQUEST_BODY) {
                res.setStatusLine("1.1", 413, "Payload Too Large");
                res.setHeader("Content-Type", "application/json; charset=utf-8", false);
                res.write(JSON.stringify({
                  jsonrpc: "2.0",
                  id: null,
                  error: { code: -32600, message: "Request body too large" }
                }));
                res.finish();
                return;
              }

              let message;
              try {
                message = JSON.parse(readRequestBody(req));
              } catch {
                res.setStatusLine("1.1", 200, "OK");
                res.setHeader("Content-Type", "application/json; charset=utf-8", false);
                res.write(JSON.stringify({
                  jsonrpc: "2.0",
                  id: null,
                  error: { code: -32700, message: "Parse error" }
                }));
                res.finish();
                return;
              }

              if (!message || typeof message !== "object" || Array.isArray(message)) {
                res.setStatusLine("1.1", 200, "OK");
                res.setHeader("Content-Type", "application/json; charset=utf-8", false);
                res.write(JSON.stringify({
                  jsonrpc: "2.0",
                  id: null,
                  error: { code: -32600, message: "Invalid Request" }
                }));
                res.finish();
                return;
              }

              const { id, method, params } = message;

              // Streamable HTTP notifications are accepted without a JSON-RPC body.
              // BEGIN MCP NOTIFICATION HTTP RESPONSE
              if (typeof method === "string" && method.startsWith("notifications/")) {
                res.setStatusLine("1.1", 202, "Accepted");
                res.finish();
                return;
              }
              // END MCP NOTIFICATION HTTP RESPONSE

              (async () => {
                try {
                  let result;
                  switch (method) {
                    case "initialize": {
                      // Per MCP lifecycle: respond with the requested version if
                      // we support it, otherwise the latest version we know.
                      // Behavior never depends on the version inside Thunderbird,
                      // so we accept any well-known protocol version.
                      const requested = params?.protocolVersion;
                      if (typeof requested !== "string") {
                        res.setStatusLine("1.1", 200, "OK");
                        res.setHeader("Content-Type", "application/json; charset=utf-8", false);
                        res.write(JSON.stringify({
                          jsonrpc: "2.0",
                          id: id ?? null,
                          error: { code: -32602, message: "Invalid params: protocolVersion must be a string" }
                        }));
                        res.finish();
                        return;
                      }
                      const negotiated = MCP_SUPPORTED_PROTOCOL_VERSIONS.has(requested)
                        ? requested
                        : MCP_LATEST_PROTOCOL_VERSION;
                      result = {
                        protocolVersion: negotiated,
                        capabilities: { tools: {} },
                        serverInfo: { name: "thundersend-mcp-minimal", version: getExtVersion() }
                      };
                      break;
                    }
                    case "resources/list":
                      result = { resources: [] };
                      break;
                    case "prompts/list":
                      result = { prompts: [] };
                      break;
                    case "tools/list":
                      // Strip internal metadata (group, crud, title) — only expose MCP-spec fields
                      result = { tools: buildTools().filter(t => MINIMAL_TOOL_NAMES.has(t.name) && isToolEnabled(t.name)).map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) };
                      break;
                    case "tools/call":
                      if (!params?.name) {
                        throw new Error("Missing tool name");
                      }
                      if (!MINIMAL_TOOL_NAMES.has(params.name)) {
                        throw new Error(`Unknown tool: ${params.name}`);
                      }
                      if (!isToolEnabled(params.name)) {
                        throw new Error(`Tool is disabled: ${params.name}`);
                      }
                      {
                        const toolArgs = coerceToolArgs(params.name, params.arguments || {});
                        const validationErrors = validateToolArgs(params.name, toolArgs);
                        if (validationErrors.length > 0) {
                          throw new Error(`Invalid parameters for '${params.name}': ${validationErrors.join("; ")}`);
                        }
                        result = {
                          content: buildToolResultContent(await callTool(params.name, toolArgs))
                        };
                      }
                      break;
                    default:
                      res.setStatusLine("1.1", 200, "OK");
                      res.setHeader("Content-Type", "application/json; charset=utf-8", false);
                      res.write(JSON.stringify({
                        jsonrpc: "2.0",
                        id: id ?? null,
                        error: { code: -32601, message: "Method not found" }
                      }));
                      res.finish();
                      return;
                  }
                  res.setStatusLine("1.1", 200, "OK");
                  // charset=utf-8 is critical for proper emoji handling in responses
                  res.setHeader("Content-Type", "application/json; charset=utf-8", false);
                  res.write(JSON.stringify({ jsonrpc: "2.0", id: id ?? null, result }));
                } catch (e) {
                  res.setStatusLine("1.1", 200, "OK");
                  res.setHeader("Content-Type", "application/json; charset=utf-8", false);
                  res.write(JSON.stringify({
                    jsonrpc: "2.0",
                    id: id ?? null,
                    error: { code: -32000, message: e.toString() }
                  }));
                }
                res.finish();
              })().catch((e) => {
                console.error("thundersend-mcp: unhandled dispatch error:", e);
                try { res.finish(); } catch {}
              });
            });

            // END MCP HTTP HANDLER

            // Try the default port first, then fall back to nearby ports
            let boundPort = null;
            const listenAll = isListenAllEnabled();
            for (let attempt = 0; attempt < MCP_MAX_PORT_ATTEMPTS; attempt++) {
              const tryPort = MCP_DEFAULT_PORT + attempt;
              try {
                if (listenAll) {
                  server.startAll(tryPort);
                } else {
                  server.start(tryPort);
                }
                boundPort = tryPort;
                break;
              } catch (portErr) {
                if (attempt === MCP_MAX_PORT_ATTEMPTS - 1) {
                  throw new Error(`Could not bind to any port in range ${MCP_DEFAULT_PORT}-${tryPort}: ${portErr}`, { cause: portErr });
                }
                console.warn(`Port ${tryPort} in use, trying ${tryPort + 1}...`);
              }
            }

            startedServer = server;
            // Write the connection file fresh on initial start so the secure
            // create path (0600 perms, directory checks) always runs. The
            // refresh timer self-heals it afterward via ensureConnectionInfo
            // if the OS deletes it while the server keeps running.
            const connFilePath = writeConnectionInfo(boundPort, authToken);
            startConnectionInfoRefresh(boundPort, authToken);
            console.log(`Thunderbird MCP server listening on port ${boundPort}`);
            console.log(`Connection info written to ${connFilePath}`);
            if (listenAll) {
              console.error(`thundersend-mcp: WARNING - server is listening on all interfaces (0.0.0.0/[::]). This exposes the MCP server to your local network. Only enable on trusted networks.`);
            }
            // Publish running state only after startup has fully succeeded.
            globalThis.__tbMcpServer = server;
            return { success: true, port: boundPort };
          } catch (e) {
            console.error("Failed to start MCP server:", e);
            stopConnectionInfoRefreshTimer();
            // Clean up before yielding: a reload may install a new connection
            // file while this listener is still draining.
            removeConnectionInfo();
            // Keep this attempt cached until the listener has finished stopping,
            // so concurrent starts cannot rebind during failure cleanup.
            if (startedServer) {
              try { await startedServer.stop(); } catch (e) { console.error("thundersend-mcp: server.stop failed:", e); }
            }
            return { success: false, error: e.toString() };
          }
          })();
          // Set sentinel BEFORE awaiting to prevent race with concurrent start() calls
          globalThis.__tbMcpStartPromise = startPromise;
          let result;
          try {
            result = await startPromise;
            if (globalThis.__tbMcpStartPromise === startPromise) {
              globalThis.__tbMcpLastStartError = result.success ? null : result.error;
            }
            return result;
          } catch (e) {
            if (globalThis.__tbMcpStartPromise === startPromise) {
              globalThis.__tbMcpLastStartError = String(e);
            }
            throw e;
          } finally {
            // The IIFE can fail synchronously before the assignment above.
            // Evict failures/rejections after settlement without clearing a
            // newer attempt installed by a restart or extension reload.
            if (!result?.success && globalThis.__tbMcpStartPromise === startPromise) {
              globalThis.__tbMcpStartPromise = null;
            }
          }
        },

        getServerInfo: async function() {
          let port = null;
          let connectionFile = null;
          let buildVersion = null;
          let buildDate = null;

          // Read build info from bundled file via resource: protocol
          try {
            const uri = Services.io.newURI("resource://thundersend-mcp/buildinfo.json");
            const channel = Services.io.newChannelFromURI(uri, null,
              Services.scriptSecurityManager.getSystemPrincipal(), null,
              Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
              Ci.nsIContentPolicy.TYPE_OTHER);
            const sis = Cc["@mozilla.org/scriptableinputstream;1"]
              .createInstance(Ci.nsIScriptableInputStream);
            sis.init(channel.open());
            const text = sis.read(sis.available());
            sis.close();
            const bi = JSON.parse(text);
            buildVersion = bi.version || bi.commit || null;
            buildDate = bi.builtAt || null;
          } catch (e) {
            // buildinfo.json may legitimately be absent in dev builds; surface anything else.
            if (e?.name !== "NS_ERROR_FILE_NOT_FOUND") {
              console.warn("thundersend-mcp: read buildinfo failed:", e);
            }
          }

          // Read connection info from temp file using XPCOM file I/O
          try {
            const connInfo = readConnectionInfo();
            connectionFile = connInfo.path;
            if (connInfo.data) {
              port = connInfo.data.port || null;
            }
          } catch (e) {
            // Connection file is absent before the server first binds; log other faults.
            if (e?.name !== "NS_ERROR_FILE_NOT_FOUND") {
              console.warn("thundersend-mcp: read connection info failed:", e);
            }
          }

          return {
            running: !!globalThis.__tbMcpServer,
            lastError: globalThis.__tbMcpLastStartError || null,
            port,
            connectionFile,
            buildVersion,
            buildDate,
          };
        },

        // END SERVER LIFECYCLE

        getCurrentAuthToken: async function() {
          let authToken = "";
          try {
            const connInfo = readConnectionInfo();
            if (connInfo.data && typeof connInfo.data.token === "string") {
              authToken = connInfo.data.token;
            }
          } catch (e) {
            if (e?.name !== "NS_ERROR_FILE_NOT_FOUND") {
              console.warn("thundersend-mcp: read auth token failed:", e);
            }
          }
          return { authToken };
        },

        // BEGIN OPTIONS ACCESS API
        getAccountAccessConfig: async function() {
          const { MailServices } = ChromeUtils.importESModule(
            "resource:///modules/MailServices.sys.mjs"
          );
          const { values: allowed, corrupt } = readAccessListPref(PREF_ALLOWED_ACCOUNTS);

          const accounts = [];
          for (const account of MailServices.accounts.accounts) {
            const server = account.incomingServer;
            accounts.push({
              id: account.key,
              name: server.prettyName,
              type: server.type,
              allowed: !corrupt && (allowed.length === 0 || allowed.includes(account.key)),
            });
          }
          return {
            mode: corrupt ? "error" : (allowed.length === 0 ? "all" : "restricted"),
            ...(corrupt ? { error: "Account access preference is corrupt or unreadable. All accounts are blocked. Select accounts explicitly to repair it." } : {}),
            allowedAccountIds: allowed,
            accounts,
          };
        },

        getToolAccessConfig: async function() {
          const { values: disabled, corrupt: invalid } = readAccessListPref(PREF_DISABLED_TOOLS);
          const corrupt = invalid || disabled.includes("__all__");

          const toolList = buildTools()
            .map(t => ({
              name: t.name,
              group: t.group,
              crud: t.crud,
              enabled: UNDISABLEABLE_TOOLS.has(t.name) || (!corrupt && !disabled.includes(t.name)),
              undisableable: UNDISABLEABLE_TOOLS.has(t.name),
            }))
            .sort((a, b) => {
              const gA = GROUP_ORDER[a.group] ?? 99;
              const gB = GROUP_ORDER[b.group] ?? 99;
              if (gA !== gB) return gA - gB;
              return (CRUD_ORDER[a.crud] ?? 99) - (CRUD_ORDER[b.crud] ?? 99);
            });
          const result = {
            mode: corrupt ? "error" : (disabled.length === 0 ? "all" : "restricted"),
            disabledTools: disabled,
            groups: GROUP_LABELS,
            tools: toolList,
          };
          if (corrupt) {
            result.error = "Disabled tools preference is corrupt. All non-infrastructure tools are blocked. Change tool selections explicitly to repair it.";
          }
          return result;
        },

        setToolAccess: async function(disabledTools) {
          if (!Array.isArray(disabledTools)) {
            return { error: "disabledTools must be an array" };
          }
          if (!disabledTools.every(t => typeof t === "string")) {
            return { error: "All tool names must be strings" };
          }
          if (disabledTools.includes("__all__")) {
            return { error: "Invalid tool name: __all__" };
          }
          const blocked = disabledTools.filter(t => UNDISABLEABLE_TOOLS.has(t));
          if (blocked.length > 0) {
            return { error: `Cannot disable infrastructure tools: ${blocked.join(", ")}` };
          }
          if (disabledTools.length === 0) {
            try { Services.prefs.clearUserPref(PREF_DISABLED_TOOLS); } catch { /* ignore */ }
          } else {
            Services.prefs.setStringPref(PREF_DISABLED_TOOLS, JSON.stringify(disabledTools));
          }
          return {
            success: true,
            mode: disabledTools.length === 0 ? "all" : "restricted",
            disabledTools,
          };
        },

        setAccountAccess: async function(allowedAccountIds) {
          if (!Array.isArray(allowedAccountIds)) {
            return { error: "allowedAccountIds must be an array" };
          }
          const { MailServices } = ChromeUtils.importESModule(
            "resource:///modules/MailServices.sys.mjs"
          );
          const validIds = new Set();
          for (const account of MailServices.accounts.accounts) {
            validIds.add(account.key);
          }
          const invalid = allowedAccountIds.filter(id => !validIds.has(id));
          if (invalid.length > 0) {
            return { error: `Unknown account IDs: ${invalid.join(", ")}` };
          }

          if (allowedAccountIds.length === 0) {
            try { Services.prefs.clearUserPref(PREF_ALLOWED_ACCOUNTS); } catch { /* ignore */ }
          } else {
            Services.prefs.setStringPref(PREF_ALLOWED_ACCOUNTS, JSON.stringify(allowedAccountIds));
          }
          return {
            success: true,
            mode: allowedAccountIds.length === 0 ? "all" : "restricted",
            allowedAccountIds,
          };
        },

        // END OPTIONS ACCESS API

        getBlockSkipReview: async function() {
          let blocked = true;
          try {
            blocked = Services.prefs.getBoolPref(PREF_BLOCK_SKIPREVIEW, true);
          } catch { /* ignore */ }
          return { blockSkipReview: blocked };
        },

        setBlockSkipReview: async function(blockSkipReview) {
          if (typeof blockSkipReview !== "boolean") {
            return { error: "blockSkipReview must be a boolean" };
          }
          // Default is true; persist the explicit value either way so the user's
          // choice survives independent of the default we ship.
          Services.prefs.setBoolPref(PREF_BLOCK_SKIPREVIEW, blockSkipReview);
          return { success: true, blockSkipReview };
        },

        getStableAuthToken: async function() {
          return { stableAuthToken: getStableAuthTokenPref() };
        },

        setStableAuthToken: async function(stableAuthToken) {
          if (typeof stableAuthToken !== "string") {
            return { error: "stableAuthToken must be a string" };
          }
          stableAuthToken = stableAuthToken.trim();
          if (stableAuthToken && !AUTH_TOKEN_PATTERN.test(stableAuthToken)) {
            return { error: "stableAuthToken must be empty or 64 lowercase hex characters" };
          }
          if (stableAuthToken) {
            Services.prefs.setStringPref(PREF_STABLE_AUTH_TOKEN, stableAuthToken);
          } else {
            try { Services.prefs.clearUserPref(PREF_STABLE_AUTH_TOKEN); } catch { /* ignore */ }
          }
          return { success: true, stableAuthToken };
        },

        generateAuthToken: async function() {
          return { authToken: generateAuthToken() };
        },

        getListenAll: async function() {
          let listenAll = false;
          try {
            listenAll = Services.prefs.getBoolPref(PREF_LISTEN_ALL, false);
          } catch { /* ignore */ }
          return { listenAll };
        },

        // BEGIN LISTEN ALL SETTER
        setListenAll: async function(listenAll) {
          if (typeof listenAll !== "boolean") {
            return { error: "listenAll must be a boolean" };
          }
          // Serialize settings changes through the entire restart, including
          // failure cleanup, so another setter cannot bypass a pending stop.
          const previousRestart = globalThis.__tbMcpRestartPromise;
          const restartPromise = (async () => {
            try { await previousRestart; } catch { /* previous restart failed */ }
            console.log(`[MCP] setListenAll called with: ${listenAll}`);
            // A failed start may still be stopping its listener. Follow any
            // newer attempt another caller installs while we are waiting.
            let startPromise;
            do {
              startPromise = globalThis.__tbMcpStartPromise;
              if (startPromise) {
                try { await startPromise; } catch { /* startup failed */ }
              }
            } while (globalThis.__tbMcpStartPromise &&
                     globalThis.__tbMcpStartPromise !== startPromise);
            if (listenAll) {
              Services.prefs.setBoolPref(PREF_LISTEN_ALL, true);
            } else {
              try { Services.prefs.clearUserPref(PREF_LISTEN_ALL); } catch { /* ignore */ }
            }

            // Remove stale info before yielding so this stop cannot remove a
            // newer attempt's connection file.
            removeConnectionInfo();
            if (globalThis.__tbMcpServer) {
              const stopServer = globalThis.__tbMcpServer;
              globalThis.__tbMcpServer = null;
              stopConnectionInfoRefreshTimer();
              // Wait for the socket close callback before rebinding the port.
              try {
                await new Promise((resolve) => {
                  try { stopServer.stop(resolve); } catch { resolve(); }
                });
              } catch { /* ignore */ }
            }
            // Only release the startup attempt this operation waited for.
            if (globalThis.__tbMcpStartPromise === startPromise) {
              globalThis.__tbMcpStartPromise = null;
            }

            console.log(`[MCP] Restarting server...`);
            return await this.start();
          })();
          globalThis.__tbMcpRestartPromise = restartPromise;
          try {
            return await restartPromise;
          } finally {
            if (globalThis.__tbMcpRestartPromise === restartPromise) {
              globalThis.__tbMcpRestartPromise = null;
            }
          }
        },
        // END LISTEN ALL SETTER
      }
    };
  }

  onShutdown(isAppShutdown) {
    // BEGIN UNINSTALL LISTENER REMOVAL
    if (this._uninstallListener) {
      try { this._addonManager.removeAddonListener(this._uninstallListener); } catch { /* best effort */ }
      this._uninstallListener = null;
      this._addonManager = null;
    }
    // END UNINSTALL LISTENER REMOVAL
    // Stop the HTTP server so the port is released
    if (globalThis.__tbMcpServer) {
      try { globalThis.__tbMcpServer.stop(() => {}); } catch { /* ignore */ }
      globalThis.__tbMcpServer = null;
    }
    stopConnectionInfoRefreshTimer();
    // Clear the start promise so a fresh start can occur on reload
    globalThis.__tbMcpStartPromise = null;

    // Always clean up the connection info file so stale tokens don't linger
    // (Inlined because getAPI() helpers are not in scope in onShutdown().)
    try {
      const tmpDir = Services.dirsvc.get("TmpD", Ci.nsIFile);
      tmpDir.append("thundersend-mcp");
      const connFile = tmpDir.clone();
      connFile.append("connection.json");
      if (connFile.exists()) {
        connFile.remove(false);
      }
    } catch {
      // Best-effort cleanup
    }

    // Always clean up temp attachment files (even on app shutdown) to avoid
    // leaving sensitive decoded attachments on disk.
    for (const tmpPath of _tempAttachFiles) {
      try {
        const f = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
        f.initWithPath(tmpPath);
        if (f.exists()) f.remove(false);
      } catch {}
    }
    _tempAttachFiles.clear();
    if (isAppShutdown) return;
    resProto.setSubstitution("thundersend-mcp", null);
    Services.obs.notifyObservers(null, "startupcache-invalidate");
  }
};

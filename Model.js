.pragma library

var PROTOCOL = 1
// QML strings count UTF-16 units; the helper's replies are ASCII JSON, so
// this matches its 1 MiB cap.
var MAX_REPLY_CHARS = 1024 * 1024
var CLEAR_AFTER_MIN = 5
var CLEAR_AFTER_MAX = 120
var CLEAR_AFTER_DEFAULT = 20
var RECENT_MAX = 5

function pluginDirFromUrl(url) {
  var u = String(url || "")
  if (u.indexOf("file://") === 0) u = u.slice(7)
  try {
    u = decodeURIComponent(u)
  } catch (e) {
    return ""
  }
  return u.replace(/\/$/, "")
}

// Mirrors the helper's item id rule. A leading "-" would be read as a flag.
function validId(id) {
  return typeof id === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(id) && id.charAt(0) !== "-"
}

function clampClearAfter(seconds) {
  var n = Math.round(Number(seconds))
  if (!isFinite(n)) return CLEAR_AFTER_DEFAULT
  return Math.max(CLEAR_AFTER_MIN, Math.min(CLEAR_AFTER_MAX, n))
}

// The reply is one line; anything after the first newline is not part of it.
// Returns null while the line is still incomplete.
function replyLine(buffer) {
  var i = buffer.indexOf("\n")
  return i < 0 ? null : buffer.slice(0, i)
}

function failure(error) {
  return { ok: false, error: error }
}

// No output at all means the helper died before replying. A reply that does
// not parse, or speaks another protocol, comes from a helper built from a
// different checkout.
function parseReply(text) {
  var trimmed = String(text || "").trim()
  if (trimmed === "") return failure("INTERNAL")
  var data
  try {
    data = JSON.parse(trimmed)
  } catch (e) {
    return failure("HELPER_OUTDATED")
  }
  if (!data || typeof data !== "object" || Array.isArray(data) || data.protocol !== PROTOCOL)
    return failure("HELPER_OUTDATED")
  if (data.ok !== true)
    return failure(typeof data.error === "string" && data.error !== "" ? data.error : "INTERNAL")
  return data
}

function emptyPrefs() {
  return { pinned: [], recent: [], privacy: false }
}

function normalizePrefs(raw) {
  var p = emptyPrefs()
  if (!raw || typeof raw !== "object") return p
  if (Array.isArray(raw.pinned)) p.pinned = raw.pinned.filter(validId)
  if (Array.isArray(raw.recent)) p.recent = raw.recent.filter(validId).slice(0, RECENT_MAX)
  p.privacy = raw.privacy === true
  return p
}

function withPinned(prefs, id, pinned) {
  var p = normalizePrefs(prefs)
  p.pinned = p.pinned.filter(function(x) { return x !== id })
  if (pinned) p.pinned.push(id)
  return p
}

function withRecent(prefs, id) {
  var p = normalizePrefs(prefs)
  p.recent = [id].concat(p.recent.filter(function(x) { return x !== id })).slice(0, RECENT_MAX)
  return p
}

function withPrivacy(prefs, on) {
  var p = normalizePrefs(prefs)
  p.privacy = on === true
  return p
}

function pinEdit(id, on) { return { op: "pin", id: id, on: on === true } }
function recentEdit(id) { return { op: "recent", id: id } }
function privacyEdit(on) { return { op: "privacy", on: on === true } }

// Replays edits made before the stored prefs were known on top of them, so an
// early edit never overwrites what was stored.
function applyEdits(prefs, edits) {
  var p = normalizePrefs(prefs)
  for (var i = 0; i < edits.length; i++) {
    var e = edits[i]
    if (e.op === "pin" && validId(e.id)) p = withPinned(p, e.id, e.on)
    else if (e.op === "recent" && validId(e.id)) p = withRecent(p, e.id)
    else if (e.op === "privacy") p = withPrivacy(p, e.on)
  }
  return p
}

function statusGlyph(status) {
  if (status === "READY") return "\u{F0BC4}"
  if (status === "KEYRING_LOCKED") return "\u{F033E}"
  return "\u{F0026}"
}

var STATUS_TEXT = {
  LOADING: "Proton Authenticator: checking",
  READY: "Proton Authenticator",
  KEYRING_LOCKED: "Keyring is locked; open the panel to unlock",
  KEYRING_UNAVAILABLE: "No Secret Service keyring is running",
  KEY_NOT_FOUND: "The vault key is not in the keyring",
  VAULT_NOT_FOUND: "Proton Authenticator vault not found",
  VAULT_BUSY: "The vault is being written; try again shortly",
  VAULT_FORMAT_CHANGED: "Vault format not recognised; the app may have updated",
  DECRYPT_FAILED: "Could not decrypt the vault; the app may have updated",
  APP_LOCKED: "App lock is on; a password-locked vault cannot be read",
  UNSAFE_KEY_STORAGE: "Proton stores its key outside the keyring",
  DEPENDENCY_MISSING: "A required tool is missing; run install.sh",
  MEMLOCK_FAILED: "The helper could not lock its memory (ulimit -l)",
  TIMEOUT: "The helper timed out",
  OUTPUT_TOO_LARGE: "The helper reply was too large",
  HELPER_MISSING: "Helper not built; run install.sh",
  HELPER_OUTDATED: "Helper is out of date; run install.sh"
}

function statusText(status) {
  return STATUS_TEXT[status] || "Proton Authenticator error: " + String(status)
}

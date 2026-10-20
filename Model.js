.pragma library

var PROTOCOL = 1
// QML strings count UTF-16 units; the helper's replies are ASCII JSON, so
// this matches its 1 MiB cap.
var MAX_REPLY_CHARS = 1024 * 1024
var CLEAR_AFTER_MIN = 5
var CLEAR_AFTER_MAX = 120
var CLEAR_AFTER_DEFAULT = 20
var RECENT_MAX = 5

// Null when the directory cannot be determined, so callers fail closed
// instead of building paths at the filesystem root.
function pluginDirFromUrl(url) {
  var u = String(url || "")
  if (u.indexOf("file://") === 0) u = u.slice(7)
  try {
    u = decodeURIComponent(u)
  } catch (e) {
    return null
  }
  u = u.replace(/\/$/, "")
  return u.charAt(0) === "/" ? u : null
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
  return Object.prototype.hasOwnProperty.call(STATUS_TEXT, status)
    ? STATUS_TEXT[status]
    : "Proton Authenticator error: " + String(status)
}

function lower(value) {
  return value === null || value === undefined ? "" : String(value).toLocaleLowerCase()
}

// Caseless scripts (CJK, Arabic) have no letter case, so every character
// there counts as a word start and substring matches score 2.
function isWordChar(c) {
  return c.toLowerCase() !== c.toUpperCase() || (c >= "0" && c <= "9")
}

function isHump(text, i) {
  var c = text.charAt(i)
  var prev = text.charAt(i - 1)
  return c !== c.toLowerCase() && prev === prev.toLowerCase() && prev !== prev.toUpperCase()
}

function isWordStart(text, i) {
  return i === 0 || !isWordChar(text.charAt(i - 1)) || isHump(text, i)
}

// "gh" reaches GitHub through its camel-case humps. Initials never span
// separate tokens, so "gh" does not reach "Gitea (home)".
function matchesHumpInitials(text, q) {
  var initials = ""
  for (var i = 0; i <= text.length; i++) {
    var boundary = i === text.length || !isWordChar(text.charAt(i))
    if (boundary) {
      if (initials.length >= 2 && initials.indexOf(q) === 0) return true
      initials = ""
    } else if (initials === "" || isHump(text, i)) {
      initials += text.charAt(i).toLocaleLowerCase()
    }
  }
  return false
}

// 3 = prefix, 2 = start of a word or hump, 1 = subsequence, 0 = no match.
function fuzzyScore(text, query) {
  if (text === null || text === undefined) return 0
  var original = String(text)
  var t = lower(original)
  var q = lower(query)
  if (q === "") return 0
  if (t.indexOf(q) === 0) return 3
  var at = t.indexOf(q)
  while (at > 0) {
    if (isWordStart(original, at)) return 2
    at = t.indexOf(q, at + 1)
  }
  if (matchesHumpInitials(original, q)) return 2
  var next = 0
  for (var i = 0; i < t.length && next < q.length; i++) {
    if (t.charAt(i) === q.charAt(next)) next++
  }
  return next === q.length ? 1 : 0
}

function compareEntries(a, b) {
  var keys = ["issuer", "account"]
  for (var i = 0; i < keys.length; i++) {
    var x = lower(a[keys[i]])
    var y = lower(b[keys[i]])
    if (x < y) return -1
    if (x > y) return 1
  }
  return 0
}

function defaultOrder(entries, prefs) {
  var p = normalizePrefs(prefs)
  entries = entries.filter(function(e) { return e !== null && e !== undefined })
  var byId = Object.create(null)
  entries.forEach(function(e) { byId[e.id] = e })
  var placed = Object.create(null)
  var out = []
  p.pinned.concat(p.recent).forEach(function(id) {
    if (byId[id] && !placed[id]) {
      placed[id] = true
      out.push(byId[id])
    }
  })
  var rest = entries.filter(function(e) { return !placed[e.id] })
  rest = rest.map(function(e, i) { return { e: e, i: i } })
  rest.sort(function(a, b) { return compareEntries(a.e, b.e) || a.i - b.i })
  return out.concat(rest.map(function(r) { return r.e }))
}

// Only the issuer can earn a prefix score; the account tops out at a word start.
function entryScore(entry, query) {
  return Math.max(fuzzyScore(entry.issuer, query), Math.min(2, fuzzyScore(entry.account, query)))
}

function filterAndOrder(entries, query, prefs) {
  var ordered = defaultOrder(Array.isArray(entries) ? entries : [], prefs)
  if (lower(query).trim() === "") return ordered
  var q = lower(query).trim()
  var scored = []
  ordered.forEach(function(e, i) {
    var score = entryScore(e, q)
    if (score > 0) scored.push({ e: e, score: score, i: i })
  })
  scored.sort(function(a, b) { return b.score - a.score || a.i - b.i })
  return scored.map(function(r) { return r.e })
}

function groupCode(code) {
  if (code === null || code === undefined) return ""
  var c = String(code)
  if (c.length === 6 || c.length === 7) return c.slice(0, 3) + " " + c.slice(3)
  if (c.length === 8) return c.slice(0, 4) + " " + c.slice(4)
  return c
}

function isUrgent(remaining) {
  return typeof remaining === "number" && remaining <= 5
}

// "" under a minute, so callers can say "just now" instead.
function ageSpan(nowSec, mtimeSec) {
  var age = nowSec - mtimeSec
  if (!(age >= 60)) return ""
  if (age < 3600) return Math.floor(age / 60) + " min"
  if (age < 86400) return Math.floor(age / 3600) + " h"
  return Math.floor(age / 86400) + " d"
}

function ageLabel(nowSec, mtimeSec) {
  var span = ageSpan(nowSec, mtimeSec)
  return span === "" ? "just now" : span + " ago"
}

function isStale(nowSec, mtimeSec, staleHours) {
  return nowSec - mtimeSec >= staleHours * 3600
}

// privateMode lists labels only and computes the code of revealId alone, so
// codes of the other rows never reach QML.
function codesRequest(privateMode, revealId) {
  var priv = privateMode !== false
  return { privateMode: priv, revealId: priv && validId(revealId) ? revealId : "" }
}

function codesArgs(request) {
  var args = ["codes"]
  if (!request.privateMode) return args
  args.push("--private")
  if (request.revealId !== "") args.push("--reveal", request.revealId)
  return args
}

function sameRequest(a, b) {
  return !!a && !!b && a.privateMode === b.privateMode && a.revealId === b.revealId
}

function hiddenEntry(e) {
  return {
    id: e.id, issuer: e.issuer, account: e.account, kind: null, code: null,
    nextCode: null, period: null, digits: null, remaining: null
  }
}

function hideCodes(entries, revealId) {
  return (Array.isArray(entries) ? entries : [])
    .filter(function(e) { return e !== null && e !== undefined })
    .map(function(e) { return e.id === revealId && revealId !== "" ? e : hiddenEntry(e) })
}

// A private-mode row whose code was not revealed. Unsupported entries carry a
// kind, so they never count as hidden.
function isHidden(entry) {
  return !!entry && (entry.kind === null || entry.kind === undefined)
}

function liveRemaining(entry, replyNowSec, nowSec) {
  if (!entry || typeof entry.remaining !== "number") return null
  return Math.max(0, replyNowSec + entry.remaining - nowSec)
}

// The 300 ms margin puts the reload after the boundary, so the helper is
// already in the next period. -1 when nothing counts down.
function refreshDelayMs(entries, replyNowSec, nowMs) {
  var boundary = -1
  ;(Array.isArray(entries) ? entries : []).forEach(function(e) {
    if (!e || typeof e.remaining !== "number" || e.code === null) return
    var at = replyNowSec + e.remaining
    if (boundary < 0 || at < boundary) boundary = at
  })
  if (boundary < 0) return -1
  var delay = boundary * 1000 + 300 - nowMs
  return delay > 0 ? delay : 1000
}

function selectionIndex(list, id) {
  if (!list || list.length === 0) return -1
  for (var i = 0; i < list.length; i++) if (list[i].id === id) return i
  return 0
}

function moveSelection(list, id, delta) {
  if (!list || list.length === 0) return ""
  var at = selectionIndex(list, id)
  var next = Math.max(0, Math.min(list.length - 1, at + delta))
  return list[next].id
}

function firstChar(text) {
  var chars = Array.from(String(text || "").trim())
  return chars.length > 0 ? chars[0].toLocaleUpperCase() : ""
}

function initial(entry) {
  var e = entry || {}
  return firstChar(e.issuer) || firstChar(e.account) || "?"
}

function issuerLabel(entry) {
  var e = entry || {}
  var issuer = String(e.issuer || "").trim()
  if (issuer !== "") return issuer
  var account = String(e.account || "").trim()
  return account !== "" ? account : "Unnamed"
}

function maskedCode() {
  return "\u2022\u2022\u2022 \u2022\u2022\u2022"
}

function canCopy(entry) {
  return !!entry && validId(entry.id) && entry.kind !== "unsupported"
}

function shellQuote(text) {
  return "'" + String(text).replace(/'/g, "'\\''") + "'"
}

function state(title, detail, action, actionLabel) {
  return { title: title, detail: detail || "", action: action || "", actionLabel: actionLabel || "" }
}

var OPEN_PROTON = "Open Proton"

// What the panel shows instead of the list; null when the list has rows.
// s: { status, entryCount, matchCount, query, codesRunning, promptRunning, pluginDir }
function emptyState(s) {
  if (s.promptRunning) return state("Waiting for keyring\u2026", "Unlock it in the prompt")
  switch (s.status) {
  case "READY":
    if (s.entryCount === 0)
      return s.codesRunning ? state("Loading\u2026") : state("No accounts yet", "", "openProton", OPEN_PROTON)
    if (s.matchCount === 0) return state("No matches", "Esc clears the search")
    return null
  case "LOADING":
    return state("Loading\u2026")
  case "KEYRING_LOCKED":
    return state("Keyring is locked", "", "unlock", "Unlock")
  case "VAULT_NOT_FOUND":
    return state("Proton Authenticator not found", "", "openProton", OPEN_PROTON)
  case "VAULT_FORMAT_CHANGED":
  case "DECRYPT_FAILED":
    return state("Vault format not recognised \u2014 the app may have updated", "", "openProton", OPEN_PROTON)
  case "APP_LOCKED":
    return state("App lock is on \u2014 this plugin can't read a password-locked vault")
  case "UNSAFE_KEY_STORAGE":
    return state("Proton is storing its key outside the keyring \u2014 open Proton and fix keyring access",
                 "", "openProton", OPEN_PROTON)
  case "HELPER_MISSING":
  case "HELPER_OUTDATED":
  case "DEPENDENCY_MISSING":
    return state("Run install.sh", "cd " + shellQuote(s.pluginDir) + " && ./install.sh")
  default:
    return state(statusText(s.status), "", "retry", "Retry")
  }
}

function syncLabel(nowSec, mtimeSec, staleHours, staleAllowed) {
  if (!(mtimeSec > 0)) return { text: "", stale: false }
  if (staleAllowed && isStale(nowSec, mtimeSec, staleHours))
    return { text: "Not synced for " + ageSpan(nowSec, mtimeSec), stale: true }
  return { text: "Updated " + ageLabel(nowSec, mtimeSec), stale: false }
}

var SHORT_STATUS = {
  LOADING: "Checking",
  KEYRING_LOCKED: "Keyring locked",
  KEYRING_UNAVAILABLE: "No keyring",
  KEY_NOT_FOUND: "Key not found",
  VAULT_NOT_FOUND: "Vault not found",
  VAULT_BUSY: "Vault busy",
  VAULT_FORMAT_CHANGED: "Format changed",
  DECRYPT_FAILED: "Decrypt failed",
  APP_LOCKED: "App lock on",
  UNSAFE_KEY_STORAGE: "Unsafe key storage",
  DEPENDENCY_MISSING: "Dependency missing",
  MEMLOCK_FAILED: "Memlock failed",
  TIMEOUT: "Timed out",
  OUTPUT_TOO_LARGE: "Reply too large",
  HELPER_MISSING: "Helper missing",
  HELPER_OUTDATED: "Helper outdated",
  ITEM_NOT_FOUND: "Account not found"
}

// The panel header's subtitle; PanelHero uppercases it.
// h: { status, entryCount, demo, promptRunning, nowSec, vaultMtime }
function heroMeta(h) {
  if (h.promptRunning) return "Waiting for keyring"
  if (h.status !== "READY") {
    return Object.prototype.hasOwnProperty.call(SHORT_STATUS, h.status)
      ? SHORT_STATUS[h.status]
      : String(h.status).toLowerCase().replace(/_/g, " ")
  }
  if (h.demo) return "Demo accounts"
  var parts = []
  if (h.entryCount > 0) parts.push(h.entryCount + (h.entryCount === 1 ? " account" : " accounts"))
  if (h.vaultMtime > 0) parts.push("updated " + ageLabel(h.nowSec, h.vaultMtime))
  return parts.join(" · ")
}

function heroBadge(privacy, demo) {
  if (privacy) return "PRIVATE"
  return demo ? "DEMO" : ""
}

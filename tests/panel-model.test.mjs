import { test } from "node:test"
import assert from "node:assert/strict"
import { loadModel } from "./load-model.mjs"

const M = loadModel()
const plain = (value) => JSON.parse(JSON.stringify(value))

const full = (id, extra) => Object.assign({
  id, issuer: id, account: "a", kind: "totp", code: "123456", nextCode: "654321",
  period: 30, digits: 6, remaining: 20
}, extra || {})
const hidden = (id) => ({
  id, issuer: id, account: "a", kind: null, code: null, nextCode: null,
  period: null, digits: null, remaining: null
})

test("codesRequest normalizes mode and reveal id", () => {
  assert.deepEqual(plain(M.codesRequest(false, "x")), { privateMode: false, revealId: "" })
  assert.deepEqual(plain(M.codesRequest(true, "demo-a")), { privateMode: true, revealId: "demo-a" })
  assert.deepEqual(plain(M.codesRequest(true, "-x")), { privateMode: true, revealId: "" })
  assert.deepEqual(plain(M.codesRequest(true, null)), { privateMode: true, revealId: "" })
  assert.deepEqual(plain(M.codesRequest(undefined)), { privateMode: true, revealId: "" })
})

test("codesArgs builds the helper arguments", () => {
  assert.deepEqual(plain(M.codesArgs(M.codesRequest(false, ""))), ["codes"])
  assert.deepEqual(plain(M.codesArgs(M.codesRequest(true, ""))), ["codes", "--private"])
  assert.deepEqual(plain(M.codesArgs(M.codesRequest(true, "a:b"))), ["codes", "--private", "--reveal", "a:b"])
})

test("sameRequest compares mode and reveal id", () => {
  assert.equal(M.sameRequest(M.codesRequest(true, "a"), M.codesRequest(true, "a")), true)
  assert.equal(M.sameRequest(M.codesRequest(true, "a"), M.codesRequest(true, "b")), false)
  assert.equal(M.sameRequest(M.codesRequest(false, ""), M.codesRequest(true, "")), false)
  assert.equal(M.sameRequest(null, M.codesRequest(true, "")), false)
})

test("hideCodes keeps labels and only the revealed code", () => {
  const out = M.hideCodes([full("a"), full("b"), null], "b")
  assert.deepEqual(plain(out[0]), hidden("a"))
  assert.equal(out[1].code, "123456")
  assert.equal(out.length, 2)
  assert.deepEqual(plain(M.hideCodes([full("a")], "")), [hidden("a")])
})

test("isHidden is true only for code-less private rows", () => {
  assert.equal(M.isHidden(hidden("a")), true)
  assert.equal(M.isHidden(full("a")), false)
  assert.equal(M.isHidden(full("a", { kind: "unsupported", code: null, nextCode: null })), false)
})

test("liveRemaining counts down from the reply time", () => {
  const e = full("a", { remaining: 20 })
  assert.equal(M.liveRemaining(e, 1000, 1000), 20)
  assert.equal(M.liveRemaining(e, 1000, 1007), 13)
  assert.equal(M.liveRemaining(e, 1000, 1030), 0)
  assert.equal(M.liveRemaining(hidden("a"), 1000, 1000), null)
})

test("refreshDelayMs targets the earliest boundary plus 300 ms", () => {
  const entries = [full("a", { remaining: 20 }), full("b", { remaining: 7 }), hidden("c")]
  assert.equal(M.refreshDelayMs(entries, 1000, 1000 * 1000), 7300)
  assert.equal(M.refreshDelayMs(entries, 1000, 1000 * 1000 + 2500), 4800)
  assert.equal(M.refreshDelayMs([hidden("c")], 1000, 1000 * 1000), -1)
  assert.equal(M.refreshDelayMs([], 1000, 0), -1)
})

test("refreshDelayMs never schedules into the past", () => {
  assert.equal(M.refreshDelayMs([full("a", { remaining: 1 })], 1000, 1010 * 1000), 1000)
})

test("selectionIndex falls back to the first row", () => {
  const list = [full("a"), full("b")]
  assert.equal(M.selectionIndex(list, "b"), 1)
  assert.equal(M.selectionIndex(list, "zz"), 0)
  assert.equal(M.selectionIndex([], "a"), -1)
})

test("moveSelection clamps at both ends", () => {
  const list = [full("a"), full("b"), full("c")]
  assert.equal(M.moveSelection(list, "a", 1), "b")
  assert.equal(M.moveSelection(list, "c", 1), "c")
  assert.equal(M.moveSelection(list, "b", -5), "a")
  assert.equal(M.moveSelection(list, "missing", 1), "b")
  assert.equal(M.moveSelection([], "a", 1), "")
})

test("initial takes the first character of the issuer, then the account", () => {
  assert.equal(M.initial({ issuer: "github", account: "x" }), "G")
  assert.equal(M.initial({ issuer: "  ", account: "zed" }), "Z")
  assert.equal(M.initial({ issuer: "\u{1F600}x" }), "\u{1F600}")
  assert.equal(M.initial({}), "?")
})

test("issuerLabel falls back to the account", () => {
  assert.equal(M.issuerLabel({ issuer: "GitHub", account: "a" }), "GitHub")
  assert.equal(M.issuerLabel({ issuer: "", account: "a" }), "a")
  assert.equal(M.issuerLabel({}), "Unnamed")
})

test("maskedCode is grouped bullets", () => {
  assert.equal(M.maskedCode(), "••• •••")
})

test("canCopy refuses unsupported entries", () => {
  assert.equal(M.canCopy(full("a")), true)
  assert.equal(M.canCopy(hidden("a")), false)
  assert.equal(M.canCopy(full("a", { kind: "unsupported" })), false)
  assert.equal(M.canCopy(null), false)
})

test("shellQuote wraps in single quotes", () => {
  assert.equal(M.shellQuote("/home/u/p"), "'/home/u/p'")
  assert.equal(M.shellQuote("/a b/it's"), "'/a b/it'\\''s'")
})

test("emptyState maps every status", () => {
  const s = (status, extra) => M.emptyState(Object.assign({
    status, entryCount: 0, matchCount: 0, codesRunning: false,
    promptRunning: false, pluginDir: "/p"
  }, extra || {}))
  assert.deepEqual(plain(s("KEYRING_LOCKED")), { title: "Keyring is locked", detail: "", action: "unlock", actionLabel: "Unlock" })
  assert.equal(s("KEYRING_LOCKED", { promptRunning: true }).title, "Waiting for keyring…")
  assert.equal(s("KEYRING_LOCKED", { promptRunning: true }).action, "")
  assert.equal(s("VAULT_NOT_FOUND").title, "Proton Authenticator not found")
  assert.equal(s("VAULT_NOT_FOUND").action, "openProton")
  for (const code of ["VAULT_FORMAT_CHANGED", "DECRYPT_FAILED"]) {
    assert.equal(s(code).title, "Vault format not recognised — the app may have updated")
    assert.equal(s(code).action, "openProton")
  }
  assert.equal(s("APP_LOCKED").title, "App lock is on — this plugin can't read a password-locked vault")
  assert.equal(s("APP_LOCKED").action, "")
  assert.equal(s("UNSAFE_KEY_STORAGE").title, "Proton is storing its key outside the keyring — open Proton and fix keyring access")
  assert.equal(s("UNSAFE_KEY_STORAGE").action, "openProton")
  for (const code of ["HELPER_MISSING", "HELPER_OUTDATED", "DEPENDENCY_MISSING"]) {
    assert.equal(s(code).title, "Run install.sh")
    assert.equal(s(code).detail, "cd '/p' && ./install.sh")
  }
  assert.equal(s("READY").title, "No accounts yet")
  assert.equal(s("READY").action, "openProton")
  assert.equal(s("READY", { codesRunning: true }).title, "Loading…")
  assert.equal(s("LOADING").title, "Loading…")
  assert.equal(s("READY", { entryCount: 3 }).title, "No matches")
  assert.equal(s("READY", { entryCount: 3, matchCount: 3 }), null)
  assert.equal(s("TIMEOUT").title, M.statusText("TIMEOUT"))
  assert.equal(s("TIMEOUT").action, "retry")
})

test("syncLabel shows the age and the stale hint", () => {
  const h = 3600
  assert.deepEqual(plain(M.syncLabel(10 * h, 10 * h - 120, 24, true)), { text: "Updated 2 min ago", stale: false })
  assert.deepEqual(plain(M.syncLabel(30 * h, 2 * h, 24, true)), { text: "Not synced for 1 d", stale: true })
  assert.deepEqual(plain(M.syncLabel(30 * h, 2 * h, 24, false)), { text: "Updated 1 d ago", stale: false })
  assert.deepEqual(plain(M.syncLabel(30 * h, 0, 24, true)), { text: "", stale: false })
})

test("heroMeta picks the subtitle by state", () => {
  const base = { status: "READY", entryCount: 6, demo: false, promptRunning: false, nowSec: 10000, vaultMtime: 10000 - 120 }
  const m = (extra) => M.heroMeta(Object.assign({}, base, extra || {}))
  assert.equal(m(), "6 accounts · updated 2 min ago")
  assert.equal(m({ entryCount: 1 }), "1 account · updated 2 min ago")
  assert.equal(m({ vaultMtime: 0 }), "6 accounts")
  assert.equal(m({ entryCount: 0 }), "updated 2 min ago")
  assert.equal(m({ demo: true }), "Demo accounts")
  assert.equal(m({ status: "KEYRING_LOCKED" }), "Keyring locked")
  assert.equal(m({ status: "KEYRING_LOCKED", promptRunning: true }), "Waiting for keyring")
  assert.equal(m({ status: "SOMETHING_NEW" }), "something new")
  assert.equal(m({ status: "LOADING" }), "Checking")
})

test("heroBadge prefers privacy over demo", () => {
  assert.equal(M.heroBadge(true, true), "PRIVATE")
  assert.equal(M.heroBadge(false, true), "DEMO")
  assert.equal(M.heroBadge(false, false), "")
})

test("loadDecision: privacy switches load now, selection moves debounce", () => {
  const d = (extra) => M.loadDecision(Object.assign({
    trigger: "change", opened: true, status: "READY",
    last: M.codesRequest(true, "a"), wanted: M.codesRequest(true, "b")
  }, extra || {}))
  assert.equal(d(), "debounce")
  assert.equal(d({ wanted: M.codesRequest(true, "a") }), "none")
  assert.equal(d({ wanted: M.codesRequest(false, "") }), "now")
  assert.equal(d({ last: null }), "now")
  assert.equal(d({ opened: false }), "none")
})

test("loadDecision never retries while the status is an error", () => {
  for (const status of ["KEYRING_LOCKED", "DECRYPT_FAILED", "KEY_NOT_FOUND", "KEYRING_UNAVAILABLE", "LOADING"]) {
    const s = { opened: true, status, last: M.codesRequest(true, "x"), wanted: M.codesRequest(true, "") }
    assert.equal(M.loadDecision(Object.assign({ trigger: "change" }, s)), "none", status)
    assert.equal(M.loadDecision(Object.assign({ trigger: "refresh" }, s)), "none", status)
  }
})

test("loadDecision refreshes at a period boundary even with an unchanged request", () => {
  const r = M.codesRequest(true, "a")
  assert.equal(M.loadDecision({ trigger: "refresh", opened: true, status: "READY", last: r, wanted: r }), "now")
  assert.equal(M.loadDecision({ trigger: "refresh", opened: false, status: "READY", last: r, wanted: r }), "none")
})

test("a failed reveal keeps labels, so the selection and request stay put", () => {
  const entries = [full("a"), full("b")]
  const kept = M.hideCodes(entries, "")
  const list = M.filterAndOrder(kept, "", M.emptyPrefs())
  const wanted = M.codesRequest(true, list[M.selectionIndex(list, "b")].id)
  assert.equal(M.loadDecision({ trigger: "change", opened: true, status: "READY", last: M.codesRequest(true, "b"), wanted }), "none")
})

test("keepsLabels only after keyring or item-level errors", () => {
  for (const e of ["KEYRING_LOCKED", "KEYRING_UNAVAILABLE", "KEY_NOT_FOUND", "ITEM_NOT_FOUND"]) assert.equal(M.keepsLabels(e), true, e)
  for (const e of ["VAULT_FORMAT_CHANGED", "DECRYPT_FAILED", "HELPER_MISSING", "HELPER_OUTDATED", "VAULT_NOT_FOUND", "TIMEOUT", "INTERNAL"])
    assert.equal(M.keepsLabels(e), false, e)
})

test("reloadAfterCheck skips the reload right after a successful unlock", () => {
  const c = (extra) => M.reloadAfterCheck(Object.assign({
    ready: true, panelOpen: true, codesFailed: false, mtimeChanged: false, wasReady: false, codesFresh: true
  }, extra || {}))
  assert.equal(c(), false)
  assert.equal(c({ codesFresh: false }), true)
  assert.equal(c({ wasReady: true, codesFresh: false }), false)
  assert.equal(c({ mtimeChanged: true }), true)
  assert.equal(c({ codesFailed: true }), true)
  assert.equal(c({ ready: false, codesFailed: true }), false)
  assert.equal(c({ panelOpen: false, mtimeChanged: true }), false)
})

test("revealIdFor ignores pointer selection in privacy mode", () => {
  const e = { id: "a" }
  assert.equal(M.revealIdFor(true, e, false), "a")
  assert.equal(M.revealIdFor(true, e, true), "")
  assert.equal(M.revealIdFor(false, e, false), "")
  assert.equal(M.revealIdFor(false, e, true), "")
  assert.equal(M.revealIdFor(true, null, false), "")
})

test("issuerGlyph normalizes case, spacing, punctuation and domains", () => {
  const gh = M.issuerGlyph("GitHub")
  assert.notEqual(gh, "")
  for (const name of ["github", "github.com", "Git Hub", "GITHUB", "GitHub (work)", "www.github.com", "Git-Hub"])
    assert.equal(M.issuerGlyph(name), gh, name)
  assert.equal(M.issuerGlyph("accounts.google.com"), M.issuerGlyph("Google"))
})

test("issuerGlyph maps aliases to one glyph", () => {
  assert.equal(M.issuerGlyph("Gmail"), M.issuerGlyph("Google"))
  assert.equal(M.issuerGlyph("Google Workspace"), M.issuerGlyph("Google"))
  assert.equal(M.issuerGlyph("Amazon Web Services"), M.issuerGlyph("AWS"))
  assert.notEqual(M.issuerGlyph("AWS"), M.issuerGlyph("Amazon"))
  assert.equal(M.issuerGlyph("X"), M.issuerGlyph("Twitter"))
  assert.equal(M.issuerGlyph("x.com"), M.issuerGlyph("Twitter"))
  assert.equal(M.issuerGlyph("Microsoft Account"), M.issuerGlyph("Microsoft"))
  assert.equal(M.issuerGlyph("ChatGPT"), M.issuerGlyph("OpenAI"))
})

test("issuerGlyph returns empty for unknown and prototype-like issuers", () => {
  for (const name of ["Hetzner", "Tailscale", "Proton", "", null, undefined, "constructor", "__proto__", "toString", "hasOwnProperty"])
    assert.equal(M.issuerGlyph(name), "", String(name))
  assert.equal(M.issuerGlyph("Gitea (home) server"), M.issuerGlyph("gitea"))
})

test("issuerGlyph never falls back to short or common-word keys", () => {
  for (const name of ["Live Nation", "X-Plane", "X Bank", "Steam Plumbing", "Medium Rare"])
    assert.equal(M.issuerGlyph(name), "", name)
  assert.notEqual(M.issuerGlyph("X"), "")
  assert.equal(M.issuerGlyph("X"), M.issuerGlyph("Twitter"))
  assert.equal(M.issuerGlyph("Live"), M.issuerGlyph("Microsoft"))
  assert.equal(M.issuerGlyph("Steam"), M.issuerGlyph("steampowered.com"))
})

import { test } from "node:test"
import assert from "node:assert/strict"
import { loadModel } from "./load-model.mjs"

const M = loadModel()
const plain = (value) => JSON.parse(JSON.stringify(value))

test("pluginDirFromUrl strips the scheme and trailing slash", () => {
  assert.equal(M.pluginDirFromUrl("file:///home/u/p/"), "/home/u/p")
  assert.equal(M.pluginDirFromUrl("/home/u/p"), "/home/u/p")
})

test("pluginDirFromUrl percent-decodes the path", () => {
  assert.equal(M.pluginDirFromUrl("file:///home/u/My%20Plugins/p/"), "/home/u/My Plugins/p")
  assert.equal(M.pluginDirFromUrl("file:///home/u/%E2%9C%93"), "/home/u/\u2713")
})

test("validId follows the helper rule", () => {
  for (const id of ["demo-github", "A.b:c_d-", "x".repeat(128)]) assert.equal(M.validId(id), true, id)
  for (const id of ["", "-x", "--demo", "a/b", "a b", "x".repeat(129), null, 7]) assert.equal(M.validId(id), false, String(id))
})

test("clampClearAfter keeps 5..120 and defaults garbage to 20", () => {
  assert.equal(M.clampClearAfter(1), 5)
  assert.equal(M.clampClearAfter(500), 120)
  assert.equal(M.clampClearAfter(30), 30)
  assert.equal(M.clampClearAfter("nope"), 20)
})

test("replyLine waits for the newline", () => {
  assert.equal(M.replyLine('{"ok":true'), null)
  assert.equal(M.replyLine('{"ok":true}\nrest'), '{"ok":true}')
})

test("parseReply maps the envelope", () => {
  assert.deepEqual(plain(M.parseReply('{"ok":true,"protocol":1,"status":"READY"}')), { ok: true, protocol: 1, status: "READY" })
  assert.deepEqual(plain(M.parseReply('{"ok":false,"protocol":1,"error":"VAULT_BUSY"}')), { ok: false, error: "VAULT_BUSY" })
  assert.deepEqual(plain(M.parseReply('{"ok":false,"protocol":1}')), { ok: false, error: "INTERNAL" })
})

test("parseReply treats garbage and other protocols as an outdated helper", () => {
  for (const text of ["not json", "[]", "null", '"READY"', '{"ok":true,"protocol":2}', '{"ok":true}'])
    assert.deepEqual(plain(M.parseReply(text)), { ok: false, error: "HELPER_OUTDATED" }, text)
})

test("parseReply treats empty output as a crash", () => {
  for (const text of ["", "  \n", null])
    assert.deepEqual(plain(M.parseReply(text)), { ok: false, error: "INTERNAL" }, String(text))
})

test("applyEdits replays queued edits on top of the loaded prefs", () => {
  const stored = { pinned: ["keep"], recent: ["r1", "r2"], privacy: true }
  const edits = [M.pinEdit("new", true), M.recentEdit("r2"), M.pinEdit("keep", false), M.pinEdit("bad id", true)]
  assert.deepEqual(plain(M.applyEdits(stored, edits)), { pinned: ["new"], recent: ["r2", "r1"], privacy: true })
  assert.deepEqual(plain(M.applyEdits(stored, [])), stored)
  assert.equal(M.applyEdits(stored, [M.privacyEdit(false)]).privacy, false)
  assert.deepEqual(plain(stored), { pinned: ["keep"], recent: ["r1", "r2"], privacy: true })
})

test("prefs edits keep ids unique and recent capped", () => {
  let p = M.emptyPrefs()
  p = M.withPinned(p, "a", true)
  p = M.withPinned(p, "a", true)
  p = M.withPinned(p, "b", true)
  assert.deepEqual(plain(p.pinned), ["a", "b"])
  p = M.withPinned(p, "a", false)
  assert.deepEqual(plain(p.pinned), ["b"])
  for (const id of ["1", "2", "3", "4", "5", "6", "3"]) p = M.withRecent(p, id)
  assert.deepEqual(plain(p.recent), ["3", "6", "5", "4", "2"])
  assert.equal(M.withPrivacy(p, true).privacy, true)
  assert.equal(M.withPrivacy(p, "yes").privacy, false)
})

test("normalizePrefs drops invalid ids", () => {
  const p = M.normalizePrefs({ pinned: ["ok", "-bad", 3], recent: ["--demo"], privacy: 1 })
  assert.deepEqual(plain(p), { pinned: ["ok"], recent: [], privacy: false })
})

test("statusGlyph and statusText cover every state", () => {
  assert.equal(M.statusGlyph("READY"), "\u{F0BC4}")
  assert.equal(M.statusGlyph("KEYRING_LOCKED"), "\u{F033E}")
  assert.equal(M.statusGlyph("HELPER_MISSING"), "\u{F0026}")
  assert.equal(M.statusText("HELPER_MISSING"), "Helper not built; run install.sh")
  assert.match(M.statusText("SOMETHING_NEW"), /SOMETHING_NEW/)
})

test("pluginDirFromUrl fails closed on malformed or non-absolute input", () => {
  for (const url of ["file:///home/u/%E0%A4%A", "", null, undefined, "file://", "/", "relative/dir"])
    assert.equal(M.pluginDirFromUrl(url), null, String(url))
})

const entry = (id, issuer, account = "") => ({ id, issuer, account, kind: "totp", code: "123456", nextCode: "654321", period: 30, digits: 6, remaining: 20 })
const ids = (list) => Array.from(list, (e) => e.id)
const sample = [
  entry("e1", "Zeta", "a@x"),
  entry("e2", "GitHub", "me"),
  entry("e3", "Gitea (home)", "me"),
  entry("e4", "alpha", "b@x"),
  entry("e5", "Alpha", "a@x"),
  entry("e6", "Gmail"),
]

test("empty query: pinned, then recent without duplicates, then the rest", () => {
  const prefs = { pinned: ["e6", "e1"], recent: ["e1", "e4", "e2"], privacy: false }
  assert.deepEqual(ids(M.filterAndOrder(sample, "", prefs)), ["e6", "e1", "e4", "e2", "e5", "e3"])
})

test("empty query tolerates missing prefs, stale ids and null fields", () => {
  const entries = [entry("b", null, null), entry("a", "Acme", null)]
  assert.deepEqual(ids(M.filterAndOrder(entries, undefined, null)), ["b", "a"])
  assert.deepEqual(ids(M.filterAndOrder(entries, "", { pinned: ["gone"], recent: ["a"] })), ["a", "b"])
  assert.deepEqual(ids(M.filterAndOrder(entries, "ac", M.emptyPrefs())), ["a"])
  assert.deepEqual(ids(M.filterAndOrder(null, "x", M.emptyPrefs())), [])
})

test("rest sorts by issuer then account, case-insensitively", () => {
  assert.deepEqual(ids(M.filterAndOrder(sample, "", M.emptyPrefs())), ["e5", "e4", "e3", "e2", "e6", "e1"])
})

test("gh matches GitHub before Gitea (home)", () => {
  assert.deepEqual(ids(M.filterAndOrder(sample, "gh", M.emptyPrefs())), ["e2", "e3"])
  assert.deepEqual(ids(M.filterAndOrder(sample, "GH", M.emptyPrefs())), ["e2", "e3"])
})

test("fuzzyScore ranks prefix 3, word start 2, subsequence 1, none 0", () => {
  assert.equal(M.fuzzyScore("GitHub", "git"), 3)
  assert.equal(M.fuzzyScore("My GitHub", "git"), 2)
  assert.equal(M.fuzzyScore("Gitea (home)", "gh"), 1)
  assert.equal(M.fuzzyScore("GitHub", "xyz"), 0)
  assert.equal(M.fuzzyScore("GitHub", ""), 0)
  assert.equal(M.fuzzyScore(null, "a"), 0)
})

test("query ties keep the empty-query order, pinned ahead", () => {
  const prefs = { pinned: ["e5"], recent: [], privacy: false }
  assert.deepEqual(ids(M.filterAndOrder(sample, "alp", prefs)), ["e5", "e4"])
})

test("query also matches the account", () => {
  assert.deepEqual(ids(M.filterAndOrder(sample, "a@x", M.emptyPrefs())), ["e5", "e1"])
})

test("non-ASCII issuers match case-insensitively", () => {
  const list = [entry("u1", "\u042F\u043D\u0434\u0435\u043A\u0441"), entry("u2", "Other")]
  assert.deepEqual(ids(M.filterAndOrder(list, "\u044F\u043D", M.emptyPrefs())), ["u1"])
  assert.equal(M.fuzzyScore("\u042F\u043D\u0434\u0435\u043A\u0441", "\u044F\u043D"), 3)
})

test("groupCode splits by length", () => {
  assert.equal(M.groupCode("482913"), "482 913")
  assert.equal(M.groupCode("4829130"), "482 9130")
  assert.equal(M.groupCode("48291307"), "4829 1307")
  assert.equal(M.groupCode("12345"), "12345")
  assert.equal(M.groupCode("ABCDE"), "ABCDE")
  assert.equal(M.groupCode(null), "")
})

test("isUrgent at 5 seconds or less", () => {
  assert.equal(M.isUrgent(5), true)
  assert.equal(M.isUrgent(6), false)
  assert.equal(M.isUrgent(null), false)
})

test("ageLabel boundaries", () => {
  assert.equal(M.ageLabel(1000, 1000 - 59), "just now")
  assert.equal(M.ageLabel(1000, 1000 - 60), "1 min ago")
  assert.equal(M.ageLabel(10000, 10000 - 3599), "59 min ago")
  assert.equal(M.ageLabel(10000, 10000 - 3600), "1 h ago")
  assert.equal(M.ageLabel(100000, 100000 - 86399), "23 h ago")
  assert.equal(M.ageLabel(100000, 100000 - 86400), "1 d ago")
  assert.equal(M.ageLabel(1000, 2000), "just now")
})

test("isStale compares age to the threshold in hours", () => {
  const now = 1000000
  assert.equal(M.isStale(now, now - 24 * 3600 + 1, 24), false)
  assert.equal(M.isStale(now, now - 24 * 3600, 24), true)
  assert.equal(M.isStale(now, now, 24), false)
})

test("ids named like Object.prototype keys survive ordering", () => {
  const list = [entry("constructor", "C"), entry("toString", "T"), entry("__proto__", "P"), entry("ok", "O")]
  assert.deepEqual(ids(M.filterAndOrder(list, "", M.emptyPrefs())), ["constructor", "ok", "__proto__", "toString"])
  const prefs = { pinned: ["__proto__", "toString"], recent: ["constructor", "__proto__"], privacy: false }
  assert.deepEqual(ids(M.filterAndOrder(list, "", prefs)), ["__proto__", "toString", "constructor", "ok"])
})

test("statusText ignores inherited keys", () => {
  assert.match(M.statusText("constructor"), /^Proton Authenticator error: constructor$/)
})

test("null entries are skipped", () => {
  const list = [null, entry("a", "Acme"), undefined]
  assert.deepEqual(ids(M.filterAndOrder(list, "", M.emptyPrefs())), ["a"])
  assert.deepEqual(ids(M.filterAndOrder(list, "ac", M.emptyPrefs())), ["a"])
})

test("an account prefix scores 2, below an issuer prefix", () => {
  const list = [entry("acc", "Zed", "alice"), entry("iss", "Alice", "x")]
  assert.deepEqual(ids(M.filterAndOrder(list, "ali", M.emptyPrefs())), ["iss", "acc"])
})

test("camel humps and digits", () => {
  assert.equal(M.fuzzyScore("GitHUB", "gh"), 2)
  assert.equal(M.fuzzyScore("GitHUB", "hub"), 2)
  assert.equal(M.fuzzyScore("GitHUB", "ub"), 1)
  assert.equal(M.fuzzyScore("Web3Auth", "auth"), 1)
  assert.equal(M.fuzzyScore("Web3 Auth", "auth"), 2)
})

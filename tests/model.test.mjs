import { test } from "node:test"
import assert from "node:assert/strict"
import { loadModel } from "./load-model.mjs"

const M = loadModel()
const plain = (value) => JSON.parse(JSON.stringify(value))

test("pluginDirFromUrl strips the scheme and trailing slash", () => {
  assert.equal(M.pluginDirFromUrl("file:///home/u/p/"), "/home/u/p")
  assert.equal(M.pluginDirFromUrl("/home/u/p"), "/home/u/p")
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
  for (const text of ["", "not json", "[]", "null", '"READY"', '{"ok":true,"protocol":2}', '{"ok":true}'])
    assert.deepEqual(plain(M.parseReply(text)), { ok: false, error: "HELPER_OUTDATED" }, text)
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

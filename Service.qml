import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

// The single owner of plugin state and the only place that runs pa-helper.
//
// Bar widgets exist once per monitor and indicators twice over, so they only
// read these properties and call these functions.
Item {
  id: root

  // Injected by omarchy-shell's service loader.
  property var shell: null
  property var manifest: null
  property var pluginRegistry: null

  readonly property string pluginDir: Model.pluginDirFromUrl(Qt.resolvedUrl("."))

  // Fake accounts from public RFC seeds; never touches the vault or keyring.
  property bool demo: false

  // "LOADING" | "READY" | an error code. A failed codes call outranks the
  // last check, so the panel shows why it has no codes.
  property string status: "LOADING"
  property string checkStatus: "LOADING"
  property string codesError: ""

  // Codes live here only while a panel is open.
  property var entries: []
  property int now: 0
  property int vaultMtime: 0
  property var prefs: Model.emptyPrefs()

  // The demo vault has a fixed, old mtime.
  readonly property bool staleHintAllowed: !root.demo

  readonly property bool panelOpen: root.openPanels.length > 0
  property var openPanels: []

  // While the unlock prompt is up nothing else may run: a second helper call
  // would race the prompt for the keyring.
  property bool promptRunning: false
  property bool checkRunning: false
  property bool codesRunning: false
  property var queuedOnlyId: null
  // Bumped whenever codes are cleared, so a reply that was already in flight
  // cannot bring them back after the panel closed.
  property int codesGeneration: 0
  property string lastOnlyId: ""

  // prefs set calls are serialized: a writer killed mid-write leaves a temp
  // file that makes the next set fail for up to 30 s. The latest wanted state
  // waits here and is written whole, so a failed write is retried with the
  // next change.
  property bool prefsWriting: false
  property var prefsWanted: null

  signal changed()

  HelperClient {
    id: helper
    helperPath: root.pluginDir + "/bin/pa-helper"
  }

  function withDemo(args) {
    return root.demo ? args.concat(["--demo"]) : args
  }

  function applyStatus() {
    root.status = root.codesError !== "" ? root.codesError : root.checkStatus
    root.changed()
  }

  function panelOpened(owner) {
    if (root.openPanels.indexOf(owner) >= 0) return
    root.openPanels = root.openPanels.concat([owner])
    root.refreshStatus()
  }

  function panelClosed(owner) {
    var rest = root.openPanels.filter(function(p) { return p !== owner })
    if (rest.length === root.openPanels.length) return
    root.openPanels = rest
    if (rest.length === 0) root.clearCodes()
  }

  function refreshStatus() {
    if (root.promptRunning || root.checkRunning) return
    root.checkRunning = true
    helper.call(root.withDemo(["check"]), "", function(reply) {
      root.checkRunning = false
      var before = root.vaultMtime
      if (reply.ok) {
        root.checkStatus = typeof reply.status === "string" ? reply.status : "INTERNAL"
        root.vaultMtime = typeof reply.vaultMtime === "number" ? reply.vaultMtime : 0
      } else {
        root.checkStatus = reply.error
      }
      root.applyStatus()
      if (root.panelOpen && before !== 0 && root.vaultMtime !== before)
        root.loadCodes(root.lastOnlyId)
    })
  }

  // onlyId: load just that entry (privacy mode keeps the others out of QML).
  function loadCodes(onlyId) {
    var id = onlyId ? String(onlyId) : ""
    if (id !== "" && !Model.validId(id)) return
    root.lastOnlyId = id
    if (root.promptRunning || !root.panelOpen) return
    if (root.codesRunning) {
      root.queuedOnlyId = id
      return
    }
    runCodes(id, false)
  }

  function runCodes(id, allowPrompt) {
    if (!root.panelOpen) return
    var args = ["codes"]
    if (id !== "") args = args.concat(["--only", id])
    if (allowPrompt) args.push("--allow-prompt")
    var generation = root.codesGeneration
    root.codesRunning = true
    if (allowPrompt) root.promptRunning = true
    helper.call(root.withDemo(args), "", function(reply) {
      root.codesRunning = false
      if (allowPrompt) root.promptRunning = false
      if (generation === root.codesGeneration) {
        if (reply.ok) {
          root.entries = Array.isArray(reply.entries) ? reply.entries : []
          root.now = typeof reply.now === "number" ? reply.now : 0
          root.codesError = ""
        } else {
          root.entries = []
          root.codesError = reply.error
        }
        root.applyStatus()
      }
      if (allowPrompt) root.refreshStatus()
      if (root.queuedOnlyId !== null) {
        var next = root.queuedOnlyId
        root.queuedOnlyId = null
        if (root.panelOpen) root.loadCodes(next)
      }
      root.flushPrefs()
    })
  }

  function clearCodes() {
    root.codesGeneration++
    root.queuedOnlyId = null
    root.entries = []
    root.now = 0
    root.codesError = ""
    root.applyStatus()
  }

  // Shows the keyring's unlock prompt; the only call allowed to.
  function unlock() {
    if (root.promptRunning || root.codesRunning) return
    runCodes(root.lastOnlyId, true)
  }

  // onDone(ok) fires when the helper has replied; it keeps running in the
  // background to clear the clipboard later.
  function copy(id, clearAfterSeconds, onDone) {
    var done = typeof onDone === "function" ? onDone : function() {}
    if (!Model.validId(id) || root.promptRunning) {
      done(false)
      return
    }
    var seconds = Model.clampClearAfter(clearAfterSeconds === undefined
                                        ? Model.CLEAR_AFTER_DEFAULT : clearAfterSeconds)
    helper.call(root.withDemo(["copy", id, "--clear-after", String(seconds)]), "", function(reply) {
      if (reply.ok) root.noteRecent(id)
      done(reply.ok === true)
    })
  }

  function openProton() {
    Quickshell.execDetached(["/usr/bin/proton-authenticator"])
  }

  function loadPrefs() {
    if (root.promptRunning) return
    helper.call(["prefs", "get"], "", function(reply) {
      if (reply.ok && root.prefsWanted === null && !root.prefsWriting)
        root.prefs = Model.normalizePrefs(reply)
    })
  }

  function setPinned(id, pinned) {
    if (Model.validId(id)) writePrefs(Model.withPinned(root.prefs, id, pinned === true))
  }

  function noteRecent(id) {
    if (Model.validId(id)) writePrefs(Model.withRecent(root.prefs, id))
  }

  function setPrivacy(on) {
    writePrefs(Model.withPrivacy(root.prefs, on === true))
  }

  function writePrefs(next) {
    root.prefs = next
    root.prefsWanted = next
    root.flushPrefs()
  }

  function flushPrefs() {
    if (root.prefsWriting || root.promptRunning || root.prefsWanted === null) return
    var next = root.prefsWanted
    root.prefsWanted = null
    root.prefsWriting = true
    helper.call(["prefs", "set"], JSON.stringify(next), function(reply) {
      root.prefsWriting = false
      if (root.prefsWanted !== null) {
        root.flushPrefs()
      } else if (reply.ok) {
        root.prefs = Model.normalizePrefs(reply)
      }
    })
  }

  Timer {
    interval: root.panelOpen ? 5000 : 60000
    running: true
    repeat: true
    onTriggered: root.refreshStatus()
  }

  Component.onCompleted: {
    root.refreshStatus()
    root.loadPrefs()
  }

  IpcHandler {
    target: "sviat.proton-authenticator"

    function status(): string { return root.status }
    function refresh(): void { root.refreshStatus() }
  }
}

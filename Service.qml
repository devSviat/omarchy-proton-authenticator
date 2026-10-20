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

  readonly property string pluginDir: Model.pluginDirFromUrl(Qt.resolvedUrl(".")) || ""

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

  // Until the stored prefs are read, privacy is assumed on, so a failed
  // read can never expose codes the user chose to hide.
  property bool prefsLoaded: false
  readonly property bool privacyEffective: !root.prefsLoaded || root.prefs.privacy === true

  // The demo vault has a fixed, old mtime.
  readonly property bool staleHintAllowed: !root.demo

  readonly property bool panelOpen: root.openPanels.length > 0
  property var openPanels: []

  // While the unlock prompt is up nothing else may run: a second helper call
  // would race the prompt for the keyring.
  property bool promptRunning: false
  property bool checkRunning: false
  property bool codesRunning: false
  // A codes call succeeded since the last non-READY check, e.g. the unlock
  // prompt's, so a return to READY needs no reload.
  property bool codesFresh: false
  // Unlock pressed while another codes call was running; it runs next.
  property bool unlockQueued: false
  property var queuedRequest: null
  // Bumped whenever codes are cleared, so a reply that was already in flight
  // cannot bring them back after the panel closed.
  property int codesGeneration: 0
  // Private until the panel says otherwise, so a reload triggered before the
  // panel's first request cannot fetch every code.
  property var lastRequest: Model.codesRequest(true, "")

  // prefs set calls are serialized: a writer killed mid-write leaves a temp
  // file that makes the next set fail for up to 30 s. The latest wanted state
  // waits here and is written whole. A failed write is retried after the next
  // successful check, or superseded by the next change.
  property bool prefsLoading: false
  property bool prefsWriting: false
  property var prefsWanted: null
  property var prefsRetry: null
  // Edits made before the stored prefs were read; replayed on top of them,
  // because writing before a read would wipe the stored pins and privacy.
  property var prefsEdits: []
  // Bumped on a demo switch, so a prefs read in flight cannot cross over.
  property int prefsGeneration: 0

  signal changed()

  HelperClient {
    id: helper
    helperPath: root.pluginDir === "" ? "" : root.pluginDir + "/bin/pa-helper"
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
      var wasReady = root.checkStatus === "READY"
      if (reply.ok) {
        root.checkStatus = typeof reply.status === "string" ? reply.status : "INTERNAL"
        root.vaultMtime = typeof reply.vaultMtime === "number" ? reply.vaultMtime : 0
      } else {
        root.checkStatus = reply.error
      }
      var codesFailed = root.codesError !== ""
      // A locked keyring or a broken vault must not leave old codes on screen.
      // A locked keyring says nothing about the vault, so its labels stay.
      if (root.checkStatus === "KEYRING_LOCKED") root.dropCodes()
      else if (root.checkStatus !== "READY") root.clearCodes()
      else root.applyStatus()
      if (reply.ok) root.retryPrefs()
      if (Model.reloadAfterCheck({
            ready: root.checkStatus === "READY",
            panelOpen: root.panelOpen,
            codesFailed: codesFailed,
            mtimeChanged: root.vaultMtime !== before,
            wasReady: wasReady,
            codesFresh: root.codesFresh
          }))
        root.loadCodes(root.lastRequest)
    })
  }

  // request: Model.codesRequest(privateMode, revealId). In private mode only
  // the revealed entry carries a code; codes already held for other rows are
  // dropped at once instead of waiting for the reply.
  function loadCodes(request) {
    var req = Model.codesRequest(request ? request.privateMode : true, request ? request.revealId : "")
    root.lastRequest = req
    if (req.privateMode) root.hideExcept(req.revealId)
    if (root.promptRunning || !root.panelOpen) return
    if (root.codesRunning) {
      root.queuedRequest = req
      return
    }
    runCodes(req, false)
  }

  // Drops every code but revealId's without running the helper, so a
  // privacy-mode selection change never leaves the previous code loaded.
  function hideExcept(revealId) {
    var id = Model.validId(revealId) ? revealId : ""
    var exposed = root.entries.some(function(e) {
      return e && e.id !== id && (e.code !== null || e.nextCode !== null)
    })
    if (exposed) root.entries = Model.hideCodes(root.entries, id)
  }

  function runCodes(req, allowPrompt) {
    if (!root.panelOpen) return
    var args = Model.codesArgs(req)
    if (allowPrompt) args.push("--allow-prompt")
    var generation = root.codesGeneration
    root.codesRunning = true
    if (allowPrompt) root.promptRunning = true
    helper.call(root.withDemo(args), "", function(reply) {
      root.codesRunning = false
      if (allowPrompt) root.promptRunning = false
      var wanted = root.lastRequest
      if (generation === root.codesGeneration) {
        if (reply.ok) {
          var entries = Array.isArray(reply.entries) ? reply.entries : []
          // now first: entries watchers read it to time the next refresh.
          root.now = typeof reply.now === "number" ? reply.now : 0
          // Privacy may have been switched on while a full listing was in flight.
          root.entries = wanted.privateMode ? Model.hideCodes(entries, wanted.revealId) : entries
          root.codesError = ""
          root.codesFresh = Model.sameRequest(wanted, req)
        } else if (reply.error === "ITEM_NOT_FOUND" && req.revealId !== "") {
          // The revealed entry was deleted; list the rest so a new selection
          // can be revealed.
          if (Model.sameRequest(wanted, req) && root.queuedRequest === null)
            root.queuedRequest = Model.codesRequest(true, "")
        } else {
          // Labels stay after a keyring or reveal failure, so the list does
          // not empty and move the selection, which would start another reveal.
          root.entries = Model.keepsLabels(reply.error) ? Model.hideCodes(root.entries, "") : []
          root.codesError = reply.error
          root.codesFresh = false
        }
        root.applyStatus()
      }
      if (allowPrompt) root.refreshStatus()
      if (root.unlockQueued) {
        root.unlockQueued = false
        root.queuedRequest = null
        if (root.panelOpen && !root.promptRunning) root.runCodes(root.lastRequest, true)
      } else if (root.queuedRequest !== null) {
        var next = root.queuedRequest
        root.queuedRequest = null
        if (root.panelOpen) root.loadCodes(next)
      }
      root.flushPrefs()
      root.loadPrefs()
    })
  }

  function clearCodes() {
    root.codesGeneration++
    root.codesFresh = false
    root.queuedRequest = null
    root.unlockQueued = false
    root.entries = []
    root.now = 0
    root.codesError = ""
    root.applyStatus()
  }

  function dropCodes() {
    root.codesGeneration++
    root.codesFresh = false
    root.queuedRequest = null
    root.entries = Model.hideCodes(root.entries, "")
    root.codesError = ""
    root.applyStatus()
  }

  // Shows the keyring's unlock prompt; the only call allowed to. Pressed
  // while a codes call runs, it waits for that call instead of being lost.
  function unlock() {
    if (root.promptRunning) return
    if (root.codesRunning) {
      root.unlockQueued = true
      return
    }
    runCodes(root.lastRequest, true)
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

  // Demo prefs live in memory only: demo ids never reach the real file, and
  // the real prefs never show up in demo state.
  function resetPrefs() {
    root.prefsGeneration++
    root.prefs = Model.emptyPrefs()
    root.prefsEdits = []
    root.prefsWanted = null
    root.prefsRetry = null
    root.prefsLoading = false
    root.prefsLoaded = root.demo
    if (!root.demo) root.loadPrefs()
  }

  onDemoChanged: {
    root.clearCodes()
    root.resetPrefs()
    root.refreshStatus()
  }

  function loadPrefs() {
    if (root.demo || root.prefsLoaded || root.prefsLoading || root.promptRunning) return
    var generation = root.prefsGeneration
    root.prefsLoading = true
    helper.call(["prefs", "get"], "", function(reply) {
      if (generation !== root.prefsGeneration) return
      root.prefsLoading = false
      if (!reply.ok) return
      var edits = root.prefsEdits
      root.prefsEdits = []
      root.prefs = Model.applyEdits(Model.normalizePrefs(reply), edits)
      root.prefsLoaded = true
      if (edits.length > 0) root.writePrefs(root.prefs)
    })
  }

  function retryPrefs() {
    if (root.demo) return
    if (!root.prefsLoaded) {
      root.loadPrefs()
      return
    }
    if (root.prefsRetry !== null && root.prefsWanted === null) {
      root.prefsWanted = root.prefsRetry
      root.prefsRetry = null
      root.flushPrefs()
    }
  }

  function editPrefs(edit) {
    root.prefs = Model.applyEdits(root.prefs, [edit])
    if (root.demo) return
    if (!root.prefsLoaded) {
      root.prefsEdits = root.prefsEdits.concat([edit])
      root.loadPrefs()
      return
    }
    root.writePrefs(root.prefs)
  }

  function setPinned(id, pinned) {
    if (Model.validId(id)) editPrefs(Model.pinEdit(id, pinned === true))
  }

  function noteRecent(id) {
    if (Model.validId(id)) editPrefs(Model.recentEdit(id))
  }

  function setPrivacy(on) {
    editPrefs(Model.privacyEdit(on === true))
  }

  function writePrefs(next) {
    root.prefsWanted = next
    root.prefsRetry = null
    root.flushPrefs()
  }

  function flushPrefs() {
    if (root.demo || !root.prefsLoaded || root.prefsWriting || root.promptRunning
        || root.prefsWanted === null) return
    var next = root.prefsWanted
    var generation = root.prefsGeneration
    root.prefsWanted = null
    root.prefsWriting = true
    helper.call(["prefs", "set"], JSON.stringify(next), function(reply) {
      root.prefsWriting = false
      if (generation !== root.prefsGeneration) return
      if (root.prefsWanted !== null) {
        root.flushPrefs()
      } else if (reply.ok) {
        root.prefs = Model.normalizePrefs(reply)
      } else {
        root.prefsRetry = next
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

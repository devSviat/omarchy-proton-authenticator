import QtQuick
import qs.Commons
import qs.Ui
import "Model.js" as Model
import "components"

// Bar button and the keyboard-driven code list. Rendering only: every helper
// call goes through the sviat.proton-authenticator service.
Panel {
  id: root
  moduleName: "sviat.proton-authenticator"
  ipcTarget: "sviat.proton-authenticator"
  // Service.qml owns the "sviat.proton-authenticator" IPC target; the panel is
  // toggled with `omarchy-shell shell toggle sviat.proton-authenticator`.
  manageIpc: false

  readonly property var service: bar?.shell?.serviceFor("sviat.proton-authenticator")
  readonly property string status: service ? service.status : "LOADING"
  readonly property var entries: service ? service.entries : []
  readonly property var prefs: service ? service.prefs : Model.emptyPrefs()
  // Fails closed: without the service, or before prefs load, codes stay hidden.
  readonly property bool privacy: service ? service.privacyEffective : true
  readonly property int replyNow: service ? service.now : 0

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property bool closeOnCopy: root.setting("closeOnCopy", true) !== false
  readonly property int clearClipboardSeconds: Model.clampClearAfter(root.setting("clearClipboardSeconds", Model.CLEAR_AFTER_DEFAULT))
  readonly property int staleHours: Math.max(1, Number(root.setting("staleHours", 24)) || 24)
  // Development and screenshots only; deliberately absent from the manifest schema.
  readonly property bool demoWanted: root.setting("demo", false) === true

  property string query: ""
  property string selectedId: ""
  property real clockMs: Date.now()
  readonly property int nowSec: Math.floor(root.clockMs / 1000)

  readonly property var filtered: Model.filterAndOrder(root.entries, root.query, root.prefs)
  readonly property int selectedIndex: Model.selectionIndex(root.filtered, root.selectedId)
  readonly property var selectedEntry: root.selectedIndex >= 0 ? root.filtered[root.selectedIndex] : null
  readonly property var wantedRequest: Model.codesRequest(root.privacy,
                                                          root.selectedEntry ? root.selectedEntry.id : "")

  readonly property var emptyState: Model.emptyState({
    status: root.status,
    entryCount: root.entries.length,
    matchCount: root.filtered.length,
    codesRunning: root.service ? root.service.codesRunning : false,
    promptRunning: root.service ? root.service.promptRunning : false,
    pluginDir: root.service ? root.service.pluginDir : ""
  })
  // The header carries the sync age; the footer only warns when it is stale.
  readonly property var syncInfo: root.service && root.service.staleHintAllowed
    ? Model.syncLabel(root.nowSec, root.service.vaultMtime, root.staleHours, true)
    : { text: "", stale: false }
  readonly property string heroMeta: Model.heroMeta({
    status: root.status,
    entryCount: root.entries.length,
    demo: root.service ? root.service.demo : false,
    promptRunning: root.service ? root.service.promptRunning : false,
    nowSec: root.nowSec,
    vaultMtime: root.service ? root.service.vaultMtime : 0
  })

  property bool copying: false
  property string feedbackId: ""
  property string feedbackText: ""
  property bool feedbackClose: false
  property int copyGeneration: 0

  // The service can appear after the panel, or be reloaded while it is open.
  property var registeredWith: null

  function syncRegistration() {
    var target = root.opened ? root.service : null
    if (root.registeredWith === target) return
    if (root.registeredWith) root.registeredWith.panelClosed(root)
    root.registeredWith = target
    if (target) {
      target.panelOpened(root)
      target.loadCodes(root.wantedRequest)
    }
  }

  function applyDemo() {
    if (root.service && root.service.demo !== root.demoWanted) root.service.demo = root.demoWanted
  }

  function resetView() {
    root.query = ""
    root.selectedId = ""
    root.copyGeneration++
    root.copying = false
    root.feedbackId = ""
    root.feedbackText = ""
    feedbackTimer.stop()
    revealDebounce.stop()
    refreshTimer.stop()
    root.clockMs = Date.now()
  }

  onOpenedChanged: {
    root.resetView()
    root.syncRegistration()
    if (root.opened) Qt.callLater(function() { if (root.opened) searchField.forceActiveFocus() })
  }
  onServiceChanged: {
    root.applyDemo()
    root.syncRegistration()
  }
  onDemoWantedChanged: root.applyDemo()
  Component.onCompleted: root.applyDemo()
  Component.onDestruction: if (root.registeredWith) root.registeredWith.panelClosed(root)

  function decide(trigger) {
    return Model.loadDecision({
      trigger: trigger,
      opened: root.opened && !!root.service,
      status: root.status,
      last: root.service ? root.service.lastRequest : null,
      wanted: root.wantedRequest
    })
  }

  // Switching privacy reloads at once (turning it on must drop codes now);
  // walking the list only reveals the row the selection settles on.
  function reconcile() {
    if (root.opened && root.service && root.wantedRequest.privateMode)
      root.service.hideExcept(root.wantedRequest.revealId)
    var decision = root.decide("change")
    if (decision === "debounce") {
      revealDebounce.restart()
      return
    }
    revealDebounce.stop()
    if (decision === "now") root.service.loadCodes(root.wantedRequest)
  }

  function revealNow() {
    revealDebounce.stop()
    if (root.decide("change") !== "none") root.service.loadCodes(root.wantedRequest)
  }

  onWantedRequestChanged: root.reconcile()
  onStatusChanged: root.reconcile()

  onQueryChanged: root.selectedId = ""

  onEntriesChanged: {
    root.clockMs = Date.now()
    var delay = Model.refreshDelayMs(root.entries, root.replyNow, root.clockMs)
    if (delay < 0 || !root.opened) {
      refreshTimer.stop()
    } else {
      refreshTimer.interval = delay
      refreshTimer.restart()
    }
  }

  Timer {
    id: revealDebounce
    interval: 150
    onTriggered: if (root.decide("change") !== "none") root.service.loadCodes(root.wantedRequest)
  }

  // One helper call per period boundary; the rings in between run on the
  // local tick below.
  Timer {
    id: refreshTimer
    repeat: false
    onTriggered: if (root.decide("refresh") === "now") root.service.loadCodes(root.wantedRequest)
  }

  Timer {
    interval: 1000
    repeat: true
    running: root.opened
    onTriggered: root.clockMs = Date.now()
  }

  Timer {
    id: feedbackTimer
    repeat: false
    onTriggered: {
      var close = root.feedbackClose
      root.feedbackId = ""
      root.feedbackText = ""
      if (close && root.opened) root.close()
    }
  }

  function move(delta) {
    pointerGate.reset()
    var next = Model.moveSelection(root.filtered, root.selectedId, delta)
    if (next !== "") root.selectedId = next
  }

  function runAction(action) {
    if (!root.service) return
    if (action === "unlock") {
      root.service.unlock()
    } else if (action === "openProton") {
      root.service.openProton()
    } else if (action === "retry") {
      root.service.refreshStatus()
      root.service.loadCodes(root.wantedRequest)
    }
  }

  function activate() {
    if (root.emptyState !== null && root.emptyState.action !== "") root.runAction(root.emptyState.action)
    else root.useEntry(root.selectedEntry)
  }

  // A row still hidden by privacy mode is revealed first, never copied blind.
  function useEntry(entry) {
    if (!entry) return
    if (Model.isHidden(entry)) root.revealNow()
    else root.copyEntry(entry)
  }

  function copyEntry(entry) {
    if (!root.service || root.copying || !Model.canCopy(entry)) return
    var generation = ++root.copyGeneration
    feedbackTimer.stop()
    root.copying = true
    root.feedbackId = entry.id
    root.feedbackText = "Copying…"
    root.service.copy(entry.id, root.clearClipboardSeconds, function(ok) {
      if (generation !== root.copyGeneration) return
      root.copying = false
      if (!root.opened) return
      root.feedbackText = ok ? "Copied ✓" : "Copy failed"
      root.feedbackClose = ok && root.closeOnCopy
      feedbackTimer.interval = ok ? 600 : 1500
      feedbackTimer.restart()
    })
  }

  function togglePin() {
    if (!root.service || !root.selectedEntry) return
    var id = root.selectedEntry.id
    root.service.setPinned(id, root.prefs.pinned.indexOf(id) < 0)
  }

  function escapeQuery() {
    if (root.query !== "") root.query = ""
    else root.close()
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: Model.statusGlyph(root.status)
    active: root.status !== "READY" && root.status !== "LOADING"
    tooltipText: Model.statusText(root.status)
    onPressed: function() { root.toggle() }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: searchField
    contentWidth: panel.fittedContentWidth(Style.space(400))
    contentHeight: panel.fittedContentHeight(column.implicitHeight)

    Column {
      id: column
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      spacing: Style.space(10)

      PanelHero {
        width: parent.width
        title: "Proton Authenticator"
        meta: root.heroMeta
        detail: Model.heroBadge(root.privacy, root.service ? root.service.demo : false)
        foreground: root.foreground
        fontFamily: root.fontFamily
        iconComponent: Component {
          Text {
            textFormat: Text.PlainText
            text: Model.statusGlyph(root.status)
            color: root.status === "READY" || root.status === "LOADING" ? root.foreground : root.urgent
            font.family: root.fontFamily
            font.pixelSize: Style.font.display
          }
        }
      }

      PanelSeparator { foreground: root.foreground }

      SearchField {
        id: searchField
        width: parent.width
        foreground: root.foreground
        dim: root.dim
        font.family: root.fontFamily
        text: root.query
        countText: root.query === "" || root.entries.length === 0 ? ""
                   : root.filtered.length + " / " + root.entries.length
        onTextEdited: root.query = text
        onMoveRequested: function(delta) { root.move(delta) }
        onPageRequested: function(direction) { root.move(direction * 5) }
        onActivateRequested: root.activate()
        onEscapeRequested: root.escapeQuery()
        onPinRequested: root.togglePin()
        onPrivacyRequested: if (root.service) root.service.setPrivacy(!root.privacy)
        onTabRequested: function(direction) { root.switchPanel(direction) }
      }

      EmptyState {
        visible: root.emptyState !== null
        width: parent.width
        info: root.emptyState
        foreground: root.foreground
        dim: root.dim
        fontFamily: root.fontFamily
        onActionRequested: function(action) { root.runAction(action) }
      }

      ListView {
        id: list
        visible: root.filtered.length > 0
        width: parent.width
        height: visible ? Math.min(contentHeight, Style.space(54) * 7) : 0
        spacing: Style.space(2)
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height
        model: root.filtered
        currentIndex: root.selectedIndex
        highlightFollowsCurrentItem: false
        function keepSelectionInView() {
          if (root.selectedIndex >= 0) list.positionViewAtIndex(root.selectedIndex, ListView.Contain)
        }
        // Every reply replaces the model, which resets the scroll position.
        onCurrentIndexChanged: keepSelectionInView()
        onCountChanged: Qt.callLater(keepSelectionInView)
        onModelChanged: {
          pointerGate.reset()
          Qt.callLater(keepSelectionInView)
        }

        PointerMoveGate { id: pointerGate; referenceItem: list }

        delegate: EntryRow {
          required property var modelData
          required property int index
          width: ListView.view.width
          entry: modelData
          selected: index === root.selectedIndex
          masked: root.privacy && index !== root.selectedIndex
          pinned: root.prefs.pinned.indexOf(modelData.id) >= 0
          remaining: Model.liveRemaining(modelData, root.replyNow, root.nowSec)
          feedback: root.feedbackId === modelData.id ? root.feedbackText : ""
          foreground: root.foreground
          dim: root.dim
          urgentColor: root.urgent
          fontFamily: root.fontFamily
          onPointerMoved: function(row, mouse) {
            if (pointerGate.moved(row, mouse)) root.selectedId = modelData.id
          }
          onClicked: {
            root.selectedId = modelData.id
            root.useEntry(modelData)
          }
        }
      }

      PanelSeparator { foreground: root.foreground }

      PanelFooter {
        width: parent.width
        syncText: root.syncInfo.stale ? root.syncInfo.text : ""
        stale: root.syncInfo.stale
        privacy: root.privacy
        foreground: root.foreground
        dim: root.dim
        urgent: root.urgent
        fontFamily: root.fontFamily
        onSyncRequested: {
          if (!root.service) return
          root.service.openProton()
          root.service.refreshStatus()
        }
      }
    }
  }
}

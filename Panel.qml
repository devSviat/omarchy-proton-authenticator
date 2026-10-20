import QtQuick
import qs.Commons
import qs.Ui
import "Model.js" as Model

// Placeholder bar widget: the bar button and an empty panel wired to the
// service. The real panel UI replaces the panel contents.
Panel {
  id: root
  moduleName: "sviat.proton-authenticator"
  ipcTarget: "sviat.proton-authenticator"
  // Service.qml owns the "sviat.proton-authenticator" IPC target; the panel is
  // toggled with `omarchy-shell shell toggle sviat.proton-authenticator`.
  manageIpc: false

  readonly property var service: bar?.shell?.serviceFor("sviat.proton-authenticator")
  readonly property string status: service ? service.status : "LOADING"

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  onOpenedChanged: {
    if (!root.service) return
    if (root.opened) root.service.panelOpened(root)
    else root.service.panelClosed(root)
  }

  Component.onDestruction: if (root.service) root.service.panelClosed(root)

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
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(320))
    contentHeight: panel.fittedContentHeight(label.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
    }

    Text {
      id: label
      width: parent.width
      wrapMode: Text.WordWrap
      color: root.foreground
      font.family: root.fontFamily
      text: Model.statusText(root.status)
    }
  }
}

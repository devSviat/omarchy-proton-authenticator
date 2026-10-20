import QtQuick
import qs.Commons
import qs.Ui

Item {
  id: root

  property string syncText: ""
  property bool stale: false
  // Model.footerHints(): { full, compact }.
  property var hints: ({ full: "", compact: "" })
  property color foreground: "transparent"
  property color dim: foreground
  property color urgent: foreground
  property string fontFamily: Style.font.family

  signal syncRequested()

  implicitHeight: Math.max(left.implicitHeight, hint.implicitHeight)

  Row {
    id: left
    anchors.left: parent.left
    anchors.verticalCenter: parent.verticalCenter
    spacing: Style.space(6)

    Text {
      visible: root.syncText !== ""
      textFormat: Text.PlainText
      text: root.syncText + "  \u00b7"
      color: root.stale ? root.urgent : root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }

    Text {
      id: syncLink
      textFormat: Text.PlainText
      text: "Sync"
      color: syncMouse.containsMouse ? root.foreground : (root.stale ? root.urgent : root.dim)
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      font.underline: syncMouse.containsMouse

      MouseArea {
        id: syncMouse
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.syncRequested()
      }

      PanelToolTip {
        visible: syncMouse.containsMouse
        text: "Open Proton Authenticator so it syncs"
        fontFamily: root.fontFamily
      }
    }
  }

  TextMetrics {
    id: fullHint
    font: hint.font
    text: root.hints.full
  }

  Text {
    id: hint
    anchors.right: parent.right
    anchors.verticalCenter: parent.verticalCenter
    textFormat: Text.PlainText
    text: fullHint.advanceWidth <= root.width - left.implicitWidth - Style.space(12)
          ? root.hints.full : root.hints.compact
    color: root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
  }
}

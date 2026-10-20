import QtQuick
import qs.Commons
import qs.Ui

Item {
  id: root

  property string syncText: ""
  property bool stale: false
  property bool privacy: false
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
      text: root.syncText + "  ·"
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

  Text {
    id: hint
    anchors.right: parent.right
    anchors.verticalCenter: parent.verticalCenter
    textFormat: Text.PlainText
    text: (root.privacy ? "hidden · " : "") + "↵ copy"
    color: root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
  }
}

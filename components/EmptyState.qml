import QtQuick
import qs.Commons
import qs.Ui

Column {
  id: root

  // Model.emptyState(): { title, detail, action, actionLabel }.
  property var info: null
  property color foreground: "transparent"
  property color dim: foreground
  property string fontFamily: Style.font.family

  signal actionRequested(string action)

  spacing: Style.space(10)
  topPadding: Style.space(14)
  bottomPadding: Style.space(14)

  Text {
    width: parent.width
    textFormat: Text.PlainText
    horizontalAlignment: Text.AlignHCenter
    wrapMode: Text.WordWrap
    text: root.info ? root.info.title : ""
    color: root.foreground
    font.family: root.fontFamily
    font.pixelSize: Style.font.body
    font.bold: true
  }

  // Selectable, so the install command can be copied as shown.
  TextEdit {
    visible: text !== ""
    width: parent.width
    readOnly: true
    selectByMouse: true
    textFormat: TextEdit.PlainText
    horizontalAlignment: TextEdit.AlignHCenter
    wrapMode: TextEdit.WrapAnywhere
    text: root.info ? root.info.detail : ""
    color: root.dim
    selectionColor: Style.selectionFillFor(root.foreground, root.foreground)
    selectedTextColor: root.foreground
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  Button {
    visible: root.info !== null && root.info.action !== ""
    anchors.horizontalCenter: parent.horizontalCenter
    text: root.info ? root.info.actionLabel + "  ↵" : ""
    bordered: true
    foreground: root.foreground
    fontFamily: root.fontFamily
    fontSize: Style.font.bodySmall
    onClicked: root.actionRequested(root.info.action)
  }
}

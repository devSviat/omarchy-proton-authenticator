import QtQuick
import qs.Commons
import qs.Ui

Column {
  id: root

  // Model.emptyState(): { title, detail, action, actionLabel, command }.
  property var info: null
  // Replaces the action label briefly, e.g. "Copied ✓".
  property string feedback: ""
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

  // One line per detail line, never wrapped: a path must not break mid-word.
  Repeater {
    model: root.info && root.info.detail !== "" ? root.info.detail.split("\n") : []

    Text {
      required property string modelData
      width: root.width
      textFormat: Text.PlainText
      horizontalAlignment: Text.AlignHCenter
      elide: Text.ElideMiddle
      text: modelData
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
  }

  Button {
    visible: root.info !== null && root.info.action !== ""
    anchors.horizontalCenter: parent.horizontalCenter
    text: root.feedback !== "" ? root.feedback : (root.info ? root.info.actionLabel + "  \u21b5" : "")
    bordered: true
    foreground: root.foreground
    fontFamily: root.fontFamily
    fontSize: Style.font.bodySmall
    onClicked: root.actionRequested(root.info.action)
  }
}

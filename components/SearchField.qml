import QtQuick
import qs.Commons
import qs.Ui

// The panel's only focus target. Typing goes to the query; every action key
// is Enter, Esc, an arrow/page key or a Ctrl chord, so no letter is ever
// taken from the query.
TextField {
  id: root

  property string countText: ""
  property color dim: foreground

  signal moveRequested(int delta)
  signal pageRequested(int direction)
  signal activateRequested()
  signal escapeRequested()
  signal pinRequested()
  signal privacyRequested()
  signal tabRequested(int direction)

  placeholderText: "Search accounts"
  rightPadding: horizontalPadding + Border.right(root._borderSpec) + countLabel.implicitWidth + Style.space(8)

  Keys.onPressed: function(event) {
    var ctrl = (event.modifiers & Qt.ControlModifier) !== 0
    var handled = true
    if (event.key === Qt.Key_Escape) root.escapeRequested()
    else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) root.activateRequested()
    else if (event.key === Qt.Key_Down || (ctrl && event.key === Qt.Key_J)) root.moveRequested(1)
    else if (event.key === Qt.Key_Up || (ctrl && event.key === Qt.Key_K)) root.moveRequested(-1)
    else if (event.key === Qt.Key_PageDown) root.pageRequested(1)
    else if (event.key === Qt.Key_PageUp) root.pageRequested(-1)
    else if (ctrl && event.key === Qt.Key_P) root.pinRequested()
    else if (ctrl && event.key === Qt.Key_H) root.privacyRequested()
    else if (event.key === Qt.Key_Tab) root.tabRequested(1)
    else if (event.key === Qt.Key_Backtab) root.tabRequested(-1)
    else handled = false
    if (handled) event.accepted = true
  }

  Text {
    id: countLabel
    textFormat: Text.PlainText
    anchors.right: parent.right
    anchors.rightMargin: root.horizontalPadding
    anchors.verticalCenter: parent.verticalCenter
    text: root.countText
    color: root.dim
    font.family: root.font.family
    font.pixelSize: Style.font.caption
  }
}

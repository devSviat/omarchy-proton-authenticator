import QtQuick
import qs.Commons
import qs.Ui
import "../Model.js" as Model

// Labels come from the vault, so every Text here is PlainText.
CursorSurface {
  id: root

  property var entry: ({})
  property bool selected: false
  property bool pinned: false
  // Privacy mode: only the selected row may show a code, even while the
  // previous row's code is still loaded.
  property bool masked: false
  // Seconds left in the period, ticked locally; null while the code is hidden.
  property var remaining: null
  // "" or a short note shown in place of the code, e.g. "Copied ✓".
  property string feedback: ""
  property color urgentColor: foreground
  property color dim: foreground
  property string fontFamily: Style.font.family

  readonly property bool hidden: root.masked || Model.isHidden(root.entry)
  readonly property bool unsupported: root.entry.kind === "unsupported"
  readonly property bool urgent: !root.hidden && Model.isUrgent(root.remaining)
  readonly property bool showNext: root.selected && root.urgent && !!root.entry.nextCode
  readonly property color codeColor: root.urgent ? root.urgentColor : root.foreground

  signal clicked()

  hasCursor: root.selected
  implicitHeight: Math.max(badge.height, labels.implicitHeight, codeColumn.implicitHeight)
                  + Style.space(8) * 2

  BorderSurface {
    id: badge
    anchors.left: parent.left
    anchors.leftMargin: Style.space(8)
    anchors.verticalCenter: parent.verticalCenter
    width: Style.space(26)
    height: Style.space(26)
    radius: Style.cornerRadius
    color: Style.normalFillFor(root.foreground, root.foreground)
    borderSpec: Border.controlSpec("normal", root.foreground, root.foreground)

    Text {
      anchors.centerIn: parent
      textFormat: Text.PlainText
      text: Model.initial(root.entry)
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.body
      font.bold: true
    }
  }

  Column {
    id: labels
    anchors.left: badge.right
    anchors.leftMargin: Style.space(10)
    anchors.right: codeColumn.left
    anchors.rightMargin: Style.space(10)
    anchors.verticalCenter: parent.verticalCenter
    spacing: Style.space(2)

    Row {
      width: parent.width
      spacing: Style.space(6)

      Text {
        id: issuerText
        width: Math.min(implicitWidth, parent.width - (pinMark.visible ? pinMark.width + parent.spacing : 0))
        textFormat: Text.PlainText
        text: Model.issuerLabel(root.entry)
        elide: Text.ElideRight
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
      }

      Text {
        id: pinMark
        visible: root.pinned
        anchors.verticalCenter: issuerText.verticalCenter
        textFormat: Text.PlainText
        text: "\u{F0403}"
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
    }

    Text {
      width: parent.width
      visible: text !== ""
      textFormat: Text.PlainText
      text: String(root.entry.account || "")
      elide: Text.ElideMiddle
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  Column {
    id: codeColumn
    anchors.right: ring.left
    anchors.rightMargin: Style.space(10)
    anchors.verticalCenter: parent.verticalCenter

    Text {
      anchors.right: parent.right
      textFormat: Text.PlainText
      text: root.feedback !== "" ? root.feedback
            : root.unsupported ? "unsupported"
            : root.hidden ? Model.maskedCode()
            : Model.groupCode(root.entry.code)
      color: root.feedback !== "" ? root.foreground
             : (root.unsupported || root.hidden) ? root.dim
             : root.codeColor
      font.family: root.fontFamily
      font.pixelSize: (root.unsupported || root.feedback !== "") ? Style.font.body : Style.font.heading
      font.letterSpacing: (root.unsupported || root.feedback !== "") ? 0 : Style.space(2)
    }

    Text {
      anchors.right: parent.right
      visible: root.showNext && root.feedback === ""
      textFormat: Text.PlainText
      text: "next " + Model.groupCode(root.entry.nextCode)
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  CountdownRing {
    id: ring
    anchors.right: parent.right
    anchors.rightMargin: Style.space(8)
    anchors.verticalCenter: parent.verticalCenter
    opacity: root.hidden || root.unsupported ? 0 : 1
    progress: typeof root.remaining === "number" && root.entry.period > 0
              ? root.remaining / root.entry.period : 0
    color: root.codeColor
    trackColor: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
  }

  MouseArea {
    anchors.fill: parent
    cursorShape: Qt.PointingHandCursor
    onClicked: root.clicked()
  }
}

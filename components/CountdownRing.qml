import QtQuick
import qs.Commons

Canvas {
  id: root

  // 0..1 of the period still left.
  property real progress: 0
  property color color: "transparent"
  property color trackColor: "transparent"
  property real lineWidth: Math.max(2, Style.space(3))

  implicitWidth: Style.space(18)
  implicitHeight: Style.space(18)

  onProgressChanged: requestPaint()
  onColorChanged: requestPaint()
  onTrackColorChanged: requestPaint()
  onWidthChanged: requestPaint()
  onHeightChanged: requestPaint()

  onPaint: {
    var ctx = getContext("2d")
    ctx.reset()
    var r = Math.min(width, height) / 2 - root.lineWidth / 2
    if (r <= 0) return
    var cx = width / 2
    var cy = height / 2
    ctx.lineWidth = root.lineWidth
    ctx.strokeStyle = root.trackColor
    ctx.beginPath()
    ctx.arc(cx, cy, r, 0, Math.PI * 2)
    ctx.stroke()
    var p = Math.max(0, Math.min(1, root.progress))
    if (p <= 0) return
    ctx.strokeStyle = root.color
    ctx.beginPath()
    ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + p * Math.PI * 2)
    ctx.stroke()
  }
}

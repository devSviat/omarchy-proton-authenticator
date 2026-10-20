import QtQuick
import Quickshell
import qs.Ui
import "../Model.js" as Model

// Visual only: this file is instantiated twice over (the active strip and the
// hover fold-out) and again per monitor, so all state and every helper call
// live in the sviat.proton-authenticator service.
BarIndicator {
  id: root

  readonly property var service: bar?.shell?.serviceFor("sviat.proton-authenticator")
  readonly property string status: service ? service.status : "LOADING"

  // Always shown: the glyph is the status, and hiding it would also hide the
  // way into the panel.
  active: root.service !== null && root.service !== undefined

  activeText: Model.statusGlyph(root.status)
  inactiveText: Model.statusGlyph("")
  activeTooltipText: Model.statusText(root.status)
  inactiveTooltipText: "Proton Authenticator is not enabled"

  onPressed: function() {
    Quickshell.execDetached(["omarchy-shell", "shell", "toggle", "sviat.proton-authenticator"])
  }
}

import QtQuick
import Quickshell.Io
import "Model.js" as Model

// Runs pa-helper and hands each call exactly one parsed reply.
//
// Replies carry account labels and codes, so nothing here ever logs them.
// The reply line (or EOF) completes a call, never process exit. `copy`
// exits right after replying; a detached holder keeps the clipboard.
Item {
  id: root

  // Absolute path inside the plugin directory, never a PATH lookup.
  required property string helperPath

  // Backstops above the helper's own watchdog (10 s, 120 s for the unlock
  // prompt), for a helper that hangs before its watchdog is armed.
  property int timeoutMs: 15000
  property int promptTimeoutMs: 125000

  property var slots: []

  function call(args, stdinText, onReply) {
    var slot = null
    for (var i = 0; i < root.slots.length; i++) {
      if (!root.slots[i].busy) { slot = root.slots[i]; break }
    }
    if (slot === null) {
      slot = slotComponent.createObject(root)
      root.slots = root.slots.concat([slot])
    }
    var prompt = args.indexOf("--allow-prompt") >= 0
    slot.begin([root.helperPath].concat(args), String(stdinText || ""),
               onReply, prompt ? root.promptTimeoutMs : root.timeoutMs)
  }

  Component {
    id: slotComponent

    Process {
      id: proc

      property bool busy: false
      property bool delivered: true
      property bool started: false
      property string buffer: ""
      property string pendingStdin: ""
      property var onReply: null

      function begin(cmd, stdinText, callback, timeout) {
        proc.busy = true
        proc.delivered = false
        proc.started = false
        proc.buffer = ""
        proc.pendingStdin = stdinText
        proc.onReply = callback
        proc.command = cmd
        proc.stdinEnabled = stdinText !== ""
        backstop.interval = timeout
        backstop.restart()
        proc.running = true
      }

      function deliver(reply) {
        if (proc.delivered) return
        proc.delivered = true
        proc.buffer = ""
        backstop.stop()
        var callback = proc.onReply
        proc.onReply = null
        if (typeof callback === "function") callback(reply)
      }

      function settle() {
        if (proc.running) return
        if (!proc.started) proc.deliver(Model.failure("HELPER_MISSING"))
        else proc.deliver(Model.parseReply(proc.buffer))
        proc.busy = false
      }

      onStarted: {
        proc.started = true
        if (proc.pendingStdin !== "") {
          proc.write(proc.pendingStdin)
          proc.pendingStdin = ""
          proc.stdinEnabled = false
        }
      }

      onExited: proc.settle()
      onRunningChanged: proc.settle()

      stdout: SplitParser {
        splitMarker: ""
        onRead: function(data) {
          if (proc.delivered) return
          proc.buffer += data
          var line = Model.replyLine(proc.buffer)
          if (line !== null) {
            proc.deliver(Model.parseReply(line))
          } else if (proc.buffer.length > Model.MAX_REPLY_CHARS) {
            proc.deliver(Model.failure("OUTPUT_TOO_LARGE"))
            proc.running = false
          }
        }
      }

      property Timer backstop: Timer {
        repeat: false
        onTriggered: {
          if (proc.delivered) return
          proc.deliver(Model.failure("TIMEOUT"))
          proc.running = false
        }
      }
    }
  }
}

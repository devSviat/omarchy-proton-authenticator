import { readFileSync } from "node:fs"
import vm from "node:vm"

// Model.js is a QML `.pragma library` script, not an ES module: drop the
// pragma and evaluate it in a fresh context, then read its globals back.
export function loadModel() {
  const url = new URL("../Model.js", import.meta.url)
  const source = readFileSync(url, "utf8").replace(/^\.pragma library\s*$/m, "")
  const context = vm.createContext({})
  vm.runInContext(source, context, { filename: url.pathname })
  return context
}

// Copies the 4:3 SVG flags from flag-icons (MIT, Panayiotis Lipiridis) into
// public/flags so the panel serves them itself; nothing loads from a CDN.
import { copyFile, mkdir, readdir } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const source = path.join(root, "node_modules", "flag-icons", "flags", "4x3")
const target = path.join(root, "public", "flags")

await mkdir(target, { recursive: true })
let n = 0
for (const name of await readdir(source)) {
  if (/^[a-z]{2}\.svg$/.test(name)) {
    await copyFile(path.join(source, name), path.join(target, name))
    n++
  }
}
await copyFile(path.join(root, "node_modules", "flag-icons", "LICENSE"), path.join(target, "LICENSE.txt"))
console.log(`Bayraklar kopyalandı: ${n}`)

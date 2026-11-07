// Copies the static export (out/) into the Go embed directory so that
// `go build` bundles the panel into the openscale binary.
import { cp, mkdir, readdir, rm, stat } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const source = path.join(root, "out")
const target = path.resolve(root, "..", "internal", "panel", "web", "dist")

const info = await stat(source).catch(() => null)
if (!info?.isDirectory()) {
  console.error("out/ bulunamadı; önce 'next build' çalışmalı.")
  process.exit(1)
}

await mkdir(target, { recursive: true })
for (const entry of await readdir(target)) {
  if (entry !== ".gitkeep") {
    await rm(path.join(target, entry), { recursive: true, force: true })
  }
}
await cp(source, target, { recursive: true })
console.log(`Panel derlemesi kopyalandı: ${path.relative(path.resolve(root, ".."), target)}`)

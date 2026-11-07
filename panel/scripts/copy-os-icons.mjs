// Copies the operating system logos the panel shows from simple-icons
// (CC0-1.0, Simple Icons Collaborators) into public/os so the panel serves
// them itself; nothing loads from a CDN. Only the listed icons are copied.
// simple-icons has no Windows logo (removed at Microsoft's request), so
// Windows uses a generic icon in components/os-icon.tsx.
import { copyFile, mkdir, readdir, rm } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const pkg = path.join(root, "node_modules", "simple-icons")
const source = path.join(pkg, "icons")
const target = path.join(root, "public", "os")

// Keep in step with the map in components/os-icon.tsx.
const icons = [
  "linux",
  "debian",
  "ubuntu",
  "fedora",
  "archlinux",
  "alpinelinux",
  "linuxmint",
  "raspberrypi",
  "redhat",
  "centos",
  "opensuse",
  "apple",
  "macos",
  "ios",
  "android",
  "freebsd",
  "openbsd",
  "docker",
]

await mkdir(target, { recursive: true })
// Drop icons an earlier build copied but the list no longer names.
const wanted = new Set([...icons.map((n) => `${n}.svg`), "LICENSE.txt"])
for (const name of await readdir(target)) {
  if (!wanted.has(name)) await rm(path.join(target, name), { force: true })
}
for (const name of icons) {
  try {
    await copyFile(path.join(source, `${name}.svg`), path.join(target, `${name}.svg`))
  } catch (err) {
    console.error(`simple-icons içinde ${name}.svg bulunamadı: ${err instanceof Error ? err.message : String(err)}`)
    process.exit(1)
  }
}
await copyFile(path.join(pkg, "LICENSE.md"), path.join(target, "LICENSE.txt"))
console.log(`İşletim sistemi simgeleri kopyalandı: ${icons.length}`)

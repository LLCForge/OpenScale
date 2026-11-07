// Bundles the user-facing Markdown documents into public/yardim/docs.json
// at build time (#237). The panel's Help page and `openscale docs` read this
// file from the binary, so the documentation works without internet.
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

const panelRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const repo = path.resolve(panelRoot, "..")
const target = path.join(panelRoot, "public", "yardim", "docs.json")

// Allowlist: only documents meant for the owner. Planning notes and the
// competitor analysis stay out of the binary.
const fixed = [
  { source: "README.tr.md", slug: "genel-bakis", group: "Başlarken" },
  { source: "docs/sunucu-kurulumu.md", group: "Başlarken" },
  { source: "docs/hazir-imaj.md", group: "Başlarken" },
  { source: "docs/kaynaktan-derleme.md", group: "Başlarken" },
  { source: "docs/sorun-giderme.md", group: "Başlarken" },
  { source: "docs/rehberler/senaryo-aile-destegi.md", group: "Senaryo rehberleri" },
  { source: "docs/rehberler/senaryo-ev-sunucusu.md", group: "Senaryo rehberleri" },
  { source: "docs/rehberler/senaryo-otel-interneti.md", group: "Senaryo rehberleri" },
  { source: "docs/rehberler/senaryo-ofis-yazici.md", group: "Senaryo rehberleri" },
  { source: "SECURITY.md", slug: "guvenlik-politikasi", group: "Güvenlik" },
  { source: "docs/surum-dogrulama.md", group: "Güvenlik" },
  { source: "docs/sertlestirme-kontrol-listesi.md", group: "Güvenlik" },
  { source: "docs/konteyner.md", group: "Platformlar" },
  { source: "docs/kubernetes.md", group: "Platformlar" },
  { source: "docs/nas.md", group: "Platformlar" },
  { source: "docs/bsd.md", group: "Platformlar" },
  { source: "docs/platform-destegi.md", group: "Platformlar" },
  { source: "docs/openwrt.md", group: "Platformlar" },
  { source: "docs/tasinabilir-kip.md", group: "Platformlar" },
  { source: "docs/mimari.md", group: "Mimari" },
  { source: "docs/yol-haritasi.md", group: "Mimari" },
  { source: "docs/adr/README.md", slug: "adr-dizini", group: "Karar kayıtları (ADR)" },
]

const MAX_DOC = 256 * 1024

function slugOf(source) {
  const base = path.basename(source, ".md").toLowerCase()
  return source.startsWith("docs/adr/") ? `adr-${base}` : base
}

function titleOf(body, fallback) {
  const m = /^#\s+(.+)$/m.exec(body)
  return m ? m[1].trim() : fallback
}

// The long-form documents may be absent from a checkout; the panel then
// ships only the documents that exist.
let adrNames = []
try {
  adrNames = (await readdir(path.join(repo, "docs", "adr"))).filter((n) => /^\d{4}-.+\.md$/.test(n)).sort()
} catch {
  console.warn("docs/adr yok; karar kayıtları atlandı")
}
const entries = [
  ...fixed,
  ...adrNames.map((n) => ({ source: `docs/adr/${n}`, group: "Karar kayıtları (ADR)" })),
]

const docs = []
for (const e of entries) {
  let body
  try {
    body = await readFile(path.join(repo, e.source), "utf8")
    // Badge images point at an outside host; the embedded copy drops them.
    body = body.split("\n").filter((line) => !line.includes("img.shields.io")).join("\n")
  } catch {
    console.warn(`Belge bulunamadı, atlandı: ${e.source}`)
    continue
  }
  if (body.length > MAX_DOC) {
    console.warn(`Belge çok büyük, atlandı: ${e.source}`)
    continue
  }
  body = body.replace(/\r\n/g, "\n")
  const slug = e.slug ?? slugOf(e.source)
  docs.push({ slug, title: titleOf(body, slug), group: e.group, source: e.source, body })
}

await mkdir(path.dirname(target), { recursive: true })
await writeFile(target, JSON.stringify({ schema: 1, docs }) + "\n", "utf8")
console.log(`Çevrimdışı belgeler yazıldı: ${docs.length} belge`)

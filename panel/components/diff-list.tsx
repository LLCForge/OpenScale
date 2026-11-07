import { Fragment } from "react"
import { ArrowRight } from "lucide-react"

import { msg, useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

type Kind = "add" | "remove" | "change" | "plain"

interface ParsedLine {
  kind: Kind
  /** Line text without its "+ ", "- " or "~ " marker. */
  text: string
  /** A sub-line of the device above it (server indents these). */
  nested: boolean
  /** The "Sürüm 3 -> 4" header line. */
  version: boolean
}

const kindLabel: Record<Kind, string> = {
  add: msg("Eklenir:"),
  remove: msg("Kaldırılır:"),
  change: msg("Değişir:"),
  plain: "",
}

const marker: Record<Kind, string> = { add: "+", remove: "−", change: "~", plain: "" }

const ARROW = " -> "

function parse(line: string): ParsedLine {
  const nested = /^\s{2,}/.test(line)
  const trimmed = line.trimStart()
  const head = trimmed.slice(0, 2)
  const kind: Kind = head === "+ " ? "add" : head === "- " ? "remove" : head === "~ " ? "change" : "plain"
  const text = kind === "plain" ? trimmed : trimmed.slice(2)
  return { kind, text, nested, version: kind === "plain" && !nested && /^Sürüm \d+ -> \d+$/.test(text) }
}

/**
 * A plain "Ad: a -> a" line whose old and new values are the same; the
 * server lists such lines (a draft re-signed at the same version, for
 * example) but they carry no change for the reader.
 */
function unchanged(p: ParsedLine): boolean {
  if (p.kind !== "plain") return false
  const parts = p.text.split(ARROW)
  if (parts.length !== 2) return false
  const [left, right] = parts
  return right !== "" && (left === right || left.endsWith(` ${right}`))
}

/**
 * Number of rules the diff deletes outright. A rule that only loses one
 * device shows as a "- kural" plus a "+ kural" line, so those pairs are
 * not counted.
 */
export function removedRuleCount(lines: string[]): number {
  const removed = lines.filter((l) => l.startsWith("- kural ")).length
  const added = lines.filter((l) => l.startsWith("+ kural ")).length
  return Math.max(0, removed - added)
}

type Translate = ReturnType<typeof useI18n>

/** A rule as the server writes it, with its "reddet: " and " (kapalı)" marks translated. */
function ruleText(rule: string, { t }: Translate): string {
  let s = rule
  // i18n-ignore: sunucunun kural metni biçimiyle eşleşme
  const denyMark = "reddet: "
  // i18n-ignore: sunucunun kural metni biçimiyle eşleşme
  const offMark = " (kapalı)"
  const deny = s.startsWith(denyMark)
  if (deny) s = s.slice(denyMark.length)
  const off = s.endsWith(offMark)
  if (off) s = s.slice(0, -offMark.length)
  if (off) s = t("{rule} (kapalı)", { rule: s })
  if (deny) s = t("reddet: {rule}", { rule: s })
  return s
}

/**
 * A diff line's text in the interface language. The server writes the
 * device, rule and group lines in a fixed form ("cihaz x", "kural a -> b
 * tcp/22"); everything else is looked up as a server text.
 */
function lineText(p: ParsedLine, tr: Translate): string {
  const { t, ts } = tr
  const text = p.text
  if (p.version) {
    const m = /^Sürüm (\d+) -> (\d+)$/.exec(text)
    if (m) return t("Sürüm {from} -> {to}", { from: m[1], to: m[2] })
  }
  if (p.kind !== "plain" && !p.nested) {
    // i18n-ignore: sunucunun fark satırı biçimiyle eşleşme
    const device = "cihaz "
    // i18n-ignore: sunucunun fark satırı biçimiyle eşleşme
    const revoked = " (iptal)"
    // i18n-ignore: sunucunun fark satırı biçimiyle eşleşme
    const rule = "kural "
    // i18n-ignore: sunucunun fark satırı biçimiyle eşleşme
    const group = "grup "
    if (text.startsWith(device)) {
      const name = text.slice(device.length)
      return name.endsWith(revoked) ? t("cihaz {name} (iptal)", { name: name.slice(0, -revoked.length) }) : t("cihaz {name}", { name })
    }
    if (text.startsWith(rule)) return t("kural {rule}", { rule: ruleText(text.slice(rule.length), tr) })
    if (text.startsWith(group)) return t("grup {group}", { group: text.slice(group.length) })
  }
  return ts(text)
}

/** "a -> b" drawn with an arrow icon; screen readers hear "a, sonra b". */
function Arrows({ text }: { text: string }) {
  const { t } = useI18n()
  const parts = text.split(ARROW)
  return (
    <>
      {parts.map((part, i) => (
        <Fragment key={`${i}-${part}`}>
          {i > 0 ? (
            <>
              <ArrowRight aria-hidden="true" className="mx-1 inline size-3.5 -translate-y-px align-middle text-muted-foreground" />
              <span className="sr-only">{`, ${t("sonra")} `}</span>
            </>
          ) : null}
          {part}
        </Fragment>
      ))}
    </>
  )
}

/**
 * Shows the Turkish diff lines produced by the server before signing.
 * Lines that change nothing are hidden and counted; arrows are drawn as
 * icons instead of the raw "->". `bare` drops the frame, for lists whose
 * rows are already separated by lines.
 */
export function DiffList({ lines, bare = false }: { lines: string[]; bare?: boolean }) {
  const tr = useI18n()
  const { t } = tr
  const parsed = lines.map(parse)
  const shown = parsed.filter((p) => !unchanged(p))
  const hidden = parsed.length - shown.length
  const body = shown.filter((p) => !p.version)
  const version = shown.find((p) => p.version)

  return (
    <div className={cn("flex flex-col gap-2 font-mono text-[0.8125rem] leading-relaxed", !bare && "rounded-lg border bg-muted/40 p-3")}>
      {version ? (
        <p className="text-muted-foreground">
          <Arrows text={lineText(version, tr)} />
        </p>
      ) : null}
      {body.length === 0 ? (
        <p className="font-sans text-sm text-muted-foreground">{t("Ağ belgesinde değişen bir şey yok.")}</p>
      ) : (
        <ul className="flex flex-col gap-1">
          {body.map((p, i) => (
            <li
              key={`${i}-${p.text}`}
              className={cn(
                "grid grid-cols-[1ch_minmax(0,1fr)] gap-x-2 break-words",
                p.nested && "pl-4 text-muted-foreground",
                p.kind === "add" && "text-success",
                p.kind === "remove" && "text-destructive",
                p.kind === "change" && "text-warning-foreground dark:text-warning"
              )}
            >
              <span aria-hidden="true" className="select-none">
                {marker[p.kind]}
              </span>
              <span className="min-w-0 whitespace-pre-wrap">
                {p.kind !== "plain" ? <span className="sr-only">{`${t(kindLabel[p.kind])} `}</span> : null}
                <Arrows text={lineText(p, tr)} />
              </span>
            </li>
          ))}
        </ul>
      )}
      {hidden > 0 ? (
        <p className="font-sans text-sm text-muted-foreground">
          {t("Değişmeyen {count} satır gizlendi.", { count: hidden })}
        </p>
      ) : null}
    </div>
  )
}

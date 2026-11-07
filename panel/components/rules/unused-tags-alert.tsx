import { TriangleAlert } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { useI18n } from "@/lib/i18n/i18n"
import type { Rule } from "@/lib/types"

/**
 * Tags referenced by rules, groups or exit users that no device carries.
 * Such a reference matches nothing; on a deny rule it is most likely a typo
 * that leaves the intended traffic allowed.
 */
export function UnusedTagsAlert({ unusedTags, rules }: { unusedTags: string[]; rules: Rule[] }) {
  const { t } = useI18n()
  if (unusedTags.length === 0) return null
  return (
    <Alert>
      <TriangleAlert />
      <AlertTitle>{t("Eşleşmeyen etiketler")}</AlertTitle>
      <AlertDescription>
        <ul className="flex flex-col gap-1">
          {unusedTags.map((tag) => {
            const ref = `tag:${tag}`
            const denying = rules.some((r) => r.action === "deny" && !r.disabled && (r.from.includes(ref) || r.to.includes(ref)))
            return (
              <li key={tag} className="text-pretty">
                {withNode(t("{tag} hiçbir cihazda yok; bu başvuru hiçbir şeyle eşleşmez."), "tag", <span className="font-mono text-[0.8125rem]">{ref}</span>)}
                {denying ? (
                  <strong className="font-medium text-foreground">
                    {" "}
                    {t("Bir reddet kuralında kullanılıyor: yazım hatası olabilir ve engellemek istediğin trafik engellenmiyor olabilir.")}
                  </strong>
                ) : null}
              </li>
            )
          })}
        </ul>
      </AlertDescription>
    </Alert>
  )
}

/** Puts a node where the translated text has its {name} placeholder. */
function withNode(text: string, name: string, node: React.ReactNode): React.ReactNode {
  const mark = `{${name}}`
  const at = text.indexOf(mark)
  if (at < 0) return text
  return (
    <>
      {text.slice(0, at)}
      {node}
      {text.slice(at + mark.length)}
    </>
  )
}

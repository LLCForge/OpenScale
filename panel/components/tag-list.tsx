import { Tag } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { useI18n } from "@/lib/i18n/i18n"
import { cn } from "@/lib/utils"

interface TagListProps {
  tags: string[]
  /** Tags carried by no device; shown in the destructive style. */
  unused?: string[]
  empty?: string
  className?: string
}

/** Device and invite tags as small badges ("tag:x"). */
export function TagList({ tags, unused = [], empty, className }: TagListProps) {
  const { t } = useI18n()
  if (tags.length === 0) {
    return empty ? <span className="text-sm text-muted-foreground">{t(empty)}</span> : null
  }
  return (
    <ul aria-label={t("Etiketler")} className={cn("flex flex-wrap gap-1", className)}>
      {tags.map((tag) => (
        <li key={tag}>
          <Badge variant={unused.includes(tag) ? "destructive" : "outline"} className="font-mono">
            <Tag data-icon="inline-start" />
            {tag}
          </Badge>
        </li>
      ))}
    </ul>
  )
}

"use client"

import { useState } from "react"

import { Button } from "@/components/ui/button"
import { Field, FieldContent, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Textarea } from "@/components/ui/textarea"
import { useI18n } from "@/lib/i18n/i18n"

interface RDeskFileRootsProps {
  roots: string[]
  disabled: boolean
  onSave: (roots: string[]) => Promise<boolean>
}

const maxRoots = 8

/** Folders of the session file browser (ADR-0146 #435); empty turns it off. */
export function RDeskFileRoots({ roots, disabled, onSave }: RDeskFileRootsProps) {
  const { t } = useI18n()
  const current = roots.join("\n")
  const [draft, setDraft] = useState<string | null>(null)
  const value = draft ?? current
  const list = value
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "")
  const changed = draft !== null && list.join("\n") !== current

  return (
    <Field>
      <FieldContent>
        <FieldLabel htmlFor="rdesk-file-roots">{t("Oturumdan dosya gezgini klasörleri")}</FieldLabel>
        <FieldDescription>
          {t(
            "Her satıra bir mutlak klasör yolu (en fazla {max}). Kontrol izni ve files kuralı olan bir oturum yalnızca bu klasörlere göz atıp dosya çekebilir. Boş bırakılırsa kapalıdır.",
            { max: maxRoots }
          )}
        </FieldDescription>
      </FieldContent>
      <Textarea
        id="rdesk-file-roots"
        className="font-mono text-sm"
        rows={3}
        maxLength={8192}
        spellCheck={false}
        value={value}
        disabled={disabled}
        onChange={(e) => setDraft(e.target.value)}
      />
      <div className="flex gap-2">
        <Button
          size="sm"
          disabled={disabled || !changed || list.length > maxRoots}
          onClick={async () => {
            if (await onSave(list)) setDraft(null)
          }}
        >
          {t("Klasörleri kaydet")}
        </Button>
        {changed && (
          <Button size="sm" variant="ghost" disabled={disabled} onClick={() => setDraft(null)}>
            {t("Vazgeç")}
          </Button>
        )}
      </div>
    </Field>
  )
}

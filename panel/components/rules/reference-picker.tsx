"use client"

import { useId, useState } from "react"
import { Plus } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldDescription, FieldError, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { useI18n } from "@/lib/i18n/i18n"
import { isLabel, LABEL_MESSAGE, referenceKind } from "@/lib/references"
import { cn } from "@/lib/utils"

/** What a rule, group or exit user list may refer to. */
export interface ReferenceChoices {
  devices: string[]
  /** Tag names without the "tag:" prefix. */
  tags: string[]
  /** Group names without the "group:" prefix. */
  groups: string[]
}

interface ReferencePickerProps {
  legend: string
  choices: ReferenceChoices
  value: string[]
  onChange: (value: string[]) => void
  /** Offer "Tüm cihazlar" ("*"). */
  allowAll?: boolean
  /** Offer group:x entries. */
  allowGroups?: boolean
  max: number
  error?: string
  description?: string
}

/**
 * Checkbox picker for devices, tag:x and group:x references. A tag no
 * device carries yet can be typed in; it matches nothing until one does.
 */
export function ReferencePicker({
  legend,
  choices,
  value,
  onChange,
  allowAll = false,
  allowGroups = false,
  max,
  error,
  description,
}: ReferencePickerProps) {
  const { t } = useI18n()
  const id = useId()
  const [extraTag, setExtraTag] = useState("")
  const [extraError, setExtraError] = useState<string | null>(null)
  const all = allowAll && value.includes("*")

  // Entries already selected but no longer offered (a removed device, a tag
  // no device carries) stay visible so they can be unticked.
  const groups = allowGroups ? union(choices.groups.map((g) => `group:${g}`), value.filter((v) => referenceKind(v) === "group")) : []
  const tags = union(choices.tags.map((t) => `tag:${t}`), value.filter((v) => referenceKind(v) === "tag"))
  const devices = union(choices.devices, value.filter((v) => referenceKind(v) === "device"))

  function toggle(ref: string, checked: boolean) {
    if (ref === "*") {
      onChange(checked ? ["*"] : [])
      return
    }
    const rest = value.filter((v) => v !== "*" && v !== ref)
    onChange(checked ? [...rest, ref] : rest)
  }

  function addTag() {
    const name = extraTag.trim().replace(/^tag:/, "")
    if (!isLabel(name)) {
      setExtraError(LABEL_MESSAGE)
      return
    }
    setExtraError(null)
    setExtraTag("")
    if (!value.includes(`tag:${name}`)) toggle(`tag:${name}`, true)
  }

  return (
    <FieldSet data-invalid={error ? true : undefined}>
      <FieldLegend variant="label">{t(legend)}</FieldLegend>
      <div className="flex flex-col gap-3 rounded-lg border p-3">
        {allowAll ? <CheckRow id={`${id}-all`} label={t("Tüm cihazlar")} checked={all} onCheckedChange={(c) => toggle("*", c)} /> : null}
        <div className={cn("flex flex-col gap-3", all && "opacity-50")}>
          {groups.length > 0 ? (
            <Section title={t("Gruplar")}>
              {groups.map((g) => (
                <CheckRow key={g} id={`${id}-${g}`} label={g} mono disabled={all} checked={value.includes(g)} onCheckedChange={(c) => toggle(g, c)} />
              ))}
            </Section>
          ) : null}
          {tags.length > 0 ? (
            <Section title={t("Etiketler")}>
              {tags.map((tag) => (
                <CheckRow key={tag} id={`${id}-${tag}`} label={tag} mono disabled={all} checked={value.includes(tag)} onCheckedChange={(c) => toggle(tag, c)} />
              ))}
            </Section>
          ) : null}
          <Section title={t("Cihazlar")}>
            {devices.length === 0 ? <span className="text-sm text-muted-foreground">{t("Cihaz yok")}</span> : null}
            {devices.map((d) => (
              <CheckRow key={d} id={`${id}-dev-${d}`} label={d} mono disabled={all} checked={value.includes(d)} onCheckedChange={(c) => toggle(d, c)} />
            ))}
          </Section>
          <Field data-invalid={extraError ? true : undefined} data-disabled={all ? true : undefined}>
            <FieldLabel htmlFor={`${id}-extra`} className="text-sm font-normal text-muted-foreground">
              {t("Henüz hiçbir cihazda olmayan bir etiket ekle")}
            </FieldLabel>
            <div className="flex gap-2">
              <Input
                id={`${id}-extra`}
                value={extraTag}
                disabled={all}
                placeholder={t("tag:sunucu")}
                autoComplete="off"
                spellCheck={false}
                className="font-mono"
                aria-invalid={extraError ? true : undefined}
                onChange={(e) => setExtraTag(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault()
                    addTag()
                  }
                }}
              />
              <Button type="button" variant="outline" disabled={all || extraTag.trim() === ""} onClick={addTag}>
                <Plus data-icon="inline-start" />
                {t("Ekle")}
              </Button>
            </div>
            {extraError ? <FieldError>{extraError}</FieldError> : null}
          </Field>
        </div>
      </div>
      {error ? (
        <FieldError>{error}</FieldError>
      ) : (
        <FieldDescription>
          {description ? t(description) : t("Birden fazla seçebilirsin.")} {t("Seçili: {count}/{max}.", { count: value.length, max })}
        </FieldDescription>
      )}
    </FieldSet>
  )
}

function union(a: string[], b: string[]): string[] {
  return Array.from(new Set([...a, ...b]))
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      <span className="text-xs font-medium text-muted-foreground">{title}</span>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">{children}</div>
    </div>
  )
}

interface CheckRowProps {
  id: string
  label: string
  checked: boolean
  disabled?: boolean
  mono?: boolean
  onCheckedChange: (checked: boolean) => void
}

function CheckRow({ id, label, checked, disabled, mono, onCheckedChange }: CheckRowProps) {
  return (
    <Field orientation="horizontal" data-disabled={disabled ? true : undefined}>
      <Checkbox id={id} checked={checked} disabled={disabled} onCheckedChange={(c) => onCheckedChange(c === true)} />
      <FieldLabel htmlFor={id} className={cn("font-normal break-all", mono && "font-mono text-[0.8125rem]")}>
        {label}
      </FieldLabel>
    </Field>
  )
}

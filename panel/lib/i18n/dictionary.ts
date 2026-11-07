// The English dictionary, merged from the area files. Every file is keyed
// by the Turkish source text; tools/i18ncheck makes sure a key has a single
// English text across files, placeholders match and no text is missing.

import { enAppsSync } from "@/lib/i18n/en/apps-sync"
import { enAuthSettings } from "@/lib/i18n/en/auth-settings"
import { enCommon } from "@/lib/i18n/en/common"
import { enDevices } from "@/lib/i18n/en/devices"
import { enDevicesDetail } from "@/lib/i18n/en/devices-detail"
import { enDiag } from "@/lib/i18n/en/diag"
import { enErrcodes } from "@/lib/i18n/en/errcodes"
import { enF3Desktop } from "@/lib/i18n/en/f3-desktop"
import { enLibUi } from "@/lib/i18n/en/lib-ui"
import { enNetworkDiag } from "@/lib/i18n/en/network-diag"
import { enObservability } from "@/lib/i18n/en/observability"
import { enOnboarding } from "@/lib/i18n/en/onboarding"
import { enRules } from "@/lib/i18n/en/rules"
import { enSecurity } from "@/lib/i18n/en/security"
import { enServer } from "@/lib/i18n/en/server"
import { enShell } from "@/lib/i18n/en/shell"
import { enSupportF4A } from "@/lib/i18n/en/support-f4a"
import { enUpdateRings } from "@/lib/i18n/en/update-rings"
import { en as enCore } from "@/lib/i18n/messages-en"

export const en: Record<string, string> = {
  ...enCommon,
  ...enCore,
  ...enShell,
  ...enLibUi,
  ...enDevices,
  ...enDevicesDetail,
  ...enOnboarding,
  ...enRules,
  ...enSecurity,
  ...enAuthSettings,
  ...enNetworkDiag,
  ...enDiag,
  ...enObservability,
  ...enAppsSync,
  ...enF3Desktop,
  ...enSupportF4A,
  ...enUpdateRings,
  ...enServer,
  ...enErrcodes,
}

export interface ServerPattern {
  re: RegExp
  names: string[]
  en: string
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

/**
 * Server texts with a variable part ("Cihaz {name} bulunamadı.") as
 * anchored patterns, longest first so the most specific wins.
 */
export const serverPatterns: ServerPattern[] = Object.entries({ ...enServer, ...enErrcodes })
  .filter(([key]) => /\{\w+\}/.test(key))
  .sort((a, b) => b[0].length - a[0].length)
  .map(([key, value]) => {
    const names: string[] = []
    const source = key
      .split(/(\{\w+\})/)
      .map((part) => {
        const m = /^\{(\w+)\}$/.exec(part)
        if (m) {
          names.push(m[1])
          return "([\\s\\S]+?)"
        }
        return escapeRe(part)
      })
      .join("")
    return { re: new RegExp(`^${source}$`), names, en: value }
  })

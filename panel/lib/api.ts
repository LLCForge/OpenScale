// Client for the openscale panel API. The API is served by the same Go
// process on loopback; every state-changing request carries the CSRF token
// and the browser adds the Origin header the server checks.

import { errorCodeTitlesEn } from "@/lib/i18n/error-codes-en"
import { getLocale, msg, translateServer, tx } from "@/lib/i18n/i18n"

export class ApiError extends Error {
  readonly status: number
  /** Stable error code such as "OS-3001" (ADR-0165); absent when the server gave none. */
  readonly code?: string

  constructor(message: string, status: number, code?: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.code = code
  }
}

const errorCodePattern = /^OS-\d{4}$/

let csrfToken: string | null = null

async function readError(res: Response): Promise<ApiError> {
  let message: string = msg("Beklenmeyen bir hata oluştu.")
  let code: string | undefined
  try {
    const data: unknown = await res.json()
    if (data && typeof data === "object") {
      if ("error" in data && typeof data.error === "string") message = data.error
      // Only a well-formed code is kept; it ends up in a URL path.
      if ("code" in data && typeof data.code === "string" && errorCodePattern.test(data.code)) code = data.code
    }
  } catch {
    // Body was not JSON; keep the generic message.
  }
  return new ApiError(message, res.status, code)
}

/** SWR fetcher for GET endpoints. */
export async function fetcher<T>(path: string): Promise<T> {
  const res = await fetch(path, { credentials: "same-origin", cache: "no-store" })
  if (!res.ok) {
    throw await readError(res)
  }
  return (await res.json()) as T
}

async function getCsrfToken(refresh = false): Promise<string> {
  if (csrfToken && !refresh) {
    return csrfToken
  }
  const data = await fetcher<{ csrfToken: string }>("/api/session")
  csrfToken = data.csrfToken
  return csrfToken
}

async function send(path: string, body: unknown, retry: boolean): Promise<Response> {
  const token = await getCsrfToken(!retry)
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
    body: JSON.stringify(body),
  })
  if (res.status === 403 && retry) {
    // The token may be stale after a server restart; fetch a new one once.
    return send(path, body, false)
  }
  return res
}

/** POST JSON and decode the JSON response. */
export async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await send(path, body, true)
  if (!res.ok) {
    throw await readError(res)
  }
  return (await res.json()) as T
}

/** POST JSON and return the response body as a Blob (file downloads). */
export async function postForBlob(path: string, body: unknown): Promise<{ blob: Blob; filename: string }> {
  const res = await send(path, body, true)
  if (!res.ok) {
    throw await readError(res)
  }
  const disposition = res.headers.get("Content-Disposition") ?? ""
  const match = /filename="([^"]+)"/.exec(disposition)
  // i18n-ignore: yedek dosyasının adı; sunucu normalde Content-Disposition ile verir
  return { blob: await res.blob(), filename: match?.[1] ?? "openscale-yedek.key" }
}

/**
 * The message of an error in the interface language. Server messages are
 * Turkish; in English the dictionary's server texts are tried, then the
 * title of the error's stable code, and only then the Turkish text.
 */
export function errorMessage(err: unknown): string {
  const locale = getLocale()
  if (err instanceof ApiError) {
    const translated = translateServer(locale, err.message)
    if (locale === "en" && translated === err.message && err.code) {
      const title = errorCodeTitlesEn[err.code]
      if (title) return `${title}.`
    }
    return translated
  }
  if (err instanceof Error) {
    return translateServer(locale, err.message)
  }
  return tx("Beklenmeyen bir hata oluştu.")
}

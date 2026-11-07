// Requests for the panel's security endpoints (G5 sign-in factors, G6
// privacy lock, SSH terminal). The shared client in lib/api.ts keeps only
// "OS-nnnn" error codes; these endpoints answer with word codes such as
// "reauth_required" that decide what the page does next, so they are read
// here without widening the shared client.

import { errorMessage } from "@/lib/api"
import { tx } from "@/lib/i18n/i18n"

export class CodedError extends Error {
  readonly status: number
  readonly code: string

  constructor(message: string, status: number, code: string) {
    super(message)
    this.name = "CodedError"
    this.status = status
    this.code = code
  }
}

const wordCode = /^[a-z][a-z0-9_]{0,63}$/

let csrf: string | null = null

async function csrfToken(refresh: boolean): Promise<string> {
  if (csrf && !refresh) return csrf
  const res = await fetch("/api/session", { credentials: "same-origin", cache: "no-store" })
  if (!res.ok) throw await codedError(res)
  const data: unknown = await res.json()
  if (!data || typeof data !== "object" || !("csrfToken" in data) || typeof data.csrfToken !== "string") {
    throw new CodedError(tx("Oturum bilgisi okunamadı."), res.status, "")
  }
  csrf = data.csrfToken
  return csrf
}

export async function codedError(res: Response): Promise<CodedError> {
  let message = tx("Beklenmeyen bir hata oluştu.")
  let code = ""
  try {
    const data: unknown = await res.json()
    if (data && typeof data === "object") {
      if ("error" in data && typeof data.error === "string" && data.error.length <= 500) message = data.error
      if ("code" in data && typeof data.code === "string" && wordCode.test(data.code)) code = data.code
    }
  } catch {
    // Not JSON; keep the generic message.
  }
  return new CodedError(message, res.status, code)
}

interface PostOptions {
  /** Send the CSRF header (every session endpoint except the second sign-in step). */
  csrf?: boolean
}

async function send(path: string, body: unknown, withCsrf: boolean, refresh: boolean): Promise<Response> {
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (withCsrf) headers["X-CSRF-Token"] = await csrfToken(refresh)
  return fetch(path, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers,
    body: JSON.stringify(body ?? {}),
  })
}

/** POST JSON; a failure throws CodedError with the server's word code. */
export async function postCoded<T>(path: string, body: unknown, opts: PostOptions = {}): Promise<T> {
  const withCsrf = opts.csrf !== false
  let res = await send(path, body, withCsrf, false)
  if (withCsrf && res.status === 403) {
    const err = await codedError(res.clone())
    // Only a stale token is retried; a re-authentication answer is not.
    if (err.code === "") res = await send(path, body, true, true)
  }
  if (!res.ok) throw await codedError(res)
  const text = await res.text()
  return (text ? JSON.parse(text) : {}) as T
}

/** GET JSON; null when the build has no such endpoint (404 or 501). */
export async function optionalGet<T>(path: string): Promise<T | null> {
  const res = await fetch(path, { credentials: "same-origin", cache: "no-store" })
  if (res.status === 404 || res.status === 501) return null
  if (!res.ok) throw await codedError(res)
  return (await res.json()) as T
}

// base64url without padding, as the WebAuthn endpoints use it.

export function toB64url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let bin = ""
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function fromB64url(s: string): Uint8Array<ArrayBuffer> {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/")
  const pad = norm.length % 4 === 0 ? "" : "=".repeat(4 - (norm.length % 4))
  const bin = atob(norm + pad)
  const out = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** UTF-8 text as base64 (the SSH password field). */
export function utf8Base64(text: string): string {
  const bytes = new TextEncoder().encode(text)
  let bin = ""
  for (const b of bytes) bin += String.fromCharCode(b)
  bytes.fill(0)
  return btoa(bin)
}

/** WebAuthn works only on a name (localhost or a domain), never an IP address. */
export function webAuthnUsable(): boolean {
  if (typeof window === "undefined" || !("PublicKeyCredential" in window)) return false
  const host = window.location.hostname
  if (host === "localhost") return true
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) return false
  return window.isSecureContext
}

interface AssertionChallenge {
  challenge: string
  rp_id: string
  allow_credentials?: string[]
  timeout_ms: number
}

export interface AssertionBody {
  credential_id: string
  client_data_json: string
  authenticator_data: string
  signature: string
}

/** Runs navigator.credentials.get for a server challenge. */
export async function getAssertion(ch: AssertionChallenge): Promise<AssertionBody> {
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: fromB64url(ch.challenge),
      rpId: ch.rp_id,
      allowCredentials: (ch.allow_credentials ?? []).map((id) => ({ type: "public-key" as const, id: fromB64url(id) })),
      userVerification: "discouraged",
      timeout: ch.timeout_ms,
    },
  })
  if (!(cred instanceof PublicKeyCredential)) throw new Error(tx("Güvenlik anahtarı yanıt vermedi."))
  const resp = cred.response
  if (!(resp instanceof AuthenticatorAssertionResponse)) throw new Error(tx("Güvenlik anahtarı yanıtı okunamadı."))
  return {
    credential_id: toB64url(cred.rawId),
    client_data_json: toB64url(resp.clientDataJSON),
    authenticator_data: toB64url(resp.authenticatorData),
    signature: toB64url(resp.signature),
  }
}

/** Turns a browser WebAuthn failure into a calm sentence in the panel language. */
export function webAuthnError(err: unknown): string {
  if (err instanceof DOMException) {
    if (err.name === "NotAllowedError") return tx("İşlem iptal edildi veya süresi doldu. Yeniden deneyin.")
    if (err.name === "InvalidStateError") return tx("Bu güvenlik anahtarı zaten kayıtlı.")
    if (err.name === "SecurityError") return tx("Tarayıcı bu adreste güvenlik anahtarını kullanmaya izin vermiyor.")
  }
  if (err instanceof Error) return errorMessage(err)
  return tx("Güvenlik anahtarı kullanılamadı.")
}

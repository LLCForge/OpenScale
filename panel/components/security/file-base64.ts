// Reads a small file chosen by the owner as base64 (canary, sealed blob)
// and turns base64 back into a downloadable file. Nothing leaves the
// computer except to the panel's own loopback API.

import { tx } from "@/lib/i18n/i18n"

/** Largest file accepted; the server limits are 48 KiB and smaller. */
export const maxUploadBytes = 64 * 1024

export async function fileToBase64(file: File): Promise<string> {
  if (file.size > maxUploadBytes) {
    throw new Error(tx("Dosya çok büyük (en çok 64 KiB)."))
  }
  const bytes = new Uint8Array(await file.arrayBuffer())
  let bin = ""
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

export function downloadBase64(data: string, filename: string, type = "application/json") {
  const bin = atob(data)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  const url = URL.createObjectURL(new Blob([bytes], { type }))
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

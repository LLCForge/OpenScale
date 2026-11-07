"use client"

import { useEffect } from "react"
import { useTheme } from "next-themes"

interface NativeHost {
  postMessage: (message: string) => void
}

interface NativeWindow {
  chrome?: { webview?: NativeHost }
  webkit?: { messageHandlers?: { openscale?: NativeHost } }
}

// Sayfa arka planını #rrggbb olarak çözer (oklch dahil her CSS rengi).
function backgroundHex(): string | null {
  const color = getComputedStyle(document.body).backgroundColor
  const canvas = document.createElement("canvas")
  canvas.width = 1
  canvas.height = 1
  const ctx = canvas.getContext("2d", { willReadFrequently: true })
  if (!ctx) return null
  ctx.fillStyle = color
  ctx.fillRect(0, 0, 1, 1)
  const [r, g, b] = ctx.getImageData(0, 0, 1, 1).data
  return `#${[r, g, b].map((v) => v.toString(16).padStart(2, "0")).join("")}`
}

function nativeHost(): NativeHost | null {
  const w = window as unknown as NativeWindow
  return w.chrome?.webview ?? w.webkit?.messageHandlers?.openscale ?? null
}

// Masaüstü penceresinin başlık çubuğunu panel temasıyla eşler. Tarayıcıda
// hiçbir şey yapmaz.
export function NativeThemeBridge() {
  const { resolvedTheme } = useTheme()

  useEffect(() => {
    const host = nativeHost()
    if (!host || (resolvedTheme !== "dark" && resolvedTheme !== "light")) return
    const frame = requestAnimationFrame(() => {
      const hex = backgroundHex()
      if (hex) host.postMessage(`theme:${resolvedTheme}:${hex}`)
    })
    return () => cancelAnimationFrame(frame)
  }, [resolvedTheme])

  return null
}

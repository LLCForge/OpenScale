import type { Metadata, Viewport } from "next"
import { Figtree, Geist_Mono } from "next/font/google"
import { ThemeProvider } from "next-themes"

import { NativeThemeBridge } from "@/components/native-theme-bridge"

import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { LocaleSync } from "@/lib/i18n/i18n"
import "./globals.css"

// Fonts are downloaded at build time and served from the panel itself;
// the running panel never contacts Google or any other host.
// Figtree is the logo's typeface (SIL Open Font License, logos/Figtree-OFL.txt).
const figtree = Figtree({ variable: "--font-figtree", subsets: ["latin", "latin-ext"] })
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin", "latin-ext"] })

export const metadata: Metadata = {
  title: "OpenScale",
  // i18n-ignore: meta açıklaması ekranda gösterilmez (yerel panel, arama motoruna kapalı)
  description: "Kişisel OpenScale ağının yerel yönetim paneli",
  robots: { index: false, follow: false },
  referrer: "no-referrer",
}

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#fafafa" },
    { media: "(prefers-color-scheme: dark)", color: "#16161a" },
  ],
}

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="tr" className={`${figtree.variable} ${geistMono.variable} h-full antialiased`} suppressHydrationWarning>
      <body className="min-h-full flex flex-col font-sans">
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem disableTransitionOnChange>
          <LocaleSync />
          <NativeThemeBridge />
          <TooltipProvider>{children}</TooltipProvider>
          <Toaster richColors position="top-center" />
        </ThemeProvider>
      </body>
    </html>
  )
}

import type { Metadata } from "next"

import { LoginForm } from "@/components/auth/login-form"
import { LoginNote } from "@/components/auth/login-note"
import { BrandWordmark } from "@/components/brand"
import { LanguageCorner } from "@/components/language-switcher"

export const metadata: Metadata = { title: "Giriş · OpenScale" }

export default function LoginPage() {
  return (
    <main className="flex min-h-svh flex-col items-center justify-center gap-10 bg-background px-4 py-12">
      <BrandWordmark size="lg" />
      <LoginForm />
      <LoginNote />
      <LanguageCorner />
    </main>
  )
}

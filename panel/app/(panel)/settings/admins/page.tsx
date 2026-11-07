import type { Metadata } from "next"

import { AdminsView } from "@/components/security/admins-view"

export const metadata: Metadata = { title: "Yöneticiler · OpenScale" }

export default function AdminsPage() {
  return <AdminsView />
}

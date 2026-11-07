import type { Metadata } from "next"

import { RDeskViewer } from "@/components/rdesk/rdesk-viewer"

export const metadata: Metadata = { title: "Uzak masaüstü · OpenScale" }

export default function RemoteViewerPage() {
  return <RDeskViewer />
}

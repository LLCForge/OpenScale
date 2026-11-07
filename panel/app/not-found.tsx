import Link from "next/link"

import { Button } from "@/components/ui/button"
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty"
import { T } from "@/lib/i18n/i18n"

export default function NotFound() {
  return (
    <Empty className="border">
      <EmptyHeader>
        <EmptyTitle>
          <T>Sayfa bulunamadı</T>
        </EmptyTitle>
        <EmptyDescription>
          <T>Aradığın sayfa bu panelde yok.</T>
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button nativeButton={false} render={<Link href="/" />}>
          <T>Genel bakışa dön</T>
        </Button>
      </EmptyContent>
    </Empty>
  )
}

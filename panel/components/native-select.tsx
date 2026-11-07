import { cn } from "@/lib/utils"

/**
 * The panel's plain select: the browser's own list (keyboard, screen
 * readers and touch work as everywhere), drawn like the other fields.
 */
export function NativeSelect({ className, ...props }: React.ComponentProps<"select">) {
  return (
    <select
      className={cn(
        "h-9 w-full min-w-0 rounded-lg border border-input bg-background px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50 aria-invalid:border-destructive sm:w-auto",
        className
      )}
      {...props}
    />
  )
}

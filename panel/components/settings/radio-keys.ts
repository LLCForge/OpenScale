import type { KeyboardEvent } from "react"

// Arrow key movement for button groups drawn as role="radiogroup" with
// role="radio" buttons (WAI-ARIA radio group pattern): only the checked
// button is in the tab order, arrows move to and choose the next option,
// Home and End jump to the ends. Disabled options are skipped.

const keys: Record<string, number | "first" | "last"> = {
  ArrowRight: 1,
  ArrowDown: 1,
  ArrowLeft: -1,
  ArrowUp: -1,
  Home: "first",
  End: "last",
}

/** onKeyDown for the radiogroup element. */
export function radioGroupKeyDown(event: KeyboardEvent<HTMLElement>) {
  const step = keys[event.key]
  if (step === undefined) return
  const radios = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('[role="radio"]')).filter(
    (el) => !el.hasAttribute("disabled") && el.getAttribute("aria-disabled") !== "true"
  )
  if (radios.length === 0) return
  const current = radios.findIndex((el) => el === document.activeElement)
  let next: number
  if (step === "first") next = 0
  else if (step === "last") next = radios.length - 1
  else next = current < 0 ? 0 : (current + step + radios.length) % radios.length
  event.preventDefault()
  radios[next].focus()
  radios[next].click()
}


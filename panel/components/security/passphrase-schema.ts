import { z } from "zod"

import { msg } from "@/lib/i18n/i18n"

const MIN_LENGTH = 12
const MIN_DISTINCT = 6

/** Mirrors trust.CheckPassphrase on the server, which remains authoritative. */
export const newPassphrase = z
  .string()
  .max(1024, msg("Parola çok uzun"))
  // The text repeats MIN_LENGTH so it can be a dictionary key.
  .refine((v) => Array.from(v).length >= MIN_LENGTH, msg("En az 12 karakter olmalı"))
  .refine((v) => new Set(Array.from(v)).size >= MIN_DISTINCT, msg("Birkaç karakterin tekrarından oluşmamalı"))

export const currentPassphrase = z.string().min(1, msg("Mevcut parola gerekli")).max(1024, msg("Parola çok uzun"))

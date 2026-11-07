"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import Link from "next/link"
import { ArrowUp, Download, File, Folder, FolderPlus, House, RefreshCw, ShieldAlert, Trash2, TriangleAlert, Upload } from "lucide-react"

import { withReauth } from "@/components/auth/reauth"
import { CodedError, codedError, postCoded, utf8Base64 } from "@/components/auth/strict-api"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatBytes, formatDateTime } from "@/lib/format"
import { msg, useI18n } from "@/lib/i18n/i18n"

// File browser beside the SSH terminal (#855, internal/panel/f3_sftp_api.go).
// It signs in like the terminal (same account and the same pinned host
// key), lists folders, uploads, creates folders and deletes after a
// confirmation. A download goes into this computer's quarantine and is
// released on the Received Files page like any other received file.

interface OpenAnswer {
  handle: string
  home: string
  hostkey?: { status: string; fingerprint: string }
}

interface Entry {
  name: string
  size: number
  dir: boolean
  link: boolean
  regular: boolean
  perm: number
  mtime?: string
}

interface ListAnswer {
  path: string
  home: string
  entries: Entry[]
  truncated: boolean
}

const maxUpload = 2 * 1024 * 1024 * 1024

const errorText: Record<string, string> = {
  auth_failed: msg("Kullanıcı adı veya parola kabul edilmedi."),
  blocked: msg("Çok fazla hatalı parola; bir süre bekleyin."),
  connect_failed: msg("Cihaza bağlanılamadı. Cihazın açık olduğunu ve SSH kuralının bu bilgisayara izin verdiğini denetleyin."),
  sftp_unavailable: msg("Cihazın SSH sunucusunda SFTP açık değil."),
  too_many: msg("Çok fazla açık dosya oturumu; birini kapatıp yeniden deneyin."),
  no_session: msg("Dosya oturumu kapandı; yeniden bağlanın."),
  not_found: msg("Dosya veya klasör bulunamadı."),
  denied: msg("Bu hesabın bu işleme izni yok."),
  too_large: msg("Dosya çok büyük (en çok 2 GiB)."),
  bad_name: msg("Ad geçersiz: tek bir ad yazın; / ve .. kullanılamaz."),
  bad_path: msg("Yol geçersiz."),
  changed: msg("Öğe değişmiş; listeyi yenileyip yeniden deneyin."),
  not_file: msg("Yalnızca normal dosyalar indirilebilir."),
  timeout: msg("Cihaz zamanında yanıt vermedi."),
}

/** True when name is one path element the server accepts. */
function validName(name: string): boolean {
  if (name === "" || name === "." || name === ".." || name.length > 255) return false
  return !/[/\\\u0000-\u001f\u007f]/.test(name)
}

function joinPath(dir: string, name: string): string {
  return dir.endsWith("/") ? dir + name : `${dir}/${name}`
}

function parentOf(p: string): string {
  if (p === "/" || p === "") return "/"
  const trimmed = p.replace(/\/+$/, "")
  const i = trimmed.lastIndexOf("/")
  return i <= 0 ? "/" : trimmed.slice(0, i)
}

async function getList(handle: string, path: string): Promise<ListAnswer> {
  const res = await fetch(`/api/sftp/list?h=${encodeURIComponent(handle)}&path=${encodeURIComponent(path)}`, {
    credentials: "same-origin",
    cache: "no-store",
  })
  if (!res.ok) throw await codedError(res)
  return (await res.json()) as ListAnswer
}

async function uploadFile(handle: string, dir: string, file: File): Promise<void> {
  const session = await fetch("/api/session", { credentials: "same-origin", cache: "no-store" })
  if (!session.ok) throw await codedError(session)
  const { csrfToken } = (await session.json()) as { csrfToken?: unknown }
  if (typeof csrfToken !== "string") throw new Error(msg("Oturum bilgisi okunamadı."))
  const res = await fetch(`/api/sftp/upload?h=${encodeURIComponent(handle)}&dir=${encodeURIComponent(dir)}`, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-CSRF-Token": csrfToken,
      "X-OpenScale-File-Name": encodeURIComponent(file.name),
    },
    body: file,
  })
  if (!res.ok) throw await codedError(res)
}

function describe(err: unknown): string {
  if (err instanceof CodedError && errorText[err.code]) return errorText[err.code]
  if (err instanceof Error && err.message) return err.message
  return msg("İşlem tamamlanamadı; bağlantı kopmuş olabilir.")
}

export function SFTPBrowser({ device }: { device: string }) {
  const { t, ts } = useI18n()
  const [user, setUser] = useState("")
  const [port, setPort] = useState("22")
  const [password, setPassword] = useState("")
  const [formError, setFormError] = useState("")
  const [handle, setHandle] = useState("")
  const [opening, setOpening] = useState(false)
  const [list, setList] = useState<ListAnswer | null>(null)
  const [loading, setLoading] = useState(false)
  const [failure, setFailure] = useState("")
  const [notice, setNotice] = useState("")
  const [inboxLink, setInboxLink] = useState(false)
  const [keyChanged, setKeyChanged] = useState(false)
  const [busy, setBusy] = useState("")
  const [newFolder, setNewFolder] = useState("")
  const [removing, setRemoving] = useState<Entry | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const handleRef = useRef("")

  // The session ends with the dialog.
  useEffect(
    () => () => {
      const h = handleRef.current
      if (h) void postCoded("/api/sftp/close", { h }).catch(() => undefined)
    },
    []
  )

  const load = useCallback(async (h: string, path: string) => {
    setLoading(true)
    setFailure("")
    try {
      setList(await getList(h, path))
    } catch (err) {
      if (err instanceof CodedError && err.code === "no_session") {
        handleRef.current = ""
        setHandle("")
        setList(null)
      }
      setFailure(describe(err))
    } finally {
      setLoading(false)
    }
  }, [])

  async function open(e: React.FormEvent) {
    e.preventDefault()
    const name = user.trim()
    const portNumber = Number.parseInt(port, 10)
    if (!/^[a-z_][a-z0-9_.-]{0,31}$/i.test(name)) {
      setFormError(msg("Geçerli bir kullanıcı adı girin."))
      return
    }
    if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
      setFormError(msg("Port 1 ile 65535 arasında olmalı."))
      return
    }
    if (!password) {
      setFormError(msg("Parola gerekli."))
      return
    }
    setFormError("")
    setFailure("")
    setKeyChanged(false)
    setOpening(true)
    const secret = utf8Base64(password)
    setPassword("")
    try {
      const answer = await withReauth(() => postCoded<OpenAnswer>("/api/sftp/open", { device, port: portNumber, user: name, password: secret }))
      handleRef.current = answer.handle
      setHandle(answer.handle)
      if (answer.hostkey?.status === "pinned") setNotice(msg("Bu cihazın sunucu anahtarı ilk kez kaydedildi:") + " " + answer.hostkey.fingerprint)
      await load(answer.handle, answer.home)
    } catch (err) {
      if (err instanceof CodedError && err.code === "host_key_changed") setKeyChanged(true)
      else setFailure(describe(err))
    } finally {
      setOpening(false)
    }
  }

  async function run(label: string, fn: () => Promise<void>) {
    setBusy(label)
    setFailure("")
    setNotice("")
    setInboxLink(false)
    try {
      await fn()
    } catch (err) {
      setFailure(describe(err))
    } finally {
      setBusy("")
    }
  }

  const cwd = list?.path ?? "/"

  function download(entry: Entry) {
    void run("download", async () => {
      const answer = await postCoded<{ name: string; size: number; quarantined: boolean }>("/api/sftp/download", { h: handle, path: joinPath(cwd, entry.name) })
      setNotice(
        answer.quarantined
          ? msg("İndirildi. Dosya bu bilgisayarda karantinada; açmadan önce Gelen Dosyalar sayfasından serbest bırakın.")
          : msg("İndirildi ve Gelen Dosyalar sayfasına kondu; işletim sistemi işareti eklenemedi, açarken dikkatli olun.")
      )
      setInboxLink(true)
    })
  }

  function upload(files: FileList | null) {
    const chosen = files ? Array.from(files) : []
    if (fileInput.current) fileInput.current.value = ""
    if (chosen.length === 0) return
    const bad = chosen.find((f) => f.size > maxUpload || !validName(f.name))
    if (bad) {
      setFailure(bad.size > maxUpload ? errorText.too_large : errorText.bad_name)
      return
    }
    void run("upload", async () => {
      for (const f of chosen) await uploadFile(handle, cwd, f)
      setNotice(msg("Yüklendi."))
      await load(handle, cwd)
    })
  }

  function mkdir(e: React.FormEvent) {
    e.preventDefault()
    const name = newFolder.trim()
    if (!validName(name)) {
      setFailure(errorText.bad_name)
      return
    }
    void run("mkdir", async () => {
      await postCoded("/api/sftp/mkdir", { h: handle, dir: cwd, name })
      setNewFolder("")
      await load(handle, cwd)
    })
  }

  function confirmRemove() {
    const entry = removing
    setRemoving(null)
    if (!entry) return
    void run("remove", async () => {
      await postCoded("/api/sftp/remove", { h: handle, path: joinPath(cwd, entry.name), dir: entry.dir })
      await load(handle, cwd)
    })
  }

  if (!handle) {
    return (
      <div className="flex min-w-0 flex-col gap-4">
        {keyChanged ? (
          <Alert variant="destructive">
            <ShieldAlert />
            <AlertTitle>{t("Sunucu anahtarı değişti!")}</AlertTitle>
            <AlertDescription>{t("Ortadaki saldırı olabilir. Bağlantı kurulmadı.")}</AlertDescription>
          </Alert>
        ) : null}
        {failure ? (
          <Alert variant="destructive">
            <TriangleAlert />
            <AlertDescription>{ts(failure)}</AlertDescription>
          </Alert>
        ) : null}
        <form onSubmit={open} noValidate className="flex flex-col gap-5">
          <FieldGroup className="grid gap-4 sm:grid-cols-[1fr_7rem]">
            <Field>
              <FieldLabel htmlFor="sftp-user">{t("Kullanıcı adı")}</FieldLabel>
              <Input id="sftp-user" autoComplete="username" value={user} maxLength={32} onChange={(e) => setUser(e.target.value)} />
            </Field>
            <Field>
              <FieldLabel htmlFor="sftp-port">Port</FieldLabel>
              <Input id="sftp-port" inputMode="numeric" value={port} maxLength={5} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} />
            </Field>
            <Field className="sm:col-span-2" data-invalid={formError ? true : undefined}>
              <FieldLabel htmlFor="sftp-password">{t("Parola")}</FieldLabel>
              <Input
                id="sftp-password"
                type="password"
                autoComplete="current-password"
                value={password}
                maxLength={1024}
                onChange={(e) => setPassword(e.target.value)}
                aria-invalid={formError ? true : undefined}
              />
              <FieldError>{formError ? ts(formError) : null}</FieldError>
              <FieldDescription>{t("Dosyalar terminalle aynı hesap ve aynı kayıtlı sunucu anahtarıyla açılır.")}</FieldDescription>
            </Field>
          </FieldGroup>
          <Button type="submit" className="w-fit" disabled={opening}>
            {opening ? <Spinner data-icon="inline-start" /> : null}
            {t("Dosyaları aç")}
          </Button>
        </form>
      </div>
    )
  }

  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" size="sm" onClick={() => void load(handle, parentOf(cwd))} disabled={loading || cwd === "/"} aria-label={t("Üst klasör")}>
          <ArrowUp data-icon="inline-start" />
          {t("Üst klasör")}
        </Button>
        <Button variant="outline" size="sm" onClick={() => void load(handle, list?.home ?? "/")} disabled={loading} aria-label={t("Ev klasörü")}>
          <House data-icon="inline-start" />
          {t("Ev klasörü")}
        </Button>
        <Button variant="outline" size="sm" onClick={() => void load(handle, cwd)} disabled={loading} aria-label={t("Yenile")}>
          <RefreshCw data-icon="inline-start" />
          {t("Yenile")}
        </Button>
        <Button size="sm" onClick={() => fileInput.current?.click()} disabled={busy !== ""}>
          {busy === "upload" ? <Spinner data-icon="inline-start" /> : <Upload data-icon="inline-start" />}
          {t("Yükle")}
        </Button>
        <input ref={fileInput} type="file" multiple className="sr-only" tabIndex={-1} aria-hidden="true" onChange={(e) => upload(e.target.files)} />
      </div>
      <p className="truncate font-mono text-xs text-muted-foreground" title={cwd}>
        {cwd}
      </p>
      <form onSubmit={mkdir} className="flex items-end gap-2">
        <Field className="max-w-xs flex-1">
          <FieldLabel htmlFor="sftp-folder" className="sr-only">
            {t("Yeni klasör adı")}
          </FieldLabel>
          <Input id="sftp-folder" placeholder={t("Yeni klasör adı")} value={newFolder} maxLength={255} onChange={(e) => setNewFolder(e.target.value)} />
        </Field>
        <Button type="submit" variant="outline" size="sm" disabled={busy !== "" || newFolder.trim() === ""}>
          {busy === "mkdir" ? <Spinner data-icon="inline-start" /> : <FolderPlus data-icon="inline-start" />}
          {t("Klasör oluştur")}
        </Button>
      </form>

      {failure ? (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertDescription>{ts(failure)}</AlertDescription>
        </Alert>
      ) : null}
      {notice ? (
        <p role="status" className="rounded-lg border bg-muted/40 px-3 py-2 text-sm text-pretty">
          {ts(notice)}{" "}
          {inboxLink ? (
            <Link href="/inbox/" className="underline underline-offset-4">
              {t("Gelen Dosyalar")}
            </Link>
          ) : null}
        </p>
      ) : null}
      {list?.truncated ? <p className="text-sm text-muted-foreground">{t("Klasörde çok fazla girdi var; ilk 10.000 gösteriliyor.")}</p> : null}

      <div className="max-h-[50vh] overflow-auto rounded-lg border">
        {loading && !list ? (
          <p role="status" className="flex items-center gap-2 p-4 text-sm text-muted-foreground">
            <Spinner /> {t("Yükleniyor…")}
          </p>
        ) : list && list.entries.length === 0 ? (
          <Empty>
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <Folder />
              </EmptyMedia>
              <EmptyTitle>{t("Klasör boş")}</EmptyTitle>
              <EmptyDescription>{t("Dosya yükleyebilir veya klasör oluşturabilirsiniz.")}</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("Ad")}</TableHead>
                <TableHead className="hidden text-right sm:table-cell">{t("Boyut")}</TableHead>
                <TableHead className="hidden md:table-cell">{t("Değiştirilme")}</TableHead>
                <TableHead className="text-right">
                  <span className="sr-only">{t("İşlemler")}</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(list?.entries ?? []).map((e) => (
                <TableRow key={e.name}>
                  <TableCell className="max-w-0 min-w-40">
                    {e.dir ? (
                      <button
                        type="button"
                        className="flex w-full items-center gap-2 truncate text-left hover:underline"
                        onClick={() => void load(handle, joinPath(cwd, e.name))}
                      >
                        <Folder className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                        <span className="truncate">{e.name}</span>
                      </button>
                    ) : (
                      <span className="flex items-center gap-2 truncate">
                        <File className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                        <span className="truncate">{e.name}</span>
                        {e.link ? <span className="text-xs text-muted-foreground">{t("(bağlantı)")}</span> : null}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="hidden text-right tabular-nums sm:table-cell">{e.dir ? "" : formatBytes(e.size)}</TableCell>
                  <TableCell className="hidden text-muted-foreground md:table-cell">{e.mtime ? formatDateTime(e.mtime) : ""}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      {e.regular ? (
                        <Button variant="ghost" size="icon-sm" onClick={() => download(e)} disabled={busy !== ""} aria-label={t("{name} indir", { name: e.name })}>
                          <Download />
                        </Button>
                      ) : null}
                      {e.dir || e.regular || e.link ? (
                        <Button variant="ghost" size="icon-sm" onClick={() => setRemoving(e)} disabled={busy !== ""} aria-label={t("{name} sil", { name: e.name })}>
                          <Trash2 />
                        </Button>
                      ) : null}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      <AlertDialog open={removing !== null} onOpenChange={(o) => (o ? undefined : setRemoving(null))}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{removing?.dir ? t("Klasör silinsin mi?") : t("Dosya silinsin mi?")}</AlertDialogTitle>
            <AlertDialogDescription className="break-all text-pretty">
              {removing ? t("{path} cihazdan kalıcı olarak silinir. Klasörler yalnızca boşken silinebilir.", { path: joinPath(cwd, removing.name) }) : null}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("Vazgeç")}</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={confirmRemove}>
              {t("Sil")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

import { DetailGroup, DetailItem, DetailSection } from "@/components/devices/detail-card"
import { UsageBar } from "@/components/devices/system-bits"
import { headCell, ListTable } from "@/components/settings/list-table"
import { EmptyNote, SettingBadge } from "@/components/settings/settings-layout"
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatBytes, formatDate, formatDateTime, formatNumber, numberFormat } from "@/lib/format"
import { msg, tx, useI18n } from "@/lib/i18n/i18n"
import type { Inventory, InventoryDisk, InventoryNIC, InventoryVolume } from "@/lib/inventory-types"
import type { DeviceDetail } from "@/lib/types"
import { cn } from "@/lib/utils"

// Detailed inventory (ADR-0143) on the device page: hardware and system in
// the two-column definition list of "Cihaz ayrıntıları", then disks,
// network adapters, battery and displays. Serial numbers, MAC addresses
// and network names never reach the panel.

/** Up to two decimals in the interface language ("1,8" / "1.8"). */
function decimal(n: number): string {
  return formatNumber(n, 2)
}

/** "%40" in Turkish, "40%" in English. */
function formatPercent(n: number): string {
  return numberFormat("percent0", { style: "percent", maximumFractionDigits: 0 }).format(n / 100)
}

/** "32 GB", "1.8 TB": binary units as in the usage bars, without a trailing ".0". */
function size(n?: number): string {
  if (!n || n <= 0) return ""
  return formatBytes(n).replace(/\.0 /, " ")
}

function ghz(mhz?: number): string {
  return mhz && mhz > 0 ? `${decimal(mhz / 1000)} GHz` : ""
}

function unixDateTime(sec?: number): string {
  return sec && sec > 0 ? formatDateTime(new Date(sec * 1000).toISOString()) : ""
}

/** "UTC+03:00" from an offset east of UTC in seconds. */
function utcOffset(sec: number): string {
  const sign = sec < 0 ? "-" : "+"
  const abs = Math.abs(sec)
  const h = String(Math.floor(abs / 3600)).padStart(2, "0")
  const m = String(Math.floor((abs % 3600) / 60)).padStart(2, "0")
  return `UTC${sign}${h}:${m}`
}

function biosDate(s?: string): string {
  if (!s || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return ""
  return formatDate(`${s}T12:00:00Z`)
}

const installTypes: Record<string, string> = { Client: msg("İstemci"), Server: msg("Sunucu"), "Server Core": msg("Sunucu çekirdeği") }

type Tone = "success" | "warning" | "muted"

const cpuVirt: Record<string, { text: string; tone: Tone }> = {
  on: { text: msg("Açık"), tone: "success" },
  off: { text: msg("Kapalı veya yok"), tone: "warning" },
  hv: { text: msg("Hiper yönetici çalışıyor"), tone: "muted" },
}

const secureBoot: Record<string, { text: string; tone: Tone }> = {
  on: { text: msg("Açık"), tone: "success" },
  off: { text: msg("Kapalı"), tone: "warning" },
  unsupported: { text: msg("Desteklenmiyor (eski BIOS)"), tone: "muted" },
}

const diskTypes: Record<string, string> = { nvme: "NVMe SSD", ssd: "SSD", hdd: "HDD" }
const busNames: Record<string, string> = { usb: "USB", sata: "SATA", sas: "SAS", scsi: "SCSI", virtual: msg("Sanal"), mmc: "SD/MMC", nvme: "" }

const nicTypes: Record<string, string> = {
  wifi: "Wi-Fi",
  ethernet: "Ethernet",
  virtual: msg("Sanal"),
  cellular: msg("Hücresel"),
  bluetooth: "Bluetooth",
  other: msg("Diğer"),
}

const batteryStates: Record<string, string> = {
  charging: msg("Şarj oluyor"),
  discharging: msg("Pille çalışıyor"),
  full: msg("Dolu"),
  ac: msg("Prizde, şarj olmuyor"),
}

/** Empty values are left out, so unknown details do not fill the list. */
function Item({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === "" || value === null || value === undefined || value === false) return null
  return <DetailItem label={label}>{value}</DetailItem>
}

function Unknown() {
  const { t } = useI18n()
  return <span className="text-muted-foreground">{t("Bilinmiyor")}</span>
}

export function HardwareSections({ device }: { device: DeviceDetail }) {
  const { t } = useI18n()
  const s = device.system
  const d = s?.detail
  let empty: string = msg("Bu cihaz ayrıntılı envanter göndermiyor (eski sürüm).")
  if (!device.liveAvailable) empty = msg("Ayrıntılı envanter masaüstü uygulamasında görünür.")
  else if (!s) empty = msg("Bu cihazdan henüz rapor gelmedi.")
  else if (s.detailPending) empty = msg("Ayrıntılı envanter cihazdan alınıyor; birkaç saniye içinde görünür.")
  return (
    <>
      <DetailSection
        id="donanim"
        title={t("Donanım")}
        description={t("Cihazın kendi gönderdiği ayrıntılı envanter; yalnızca yönetici panelinde görünür.")}
        framed={false}
      >
        {d ? <HardwareGrid detail={d} osLabel={s?.osLabel || ""} /> : <EmptyNote>{t(empty)}</EmptyNote>}
      </DetailSection>
      {d ? (
        <>
          <DisksSection disks={d.disks ?? []} volumes={d.vols ?? []} />
          <NICsSection nics={d.nics ?? []} />
          {d.bat ? <BatterySection detail={d} /> : null}
          {d.displays && d.displays.length > 0 ? <DisplaysSection detail={d} /> : null}
        </>
      ) : null}
    </>
  )
}

function HardwareGrid({ detail: d, osLabel }: { detail: Inventory; osLabel: string }) {
  const { t } = useI18n()
  const os = d.os
  const cpu = d.cpu
  const b = d.board
  const modules = groupModules(d)
  const vendorModel = [b.vendor, b.model].filter(Boolean).join(" ")
  const boardModel = [b.board_vendor, b.board_model].filter(Boolean).join(" ")
  const bios = [b.bios_vendor, b.bios_ver].filter(Boolean).join(" ")
  const coreText = [
    cpu.cores ? t("{count} çekirdek", { count: cpu.cores }) : "",
    cpu.threads ? t("{count} iş parçacığı", { count: cpu.threads }) : "",
  ]
    .filter(Boolean)
    .join(" / ")
  const virt = cpu.virt ? cpuVirt[cpu.virt] : undefined
  const sb = b.secure_boot ? secureBoot[b.secure_boot] : undefined
  const gpus = d.gpus ?? []
  return (
    <div className="grid rounded-lg border md:grid-cols-2">
      <div className="flex min-w-0 flex-col gap-8 p-4 md:p-6">
        <DetailGroup title={t("İşletim sistemi")}>
          <DetailItem label={t("Ad")}>{os.name ? <span className="break-words">{osLabel || os.name}</span> : <Unknown />}</DetailItem>
          <Item label={t("Sürüm")} value={os.ver} />
          <Item label={t("Derleme")} value={os.build ? <span className="font-mono">{os.build}</span> : ""} />
          <Item
            label={t("Sürüm türü")}
            value={[os.edition, os.install_type ? t(installTypes[os.install_type] ?? os.install_type) : ""].filter(Boolean).join(" · ")}
          />
          <Item label={t("Insider kanalı")} value={os.channel} />
          <Item label={t("Çekirdek")} value={os.kernel ? <span className="font-mono break-all">{os.kernel}</span> : ""} />
          <Item label={t("Mimari")} value={os.arch ? <span className="font-mono">{os.arch}</span> : ""} />
          <Item label={t("Kurulum tarihi")} value={unixDateTime(os.installed)} />
          <Item label={t("Son açılış")} value={unixDateTime(os.boot)} />
          <Item label={t("Saat dilimi")} value={os.tz ? `${os.tz} (${utcOffset(os.tz_offset)})` : utcOffset(os.tz_offset)} />
          <Item label={t("Oturum açan kullanıcı")} value={d.users >= 0 ? String(d.users) : ""} />
        </DetailGroup>
        <DetailGroup title={t("İşlemci")}>
          <DetailItem label={t("Model")}>{cpu.model ? <span className="break-words">{cpu.model}</span> : <Unknown />}</DetailItem>
          <Item
            label={t("Çekirdek")}
            value={cpu.sockets && cpu.sockets > 1 ? t("{cores} ({count} soket)", { cores: coreText, count: cpu.sockets }) : coreText}
          />
          <Item label={t("Temel hız")} value={ghz(cpu.base_mhz)} />
          <Item label={t("Azami hız")} value={ghz(cpu.max_mhz)} />
          <Item label={t("Sanallaştırma")} value={virt ? <SettingBadge tone={virt.tone}>{t(virt.text)}</SettingBadge> : ""} />
        </DetailGroup>
      </div>
      <div className="flex min-w-0 flex-col gap-8 border-t p-4 md:border-t-0 md:border-l md:p-6">
        <DetailGroup title={t("Bellek")}>
          <DetailItem label={t("Toplam")}>{size(d.mem.total) || <Unknown />}</DetailItem>
          <Item
            label={t("Modüller")}
            value={
              modules.length > 0 ? (
                <span className="flex flex-col gap-0.5">
                  {modules.map((m) => (
                    <span key={m}>{m}</span>
                  ))}
                </span>
              ) : (
                ""
              )
            }
          />
          <Item
            label={t("Yuvalar")}
            value={d.mem.slots ? t("{used} / {count} dolu", { used: d.mem.modules?.length ?? 0, count: d.mem.slots }) : ""}
          />
        </DetailGroup>
        <DetailGroup title={t("Anakart ve ürün yazılımı")}>
          <Item label={t("Sistem")} value={vendorModel ? <span className="break-words">{vendorModel}</span> : ""} />
          <Item label={t("Anakart")} value={boardModel && boardModel !== vendorModel ? <span className="break-words">{boardModel}</span> : ""} />
          <Item label="BIOS" value={bios ? <span className="break-words">{[bios, biosDate(b.bios_date)].filter(Boolean).join(" · ")}</span> : ""} />
          <Item label={t("Ürün yazılımı")} value={b.fw === "uefi" ? "UEFI" : b.fw === "bios" ? t("Eski BIOS") : ""} />
          <Item label={t("Güvenli Önyükleme")} value={sb ? <SettingBadge tone={sb.tone}>{t(sb.text)}</SettingBadge> : ""} />
          <Item label="TPM" value={<TpmValue tpm={b.tpm} vendor={b.tpm_vendor} />} />
        </DetailGroup>
        <DetailGroup title={t("Ekran kartları")}>
          {gpus.length > 0 ? (
            gpus.map((g, i) => (
              <DetailItem key={`${g.model ?? ""}-${i}`} label={gpus.length > 1 ? t("Kart {n}", { n: i + 1 }) : t("Model")}>
                <span className="flex min-w-0 flex-col gap-0.5">
                  <span className="break-words">{g.model || t("Bilinmeyen bağdaştırıcı")}</span>
                  {g.vram || g.driver ? (
                    <span className="text-xs text-muted-foreground">
                      {[g.vram ? t("{size} bellek", { size: size(g.vram) }) : "", g.driver ? t("sürücü {driver}", { driver: g.driver }) : ""]
                        .filter(Boolean)
                        .join(" · ")}
                    </span>
                  ) : null}
                </span>
              </DetailItem>
            ))
          ) : (
            <DetailItem label={t("Model")}>
              <Unknown />
            </DetailItem>
          )}
        </DetailGroup>
      </div>
    </div>
  )
}

function TpmValue({ tpm, vendor }: { tpm?: string; vendor?: string }) {
  const { t } = useI18n()
  if (!tpm) return <Unknown />
  if (tpm === "none") return <SettingBadge tone="warning">{t("none|Yok")}</SettingBadge>
  return (
    <span>
      {tpm}
      {vendor ? <span className="text-muted-foreground"> ({vendor})</span> : null}
    </span>
  )
}

/** "2 × 32 GB DDR4-4266" lines, identical modules counted together. */
function groupModules(d: Inventory): string[] {
  const counts = new Map<string, number>()
  for (const m of d.mem.modules ?? []) {
    const kind = m.type && m.mhz ? `${m.type}-${m.mhz}` : m.type || (m.mhz ? `${m.mhz} MT/s` : "")
    const text = [size(m.size), kind].filter(Boolean).join(" ")
    if (!text) continue
    counts.set(text, (counts.get(text) ?? 0) + 1)
  }
  return [...counts].map(([text, n]) => (n > 1 ? `${n} × ${text}` : text))
}

/** Called during render of DiskRows, which uses useI18n(). */
function diskKind(disk: InventoryDisk): string {
  const parts = [disk.type ? (diskTypes[disk.type] ?? disk.type) : "", disk.bus ? tx(busNames[disk.bus] ?? disk.bus.toUpperCase()) : ""]
  if (disk.removable) parts.push(tx("Çıkarılabilir"))
  return parts.filter(Boolean).join(" · ") || tx("Bilinmiyor")
}

function DisksSection({ disks, volumes }: { disks: InventoryDisk[]; volumes: InventoryVolume[] }) {
  const { t } = useI18n()
  const known = new Set(disks.map((d) => d.idx))
  const orphan = volumes.filter((v) => !known.has(v.disk))
  const groups: { key: string; disk?: InventoryDisk; vols: InventoryVolume[] }[] = disks.map((d) => ({
    key: `d${d.idx}`,
    disk: d,
    vols: volumes.filter((v) => v.disk === d.idx),
  }))
  if (orphan.length > 0) groups.push({ key: "other", vols: orphan })
  return (
    <DetailSection
      id="diskler"
      title={t("Diskler ve birimler")}
      description={t("Fiziksel diskler ve üzerlerindeki bağlı birimler; şifreleme cihazın kendi beyanıdır.")}
      framed={false}
    >
      {groups.length === 0 ? (
        <EmptyNote>{t("Disk bilgisi okunamadı.")}</EmptyNote>
      ) : (
        <ListTable label={t("Diskler ve birimler")}>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className={headCell}>{t("Disk / birim")}</TableHead>
              <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Tür")}</TableHead>
              <TableHead className={headCell}>{t("Boyut")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {groups.map((g) => (
              <DiskRows key={g.key} disk={g.disk} volumes={g.vols} />
            ))}
          </TableBody>
        </ListTable>
      )}
    </DetailSection>
  )
}

function DiskRows({ disk, volumes }: { disk?: InventoryDisk; volumes: InventoryVolume[] }) {
  const { t } = useI18n()
  return (
    <>
      <TableRow className="bg-muted/40 hover:bg-muted/40">
        <TableCell className="min-w-40 whitespace-normal">
          <span className="flex flex-col gap-0.5">
            <span className="text-sm font-medium break-words">{disk ? disk.model || t("Disk {n}", { n: disk.idx }) : t("Diğer birimler")}</span>
            {disk ? <span className="text-xs text-muted-foreground sm:hidden">{diskKind(disk)}</span> : null}
          </span>
        </TableCell>
        <TableCell className="hidden text-sm whitespace-normal text-muted-foreground sm:table-cell">{disk ? diskKind(disk) : ""}</TableCell>
        <TableCell className="text-sm whitespace-nowrap">{disk ? size(disk.size) || "-" : ""}</TableCell>
      </TableRow>
      {volumes.map((v) => (
        <TableRow key={`${v.mount}-${v.disk}`}>
          <TableCell className="min-w-40 whitespace-normal">
            <span className="flex flex-col gap-1 pl-3">
              <span className="flex flex-wrap items-center gap-1.5">
                <span className="font-mono text-sm break-all">{v.mount}</span>
                {v.enc === "on" ? <SettingBadge tone="success">{t("Şifreli")}</SettingBadge> : null}
                {v.enc === "off" ? <SettingBadge>{t("Şifresiz")}</SettingBadge> : null}
                {v.removable ? <SettingBadge>{t("Çıkarılabilir")}</SettingBadge> : null}
              </span>
              {v.fs ? <span className="text-xs text-muted-foreground sm:hidden">{v.fs}</span> : null}
            </span>
          </TableCell>
          <TableCell className="hidden text-sm text-muted-foreground sm:table-cell">{v.fs || "-"}</TableCell>
          <TableCell className="min-w-40">
            {v.size ? <UsageBar label={t("{size} boş", { size: size(v.free) || "0 B" })} used={v.size - (v.free ?? 0)} total={v.size} /> : "-"}
          </TableCell>
        </TableRow>
      ))}
    </>
  )
}

function linkSpeed(mbit?: number): string {
  if (!mbit || mbit <= 0) return ""
  return mbit >= 1000 ? `${decimal(mbit / 1000)} Gbit/s` : `${formatNumber(mbit)} Mbit/s`
}

function NICsSection({ nics }: { nics: InventoryNIC[] }) {
  const { t } = useI18n()
  return (
    <DetailSection
      id="ag-kartlari"
      title={t("Ağ kartları")}
      description={t("Yerel adresler ve bağlantı hızı; donanım adresleri ve Wi-Fi ağ adları gönderilmez.")}
      framed={false}
    >
      {nics.length === 0 ? (
        <EmptyNote>{t("Ağ kartı bilgisi okunamadı.")}</EmptyNote>
      ) : (
        <ListTable label={t("Ağ kartları")}>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className={headCell}>{t("Ad")}</TableHead>
              <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Tür")}</TableHead>
              <TableHead className={cn(headCell, "hidden md:table-cell")}>{t("Hız")}</TableHead>
              <TableHead className={headCell}>{t("Yerel adresler")}</TableHead>
              <TableHead className={cn(headCell, "hidden sm:table-cell")}>{t("Sinyal")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {nics.map((n, i) => (
              <NICRow key={`${n.name ?? ""}-${i}`} nic={n} />
            ))}
          </TableBody>
        </ListTable>
      )}
    </DetailSection>
  )
}

function NICRow({ nic: n }: { nic: InventoryNIC }) {
  const { t } = useI18n()
  const kind = [n.type ? t(nicTypes[n.type] ?? n.type) : "", n.wifi_std ?? ""].filter(Boolean).join(" · ")
  const addrs = [...(n.ipv4 ?? []), ...(n.ipv6 ?? [])]
  return (
    <TableRow>
      <TableCell className="min-w-40 whitespace-normal">
        <span className="flex flex-col gap-0.5">
          <span className="flex flex-wrap items-center gap-1.5">
            <span className="text-sm font-medium break-words">{n.name || n.model || t("Bağdaştırıcı")}</span>
            {n.gw ? <SettingBadge>{t("Varsayılan yol")}</SettingBadge> : null}
            {n.up ? null : <SettingBadge>{t("Bağlı değil")}</SettingBadge>}
          </span>
          {n.model && n.model !== n.name ? <span className="text-xs text-muted-foreground break-words">{n.model}</span> : null}
          <span className="text-xs text-muted-foreground sm:hidden">
            {[kind, linkSpeed(n.speed), n.signal ? t("sinyal {pct}", { pct: formatPercent(n.signal) }) : ""].filter(Boolean).join(" · ")}
          </span>
        </span>
      </TableCell>
      <TableCell className="hidden text-sm whitespace-normal sm:table-cell">{kind || "-"}</TableCell>
      <TableCell className="hidden text-sm whitespace-nowrap md:table-cell">{linkSpeed(n.speed) || "-"}</TableCell>
      <TableCell className="min-w-36 whitespace-normal">
        {addrs.length === 0 ? (
          <span className="text-sm text-muted-foreground">-</span>
        ) : (
          <ul className="flex flex-col gap-0.5">
            {addrs.map((a) => (
              <li key={a} className="font-mono text-xs break-all">
                {a}
              </li>
            ))}
          </ul>
        )}
      </TableCell>
      <TableCell className="hidden text-sm sm:table-cell">{n.signal ? <Meter label={t("Wi-Fi sinyali")} percent={n.signal} low={30} /> : "-"}</TableCell>
    </TableRow>
  )
}

function Meter({ label, percent, low }: { label: string; percent: number; low: number }) {
  const pct = Math.min(100, Math.max(0, Math.round(percent)))
  return (
    <span className="flex items-center gap-2">
      <span
        className="h-1.5 w-16 overflow-hidden rounded-full bg-muted"
        role="meter"
        aria-label={label}
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <span className={cn("block h-full rounded-full", pct <= low ? "bg-warning" : "bg-foreground/70")} style={{ width: `${pct}%` }} />
      </span>
      <span className="font-mono text-xs">{formatPercent(pct)}</span>
    </span>
  )
}

function BatterySection({ detail }: { detail: Inventory }) {
  const { t } = useI18n()
  const b = detail.bat
  if (!b) return null
  return (
    <DetailSection id="pil" title={t("Pil")} framed={false}>
      <div className="rounded-lg border p-4 md:p-6">
        <DetailGroup>
          <DetailItem label={t("Şarj")}>
            <Meter label={t("Pil şarjı")} percent={b.pct} low={15} />
          </DetailItem>
          <Item label={t("Durum")} value={b.state ? t(batteryStates[b.state] ?? b.state) : ""} />
          <Item
            label={t("Sağlık")}
            value={
              b.health ? (
                <>
                  {b.health < 70 ? <SettingBadge tone="warning">{formatPercent(b.health)}</SettingBadge> : <span>{formatPercent(b.health)}</span>}
                  {b.full_mwh && b.design_mwh ? (
                    <span className="text-xs text-muted-foreground">
                      {decimal(b.full_mwh / 1000)} / {decimal(b.design_mwh / 1000)} Wh
                    </span>
                  ) : null}
                </>
              ) : (
                ""
              )
            }
          />
          <Item label={t("Şarj döngüsü")} value={b.cycles ? String(b.cycles) : ""} />
        </DetailGroup>
      </div>
    </DetailSection>
  )
}

function DisplaysSection({ detail }: { detail: Inventory }) {
  const { t } = useI18n()
  const list = detail.displays ?? []
  return (
    <DetailSection
      id="ekranlar"
      title={t("Ekranlar")}
      description={t("Bağlı monitörlerin doğal çözünürlüğü; o anki ekran modu olmayabilir.")}
    >
      {list.map((m, i) => (
        <div key={`${m.name ?? ""}-${i}`} className="flex flex-col gap-0.5 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
          <span className="text-sm font-medium break-words">{m.name || t("Ekran {n}", { n: i + 1 })}</span>
          <span className="font-mono text-sm text-muted-foreground">
            {m.w > 0 && m.h > 0 ? `${m.w} × ${m.h}` : t("Bilinmiyor")}
            {m.hz ? ` · ${m.hz} Hz` : ""}
          </span>
        </div>
      ))}
    </DetailSection>
  )
}

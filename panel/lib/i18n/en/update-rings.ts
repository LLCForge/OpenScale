// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.
//
// Phase 5: update rings (#827, ADR-0235) on the automatic update card
// (about/update-rings-row.tsx, about/auto-update-section.tsx) and the ring
// hint of the device tags dialog.

export const enUpdateRings: Record<string, string> = {
  canary: "canary",
  early: "early",
  main: "main",
  "Halka sırası bekleniyor": "Waiting for its ring",
  "Sürüm durduruldu": "Release halted",
  "Güncelleme halkası": "Update ring",
  "Bu cihaz {ring} halkasında. Halka cihazın imzalı etiketinden gelir: ring-canary önce, ring-early sonra kurar; etiketsiz cihazlar main halkasındadır.":
    "This device is in the {ring} ring. The ring comes from the device's signed tag: ring-canary installs first, ring-early next; devices without one are in the main ring.",
  "Koordinatöre göre açık halka: {ring}": "Open ring according to the coordinator: {ring}",
  "Koordinatör halka ilerlemesi göndermiyor (eski sürüm); bu cihaz yalnızca kendi bekleme süresini uygular.":
    "The coordinator sends no ring progress (older version); this device only applies its own waiting time.",
  "Bekleme süreleri: canary → early {canary} sa, early → main {early} sa": "Waiting times: canary → early {canary} h, early → main {early} h",
  "Bu cihazın kendi bekleme sınırı: {when}": "This device's own earliest install time: {when}",
  "{ring}: üye {members} · yeni sürümde {updated} · sağlıklı {healthy} · geri dönen {rolledBack}":
    "{ring}: members {members} · on the new version {updated} · healthy {healthy} · rolled back {rolledBack}",
  "Sürüm otomatik olarak durduruldu": "The release was halted automatically",
  "{ring} halkasındaki bir cihaz yeni sürümde sağlıklı başlamadı ve önceki sürüme döndü. Henüz kurmamış cihazlar beklemede. Sahip sorunu inceleyip koordinatör sunucusunda openscale update rings resume ile sürdürebilir ya da düzeltilmiş bir sürüm yayımlayabilir.":
    "A device in the {ring} ring did not start healthily on the new version and went back to the previous one. Devices that have not installed it yet are waiting. The owner can look into it and resume with openscale update rings resume on the coordinator server, or publish a fixed release.",
  "Güncelleme halkası da etiketle seçilir: ring-canary yeni sürümü ilk kurar, ring-early canary cihazlar sorunsuz çalışınca, etiketsiz cihazlar (main) en son. Durum: Hakkında > Otomatik güncelleme.":
    "The update ring is chosen with a tag too: ring-canary installs a new release first, ring-early once the canary devices run it without problems, devices without one (main) last. Status: About > Automatic updates.",
}

// English texts (#224), keyed by the Turkish source text. See lib/i18n/i18n.tsx.
//
// Phase 3: desktop, files and remote sessions (#855 SFTP browser, #120
// monitor picker, #853 second viewer). Server texts of
// internal/panel/f3_sftp_api.go and w1_rdesk_viewer.go are listed too, so
// ts() shows them in English.

export const enF3Desktop: Record<string, string> = {
  // SSH dialog tabs and file browser (terminal/f3-*.tsx)
  Terminal: "Terminal",
  "Dosyaları aç": "Open files",
  "Dosyalar terminalle aynı hesap ve aynı kayıtlı sunucu anahtarıyla açılır.": "Files open with the terminal's account and the same pinned server key.",
  "Üst klasör": "Parent folder",
  "Ev klasörü": "Home folder",
  Yükle: "Upload",
  "Yeni klasör adı": "New folder name",
  "Klasör oluştur": "Create folder",
  Değiştirilme: "Modified",
  "(bağlantı)": "(link)",
  "{name} indir": "Download {name}",
  "{name} sil": "Delete {name}",
  "Klasör boş": "The folder is empty",
  "Dosya yükleyebilir veya klasör oluşturabilirsiniz.": "You can upload files or create a folder.",
  "Klasörde çok fazla girdi var; ilk 10.000 gösteriliyor.": "The folder has too many entries; the first 10,000 are shown.",
  "Dosya silinsin mi?": "Delete the file?",
  "Klasör silinsin mi?": "Delete the folder?",
  "{path} cihazdan kalıcı olarak silinir. Klasörler yalnızca boşken silinebilir.":
    "{path} is deleted from the device for good. Folders can only be deleted when they are empty.",
  "Yüklendi.": "Uploaded.",
  "İndirildi. Dosya bu bilgisayarda karantinada; açmadan önce Gelen Dosyalar sayfasından serbest bırakın.":
    "Downloaded. The file is in quarantine on this computer; release it on the Received Files page before opening it.",
  "İndirildi ve Gelen Dosyalar sayfasına kondu; işletim sistemi işareti eklenemedi, açarken dikkatli olun.":
    "Downloaded to the Received Files page; the operating system mark could not be added, so be careful when opening it.",
  "Ad geçersiz: tek bir ad yazın; / ve .. kullanılamaz.": "Invalid name: type a single name; / and .. cannot be used.",
  "Cihazın SSH sunucusunda SFTP açık değil.": "SFTP is not enabled on the device's SSH server.",
  "Çok fazla açık dosya oturumu; birini kapatıp yeniden deneyin.": "Too many open file sessions; close one and try again.",
  "Dosya oturumu kapandı; yeniden bağlanın.": "The file session closed; connect again.",
  "Dosya veya klasör bulunamadı.": "File or folder not found.",
  "Bu hesabın bu işleme izni yok.": "This account is not allowed to do that.",
  "Dosya çok büyük (en çok 2 GiB).": "The file is too large (at most 2 GiB).",
  "Yol geçersiz.": "Invalid path.",
  "Öğe değişmiş; listeyi yenileyip yeniden deneyin.": "The item changed; refresh the list and try again.",
  "Yalnızca normal dosyalar indirilebilir.": "Only normal files can be downloaded.",
  "Cihaz zamanında yanıt vermedi.": "The device did not answer in time.",
  "İşlem tamamlanamadı; bağlantı kopmuş olabilir.": "The operation did not complete; the connection may have dropped.",

  // Server texts of the file browser (internal/panel/f3_sftp_api.go)
  "Cihaz, port, kullanıcı adı veya parola geçersiz.": "Invalid device, port, user name or password.",
  "Dosya oturumu yok veya süresi doldu; yeniden bağlanın.": "No file session, or it expired; connect again.",
  "Cihaz işlemi yapamadı (zaten var, klasör boş değil veya desteklenmiyor olabilir).":
    "The device could not do it (it may already exist, the folder may not be empty or it is not supported).",
  "Bu bilgisayarda karantina klasörü yok; dosya indirilemez.": "This computer has no quarantine folder; the file cannot be downloaded.",
  "Dosya bu bilgisayara yazılamadı.": "The file could not be written on this computer.",
  "Dosya adı veya klasör geçersiz.": "Invalid file name or folder.",
  "Klasör adı geçersiz.": "Invalid folder name.",
  "Klasörde çok fazla girdi var.": "The folder has too many entries.",

  // Remote desktop viewer: monitors and the second viewer (rdesk/*.tsx)
  "Monitör seçimi": "Monitor choice",
  "Monitör {n}": "Monitor {n}",
  "Monitör {n} (birincil)": "Monitor {n} (primary)",
  "Tüm monitörler": "All monitors",
  "Bu cihazı başka bir yönetici denetliyor. İzleyici olarak katılmak için yeniden bağlanın; ayrı bir doğrulama kodu alırsınız.":
    "Another administrator controls this device. Connect again to join as a viewer; you get your own verification code.",
  "Monitör seçimi geçersiz.": "Invalid monitor choice.",
  "Bu cihazı başka bir yönetici denetliyor; yalnızca izleyici olarak katılabilirsiniz.":
    "Another administrator controls this device; you can only join as a viewer.",
}

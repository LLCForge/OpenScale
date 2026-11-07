# VPS için cloud-init (#480, ADR-0153)

Bu klasörde hazır bir `user-data` yoktur: dosya her kurulum için yönetici
bilgisayarda üretilir, çünkü içine o sürümün imzalı manifestosundan okunan
paket özeti, sahibin SSH anahtarı ve (çıkış düğümünde) ön onaylı kayıt
anahtarı yazılır.

```bash
openscale server cloud-init --role coordinator --hostname vpn \
  --manifest openscale-<sürüm>.release.json \
  --package-url https://<sizin-sunucunuz>/openscale_<sürüm>_amd64.deb \
  --ssh-key @~/.ssh/id_ed25519.pub --out user-data
```

Üretilen dosya:

- paketi verilen https adresinden indirir, boyutunu ve SHA-256 özetini
  manifestoyla karşılaştırır; eşleşmezse hiçbir şey kurmaz;
- yalnızca anahtarla SSH (`PasswordAuthentication no`, `PermitRootLogin no`),
  otomatik güvenlik güncellemeleri ve varsayılan reddeden nftables kuralları
  (`deploy/linux/nftables.conf`) yazar;
- koordinatörde anahtarı üretip parmak izini konsola ve
  `/root/openscale-coordinator.txt` dosyasına yazar (koordinatörü belgeye
  sahip imzalar: `network set-coordinator` veya `network coordinator add`);
- çıkış düğümünde `preauth-join` ile katılır ve kayıt anahtarını siler;
- sonunda `openscale server audit` çıktısını `/root/openscale-audit.txt`
  dosyasına yazar.

Sağlayıcı API'si kullanılmaz; Debian 12/13 ve Ubuntu 22.04+ bulut imajları
için yazılmıştır. Gerçek bir VPS sağlayıcısında henüz denenmemiştir.

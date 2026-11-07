# Koordinatör için salt okunur minimal imaj (mkosi)

Bu tarif #636 ve ADR-0184 kapsamındadır. İmajda yalnızca çekirdek, systemd ve statik `openscale` ikilisi bulunur.

- **Çalışma anında yok:** paket yöneticisi, kabuk girişi, SSH sunucusu.
- **Kök dosya sistemi:** salt okunur (`ro`).
- **`/var`:** tmpfs (`systemd.volatile=state`).
- **Koordinatör:** RAM kipinde çalışır (ADR-0182). Belge geçmişi, aktarıcı kullanımı ve nesneler diske hiç yazılmaz.

## Derleme

```sh
CGO_ENABLED=0 go build -trimpath -o openscale-linux-amd64 ./cmd/openscale
openscale releaseverify ...          # imzalı manifestoyla doğrulayın
sh hazirla.sh ./openscale-linux-amd64
mkosi build
```

## İlk açılış

Tohum dosyaları imaja konmaz:
- `anchor.json`, `network.json`, `state.json` ve `coordinator-hardening.json` (`ram_only: true`) sunucuya ayrı bir diskten veya sağlayıcının kimlik bilgisi (credential) mekanizmasıyla verilir.
- `coordinator.key`, TPM'e mühürlü bir systemd kimlik bilgisi (`systemd-creds encrypt --with-key=tpm2`) olarak verilir.

Ayrıntılar `deploy/linux/openscale-coordinator-ram.conf` dosyasındadır.

## Güncelleme

İmaj değişmez. Yeni sürüm için yeni imaj üretilir ve sunucu yeni imajla açılır. Belge, cihazlardan geri gelir.

## Sınırlar

- İmaj içinde SSH olmadığı için sorun giderme sağlayıcı konsolundan yapılır.
- Bu tarif gerçek bir mkosi sürümüyle derlenmedi. Ayar adları mkosi belgesine göre yazıldı. Kullandığınız mkosi sürümünün belgesiyle karşılaştırın.
- Doğrulanmış önyükleme (dm-verity, Secure Boot imzası) bu tarifte yok. Sağlayıcı imajı değiştirebilir; `openscale server provider-check` değişen çekirdek ve komut satırını raporlar.

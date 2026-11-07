# Koordinatör sunucusunda şifreli disk ve tünelden kilit açma

Bu rehber, #634 ve ADR-0184 kapsamındadır. Bir VPS'te kök diski LUKS ile şifrelemeyi anlatır. Açılışta disk parolası seri konsoldan değil, initramfs içindeki küçük bir SSH sunucusu (dropbear) üzerinden girilir. Bu SSH sunucusuna da yalnızca OpenScale tünelinden ulaşılır.

`openscale server audit` komutu sonucu "Şifreli disk ve tünelden kilit açma" satırında denetler. Denetim yalnızca okur.

> **Önce okuyun:** Bu işlemler sunucunun açılışını değiştirir. Yanlış bir adımda sunucu açılmaz ve yalnızca sağlayıcının konsolundan kurtarılabilir. Her adımı önce bir deneme sunucusunda yapın. Sağlayıcının seri/VNC konsoluna erişiminiz olduğundan emin olun.

## Neye karşı korur, neye karşı korumaz

- **Korur:**
  - Sağlayıcının disk görüntüsünü veya yedeğini kopyalaması.
  - Diskin el konulup çevrimdışı okunması.
  - Kapalı sunucunun incelenmesi.
- **Korumaz:**
  - Çalışan sunucunun belleğinden anahtar çekilmesi. Sağlayıcı hipervizörden belleği okuyabilir.
  - Açılışta değiştirilmiş bir initramfs ile parolanın yakalanması. Bu yüzden kilit açmadan önce `openscale server provider-check` çalıştırın: yeni çekirdek, değişen komut satırı veya beklenmeyen yeniden başlatma bir uyarı işaretidir.
- **Ek koruma:** Koordinatör güvenilmez tasarlanmıştır (ADR-0003). Disk şifrelemesi ek bir katmandır, güven modelinin parçası değildir.

## 1. Kurulumda LUKS

Sağlayıcı kurulum görüntüsünde "şifreli LVM" (Debian kurucusu: *Guided - use entire disk and set up encrypted LVM*) seçin. Var olan şifresiz bir sunucuyu yerinde şifrelemek yerine yeni sunucu kurup koordinatörü taşıyın (`openscale coordinator preflight`, ADR-0153).

## 2. dropbear-initramfs

```sh
apt install dropbear-initramfs
```

Kilit açacak anahtarı ekleyin. Anahtara yalnızca kilit açma izni verin:

```sh
echo 'no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="/usr/bin/cryptroot-unlock" ssh-ed25519 AAAA... sahip' \
  > /etc/dropbear/initramfs/authorized_keys
chmod 600 /etc/dropbear/initramfs/authorized_keys
```

Eski Debian/Ubuntu sürümlerinde yol `/etc/dropbear-initramfs/` olur.

`/etc/dropbear/initramfs/dropbear.conf` içine şunu yazın:

```sh
DROPBEAR_OPTIONS="-s -j -k -p 100.64.0.9:2222 -c cryptroot-unlock"
```

Bayrakların anlamı:
- `-s`: parola girişi kapalı.
- `-j -k`: yönlendirme kapalı.
- `-p 100.64.0.9:2222`: yalnızca tünel adresinde, 2222 portunda dinler. Adresi kendi sunucunuzun tünel adresiyle değiştirin.
- `-c`: oturum yalnızca kilit açma komutunu çalıştırır.

## 3. Açılışta tünel (WireGuard initramfs içinde)

dropbear'ın tünel adresinde dinleyebilmesi için tünelin initramfs içinde kurulması gerekir. Bunun için WireGuard'ı initramfs'e ekleyen bir kanca kullanılır. Örneğin `wireguard-initramfs` projesi; kurulumu kendi belgesine göre yapın, OpenScale bu kancayı indirmez ve kurmaz.

Kanca için kurallar:
- Bu sunucuya **ayrı bir cihaz kimliği** verin, ör. `koordinator-kilit` adında bir cihaz. Böylece initramfs'teki anahtar ele geçse bile yalnızca bu cihaz iptal edilir (`openscale device remove`).
- Bu cihaza kurallarla yalnızca yönetici cihazınızdan 2222/tcp izni verin.
- Kanca, imzalı belgedeki koordinatör uç noktasına doğrudan bağlanır. Kilit açılmadan koordinatör çalışmaz; bu nedenle initramfs'teki tünel **ek bir koordinatör** veya bir çıkış düğümü üzerinden kurulmalıdır. Birden çok koordinatör için: `network coordinator add`.

Yapılandırma bitince initramfs'i yeniden üretin:

```sh
update-initramfs -u
```

Kancayı kurmayacaksanız dropbear'ı genel adreste bırakmak yerine sağlayıcının güvenlik duvarında 2222/tcp'yi yalnızca kendi IP'nize açın. Denetim bu durumu "UYARI" olarak gösterir.

## 4. Kilit açma

Yönetici cihazdan (tünel açıkken):

```sh
ssh -p 2222 root@100.64.0.9
```

Komut doğrudan disk parolasını sorar. Parola doğruysa açılış sürer ve koordinatör kendiliğinden başlar.

## 5. Denetim

```sh
openscale server audit --role coordinator
openscale server provider-check
```

Beklenen sonuç: "Kök disk LUKS ile şifreli; kilit yalnızca anahtarla, yönlendirmesiz dropbear üzerinden açılıyor. Açılışta WireGuard tüneli kuruluyor."

## Geri dönüş

- `apt remove dropbear-initramfs && update-initramfs -u` ile uzaktan kilit açma kaldırılır.
- Disk şifreli kalır ve parola seri konsoldan girilir.

## Denenmedi

Bu rehber gerçek bir VPS'te ve gerçek bir initramfs WireGuard kancasıyla denenmedi. Denetim kodu yalnızca örnek dosya sistemleriyle test edildi.

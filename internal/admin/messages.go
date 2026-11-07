package admin

import (
	"errors"
	"fmt"
	"os"

	"github.com/openscale/openscale/internal/trust"
)

// Describe turns well-known errors into Turkish messages for the CLI and the
// panel. Unknown errors are returned as-is; they never contain secrets
// because no error in this code base wraps a passphrase or private key.
func Describe(err error) string {
	// Root rotation and membership errors (ADR-0027, ADR-0028).
	if msg, ok := describeMembership(err); ok {
		return msg
	}
	if msg, ok := describeP01(err); ok { // ADR-0151, p01.go
		return msg
	}
	messages := []struct {
		target error
		text   string
	}{
		{trust.ErrWrongPassphrase, "Parola yanlış veya kök anahtar dosyası bozulmuş."},
		{trust.ErrGuessablePassphrase, "Parola kolay tahmin edilir: yaygın kelime, klavye dizisi (qwerty, 1234), yıl veya tekrar içeriyor. Birbiriyle ilgisiz dört beş kelime veya rastgele karakterler seçin."},
		{trust.ErrUnsupportedAlgorithm, "Bu veri bu sürümün tanımadığı bir imza algoritmasıyla imzalanmış; OpenScale'i güncelleyin."},
		{trust.ErrRandomUnhealthy, "İşletim sisteminin rastgele sayı üreteci sağlık denetiminden geçemedi; güvenlik için anahtar üretilmedi."},
		{ErrSASMismatch, "Kısa doğrulama kodları eşleşmiyor; kayıt isteği değiştirilmiş olabilir, cihaz eklenmedi."},
		{ErrKDFCurrent, "Kök anahtar zaten bu veya daha güçlü Argon2id ayarlarını kullanıyor."},
		{trust.ErrWeakPassphrase, fmt.Sprintf("Parola en az %d karakter olmalı ve tekrar eden birkaç karakterden oluşmamalı.", trust.MinPassphraseLength)},
		{trust.ErrBadSignature, "İmza doğrulanamadı; dosya değiştirilmiş veya başka bir ağa ait."},
		{trust.ErrWrongContext, "Bu veri başka bir amaç için imzalanmış."},
		{trust.ErrEnrollmentExpired, "Kayıt isteğinin süresi geçmiş; yeni cihazda tekrar 'openscale keygen' çalıştırın."},
		{trust.ErrNameTaken, "Bu cihaz adı zaten kullanılıyor."},
		{trust.ErrRevokedKey, "Bu cihazın anahtarları daha önce iptal edilmiş; yeni cihazda yeni anahtar üretin."},
		{trust.ErrUnknownDevice, "Cihaz bulunamadı."},
		{trust.ErrAddressSpaceFull, "Ağdaki IP adresleri tükendi."},
		{ErrNetworkExists, "Bu klasörde zaten bir ağ var."},
		{ErrConcurrentChange, "Ağ belgesi başka bir yerden (ör. CLI) değiştirildi. Sayfayı yenileyip tekrar deneyin."},
		{ErrSamePassphrase, "Yeni parola mevcut paroladan farklı olmalı."},
		{ErrBackupKeyMismatch, "Bu yedek bu ağa ait değil."},
		{ErrHistoryVersionUsed, "Bu sürüm geçmişte zaten var; belge başka bir yerden değiştirilmiş olabilir."},
		{ErrDuplicateRequest, "Bu kayıt isteği zaten kullanılmış; cihaz ağda kayıtlı."},
		{ErrFingerprintMismatch, "Parmak izleri eşleşmiyor; kayıt isteği değiştirilmiş olabilir, cihaz eklenmedi."},
		{trust.ErrRootFingerprintMismatch, "Kök anahtar parmak izi eşleşmiyor; paket başka bir ağa ait veya yolda değiştirilmiş. Yönetici ekranındaki parmak izini kontrol et."},
		{trust.ErrExpired, "Ağ belgesinin süresi dolmuş; yöneticinin belgeyi yenilemesi gerekiyor."},
		{trust.ErrRollback, "Bu belge mevcut olandan daha eski; kabul edilmedi."},
		{trust.ErrEquivocation, "Aynı sürüm numarasıyla farklı bir belge görüldü; kök anahtar kötüye kullanılmış olabilir."},
		{trust.ErrInviteNotFound, "Davet bulunamadı; iptal edilmiş veya süresi dolmuş olabilir."},
		{trust.ErrInviteExpired, "Davetin süresi dolmuş; yeni bir davet oluşturun."},
		{trust.ErrInviteUsed, "Bu davet zaten kullanıldı; yeni bir davet oluşturun."},
		{trust.ErrNameReserved, "Bu ad koordinatöre ayrılmış; başka bir ad seçin."},
		{trust.ErrInvalidName, "Cihaz adı yalnızca küçük harf, rakam ve tire içerebilir (en fazla 63 karakter)."},
		{trust.ErrSameName, "Yeni ad mevcut adla aynı."},
		{trust.ErrInvalidLifetime, "Üyelik süresi 1 saniye ile 3650 gün arasında olmalı."},
		{trust.ErrGroupNotFound, "Grup bulunamadı."},
		{trust.ErrRotationStale, "Anahtar yenileme isteği cihazın güncel anahtarlarıyla eşleşmiyor; istek zaten uygulanmış veya eskimiş."},
		{trust.ErrRotationExpired, "Anahtar yenileme isteğinin süresi geçmiş; cihazda yeni bir istek oluşturun."},
		{trust.ErrKeyInUse, "Bu anahtar ağda zaten kullanılıyor."},
		{trust.ErrWrongNetwork, "Bu veri başka bir ağa ait."},
		{trust.ErrInvalidDisplayName, "Ağ adı 1-64 karakter olmalı; kontrol karakteri ve baştaki/sondaki boşluk kullanılamaz."},
		{os.ErrNotExist, "Dosya bulunamadı."},
	}
	for _, m := range messages {
		if errors.Is(err, m.target) {
			return m.text
		}
	}
	return err.Error()
}

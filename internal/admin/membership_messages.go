package admin

import (
	"errors"

	"github.com/openscale/openscale/internal/trust"
)

// describeMembership turns the errors of root rotation and the membership
// extensions into Turkish messages (ADR-0027, ADR-0028).
func describeMembership(err error) (string, bool) {
	messages := []struct {
		target error
		text   string
	}{
		{trust.ErrEpochMismatch, "Belge başka bir kök anahtar dönemine ait; önce kök anahtar geçişinin uygulanması gerekiyor."},
		{trust.ErrRecoveryKeysChanged, "Kurtarma anahtarları yalnızca bir kurtarma anahtarının imzaladığı kök geçişiyle değişebilir; belge reddedildi."},
		{trust.ErrTransitionStale, "Kök anahtar geçişi bu üyenin belgesinden sonra imzalanmış başka bir belgeyle çelişiyor; kök anahtar kötüye kullanılmış olabilir, kurtarma anahtarıyla kurtarın."},
		{trust.ErrRootRevoked, "Bu kök anahtar daha önceki bir geçişle iptal edilmiş."},
		{trust.ErrNoTransition, "Uygulanabilir bir kök anahtar geçişi bulunamadı."},
		{ErrRecoveryKeyUnknown, "Bu kurtarma anahtarı ağ belgesinde yayımlanmamış."},
		{ErrRecoveryPassphrase, "Kurtarma anahtarının parolası kök anahtar parolasından farklı olmalı."},
		{ErrNotRecoveryKey, "Bu dosya bir OpenScale kurtarma anahtarı değil."},
		{ErrLastGoodUnavailable, "Seçilen son güvenilir sürüm geçmişte bulunamadı veya doğrulanamadı."},
		{trust.ErrInvalidClientVersion, "Sürüm 1.2.3 biçiminde olmalı."},
		{trust.ErrPreauthExpired, "Ön onaylı cihazın üyeliği dolmuş; yeni bir kayıt anahtarı oluşturun."},
		{trust.ErrNotPreauthorized, "Bu kayıt anahtarının cihazı belgede ön onaylı olarak kayıtlı değil."},
		{trust.ErrLeaveExpired, "Ayrılma isteğinin süresi geçmiş."},
		{trust.ErrEphemeralLifetime, "Geçici bir cihazın üyeliği en fazla 30 gün olabilir."},
		{ErrInvalidNote, "Davet açıklaması en fazla 120 karakter olabilir ve kontrol karakteri içeremez."},
		{ErrPendingRejected, "Bu katılım isteği reddedildi."},
		// ADR-0232 (f4a_icon.go).
		{trust.ErrUnknownIcon, "Cihaz simgesi tanınmıyor; laptop, desktop, phone, tablet, server, nas, printer, camera, tv, router veya other olmalı."},
		{trust.ErrSchemaNeedsClients, "Bu belge eski istemcilerin reddettiği alanlar kullanıyor; asgari istemci sürümü en az 1.0.0-beta.2 olmalı."},
	}
	for _, m := range messages {
		if errors.Is(err, m.target) {
			return m.text, true
		}
	}
	return "", false
}

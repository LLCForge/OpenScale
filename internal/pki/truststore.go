package pki

// TrustStoreSteps returns the commands that add the CA certificate at path
// to a system or browser trust store, for the person to run. OpenScale
// never changes a trust store itself (ADR-0138): trusting a CA is the
// owner's decision on each computer, and the name constraints limit what
// the CA can vouch for.
func TrustStoreSteps(goos, path string) []string {
	q := `"` + path + `"`
	switch goos {
	case "windows":
		return []string{
			"Yalnızca bu kullanıcı için: certutil -user -addstore Root " + q,
			"Bütün kullanıcılar için (yönetici): certutil -addstore Root " + q,
			"Kaldırmak için: certutil -user -delstore Root <seri numarası>",
		}
	case "darwin":
		return []string{
			"security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db " + q,
			"Kaldırmak için: Anahtar Zinciri Erişimi'nde sertifikayı silin",
		}
	case "linux":
		return []string{
			"Debian/Ubuntu: sudo cp " + q + " /usr/local/share/ca-certificates/openscale-ic-ca.crt && sudo update-ca-certificates",
			"Fedora/RHEL: sudo cp " + q + " /etc/pki/ca-trust/source/anchors/openscale-ic-ca.crt && sudo update-ca-trust",
			"Kaldırmak için dosyayı silip aynı güncelleme komutunu çalıştırın",
		}
	case "android":
		return []string{"Ayarlar > Güvenlik > Şifreleme ve kimlik bilgileri > Sertifika yükle > CA sertifikası"}
	}
	return []string{"Sertifikayı işletim sisteminin güvenilen kök sertifikalarına elle ekleyin"}
}

// BrowserNote explains browsers with their own store.
const BrowserNote = "Firefox kendi deposunu kullanır: Ayarlar > Gizlilik ve Güvenlik > Sertifikaları göster > Yetkililer > İçe aktar (yalnızca \"web sitelerini tanımlamak için\" seçin)."

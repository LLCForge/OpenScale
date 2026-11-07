package service

import (
	"errors"
	"fmt"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/piv"
	"github.com/openscale/openscale/internal/tpm"
)

// HardwareKeys implements panel.HardwareApp: what the operating system
// reports about a TPM (ADR-0124) and smart card readers for PIV keys
// (ADR-0123). Both are read only; nothing is sent to the TPM or a token.
func (r *Runtime) HardwareKeys() panel.HardwareKeys {
	out := panel.HardwareKeys{PIV: []string{}}
	p, err := tpm.Detect()
	switch {
	case errors.Is(err, tpm.ErrUnsupported):
		out.TPM, out.TPMNote = "desteklenmiyor", "Bu sistemde TPM okuma uygulanmadı."
	case err != nil || !p.Present:
		out.TPM, out.TPMNote = "yok", "İşletim sistemi bir TPM bildirmiyor."
	default:
		out.TPM = "TPM " + p.Version
		out.TPMNote = fmt.Sprintf("Arayüz: %s. Cihaz anahtarı TPM'e taşınmadı (ADR-0124: yalnızca okuma).", p.Interface)
	}
	readers, err := piv.Readers()
	switch {
	case errors.Is(err, piv.ErrUnsupported):
		out.PIVNote = "Bu sistemde akıllı kart okuma uygulanmadı."
	case err != nil:
		out.PIVNote = "Akıllı kart okuyucuları listelenemedi."
	case len(readers) == 0:
		out.PIVNote = "Takılı akıllı kart veya güvenlik anahtarı yok."
	default:
		out.PIV = append(out.PIV, readers...)
		out.PIVNote = "PIV desteği gerçek donanımda denenmedi; kök anahtarı taşımadan önce kâğıt yedeğin olduğundan emin ol."
	}
	if len(out.PIV) > 8 {
		out.PIV = out.PIV[:8]
	}
	return out
}

var _ panel.HardwareApp = (*Runtime)(nil)

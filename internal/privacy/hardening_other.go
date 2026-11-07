//go:build !unix && !windows

package privacy

// hardenProcess has nothing to apply on platforms without core dumps
// (plan9, js/wasm).
func hardenProcess() HardeningStatus {
	return HardeningStatus{Warnings: []string{"bu platformda çökme dökümü denetimi yok"}}
}

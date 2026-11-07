//go:build unix && !linux

package privacy

import "golang.org/x/sys/unix"

// hardenProcess sets RLIMIT_CORE to zero (the BSDs, macOS and other Unix
// systems); there is no dumpable flag outside Linux.
func hardenProcess() HardeningStatus {
	var st HardeningStatus
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		st.Warnings = append(st.Warnings, "çekirdek dökümü sınırı sıfırlanamadı: "+err.Error())
		return st
	}
	st.CoreDumpsDisabled = true
	st.Measures = append(st.Measures, "RLIMIT_CORE=0 (çekirdek dökümü boyutu sıfır)")
	return st
}

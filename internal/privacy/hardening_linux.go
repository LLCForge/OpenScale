//go:build linux

package privacy

import (
	"golang.org/x/sys/unix"
)

// hardenProcess sets RLIMIT_CORE to zero and clears the dumpable flag.
// PR_SET_DUMPABLE=0 also keeps other processes of the same user from
// attaching with ptrace or reading /proc/<pid>/mem, and makes systemd-
// coredump (a core_pattern pipe, which ignores RLIMIT_CORE) skip the
// process.
func hardenProcess() HardeningStatus {
	var st HardeningStatus
	rlimitOK := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}) == nil
	if rlimitOK {
		st.Measures = append(st.Measures, "RLIMIT_CORE=0 (çekirdek dökümü boyutu sıfır)")
	} else {
		st.Warnings = append(st.Warnings, "RLIMIT_CORE sıfırlanamadı")
	}
	dumpableOK := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) == nil
	if dumpableOK {
		st.Measures = append(st.Measures, "PR_SET_DUMPABLE=0 (döküm ve aynı kullanıcıdan ptrace kapalı)")
	} else {
		st.Warnings = append(st.Warnings, "PR_SET_DUMPABLE kapatılamadı")
	}
	st.CoreDumpsDisabled = dumpableOK || rlimitOK
	return st
}

// dumpable reports the current PR_GET_DUMPABLE value (tests).
func dumpable() (int, error) {
	return unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
}

// coreLimit reports the current RLIMIT_CORE (tests).
func coreLimit() (uint64, uint64, error) {
	var r unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_CORE, &r)
	return r.Cur, r.Max, err
}

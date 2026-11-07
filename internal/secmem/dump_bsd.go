//go:build darwin || freebsd || netbsd || openbsd

package secmem

// excludeFromDump: there is no portable MADV_DONTDUMP here; the process
// hardening (ADR-0060) turns core dumps off instead.
func excludeFromDump([]byte) {}

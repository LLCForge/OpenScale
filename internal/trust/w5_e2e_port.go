package trust

// FilesE2EPort is the end-to-end encrypted file transfer port inside the
// tunnel (ADR-0204, p2psend.DefaultPort). It belongs to the files service:
// a files rule opens it next to FilesPort, so no new document field is
// needed. Devices older than 1.0.0-beta.1 never open it; for them the
// sender's "auto" route fails closed and the classic files path stays.
const FilesE2EPort uint16 = 4054

// opensE2EPort reports whether a rule for s also opens port for
// end-to-end transfers.
func (s RuleService) opensE2EPort(port uint16) bool {
	return s == ServiceFiles && port == FilesE2EPort
}

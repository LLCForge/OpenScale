package rdesk

// ParseRecordingKey reads a recording key in the format of the key file
// that LoadOrCreateRecordingKey writes. The Windows service reads the file
// (readable only by SYSTEM and administrators) and hands its contents to
// the desktop helper it starts in the user's session over an inherited
// pipe, so the helper never needs access to the service's data directory.
func ParseRecordingKey(data []byte) (*RecordingKey, error) { return parseRecordingKey(data) }

package rdesk

import "testing"

// FuzzParseRecordingKey feeds arbitrary bytes to the recording key parser
// (#654, ADR-0209); recordings and their keys can be copied between
// devices.
func FuzzParseRecordingKey(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseRecordingKey(data)
	})
}

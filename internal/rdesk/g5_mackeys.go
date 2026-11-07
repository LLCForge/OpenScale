package rdesk

// macKeyCodes maps USB HID keyboard usages (page 0x07) to macOS virtual
// key codes (Carbon kVK_* values) for the CGEvent injector (ADR-0202). It
// has no build constraint so it is tested on every platform.
var macKeyCodes = map[uint16]uint16{
	0x04: 0x00, 0x05: 0x0B, 0x06: 0x08, 0x07: 0x02, 0x08: 0x0E, 0x09: 0x03, // a b c d e f
	0x0a: 0x05, 0x0b: 0x04, 0x0c: 0x22, 0x0d: 0x26, 0x0e: 0x28, 0x0f: 0x25, // g h i j k l
	0x10: 0x2E, 0x11: 0x2D, 0x12: 0x1F, 0x13: 0x23, 0x14: 0x0C, 0x15: 0x0F, // m n o p q r
	0x16: 0x01, 0x17: 0x11, 0x18: 0x20, 0x19: 0x09, 0x1a: 0x0D, 0x1b: 0x07, // s t u v w x
	0x1c: 0x10, 0x1d: 0x06, // y z
	0x1e: 0x12, 0x1f: 0x13, 0x20: 0x14, 0x21: 0x15, 0x22: 0x17, // 1 2 3 4 5
	0x23: 0x16, 0x24: 0x1A, 0x25: 0x1C, 0x26: 0x19, 0x27: 0x1D, // 6 7 8 9 0
	0x28: 0x24,                                                             // Return
	0x29: 0x35,                                                             // Escape
	0x2a: 0x33,                                                             // Backspace (kVK_Delete)
	0x2b: 0x30,                                                             // Tab
	0x2c: 0x31,                                                             // Space
	0x2d: 0x1B,                                                             // -
	0x2e: 0x18,                                                             // =
	0x2f: 0x21,                                                             // [
	0x30: 0x1E,                                                             // ]
	0x31: 0x2A,                                                             // backslash
	0x32: 0x2A,                                                             // non-US #
	0x33: 0x29,                                                             // ;
	0x34: 0x27,                                                             // '
	0x35: 0x32,                                                             // `
	0x36: 0x2B,                                                             // ,
	0x37: 0x2F,                                                             // .
	0x38: 0x2C,                                                             // /
	0x39: 0x39,                                                             // Caps Lock
	0x3a: 0x7A, 0x3b: 0x78, 0x3c: 0x63, 0x3d: 0x76, 0x3e: 0x60, 0x3f: 0x61, // F1-F6
	0x40: 0x62, 0x41: 0x64, 0x42: 0x65, 0x43: 0x6D, 0x44: 0x67, 0x45: 0x6F, // F7-F12
	0x46: 0x69,                                                 // Print Screen -> F13
	0x47: 0x6B,                                                 // Scroll Lock -> F14
	0x48: 0x71,                                                 // Pause -> F15
	0x49: 0x72,                                                 // Insert -> Help
	0x4a: 0x73,                                                 // Home
	0x4b: 0x74,                                                 // Page Up
	0x4c: 0x75,                                                 // Delete forward
	0x4d: 0x77,                                                 // End
	0x4e: 0x79,                                                 // Page Down
	0x4f: 0x7C,                                                 // Right
	0x50: 0x7B,                                                 // Left
	0x51: 0x7D,                                                 // Down
	0x52: 0x7E,                                                 // Up
	0x53: 0x47,                                                 // Num Lock -> Keypad Clear
	0x54: 0x4B,                                                 // Keypad /
	0x55: 0x43,                                                 // Keypad *
	0x56: 0x4E,                                                 // Keypad -
	0x57: 0x45,                                                 // Keypad +
	0x58: 0x4C,                                                 // Keypad Enter
	0x59: 0x53, 0x5a: 0x54, 0x5b: 0x55, 0x5c: 0x56, 0x5d: 0x57, // Keypad 1-5
	0x5e: 0x58, 0x5f: 0x59, 0x60: 0x5B, 0x61: 0x5C, 0x62: 0x52, // Keypad 6-9, 0
	0x63: 0x41,                                     // Keypad .
	0x64: 0x0A,                                     // non-US backslash (ISO section)
	0x67: 0x51,                                     // Keypad =
	0x68: 0x69, 0x69: 0x6B, 0x6a: 0x71, 0x6b: 0x6A, // F13-F16
	0x6c: 0x40, 0x6d: 0x4F, 0x6e: 0x50, 0x6f: 0x5A, // F17-F20
	0xe0: 0x3B, // Left Control
	0xe1: 0x38, // Left Shift
	0xe2: 0x3A, // Left Option
	0xe3: 0x37, // Left Command
	0xe4: 0x3E, // Right Control
	0xe5: 0x3C, // Right Shift
	0xe6: 0x3D, // Right Option
	0xe7: 0x36, // Right Command
}

// macModifierFlag returns the CGEventFlags bit a modifier key sets.
func macModifierFlag(usage uint16) uint64 {
	switch usage {
	case 0xe0, 0xe4:
		return 1 << 18 // kCGEventFlagMaskControl
	case 0xe1, 0xe5:
		return 1 << 17 // kCGEventFlagMaskShift
	case 0xe2, 0xe6:
		return 1 << 19 // kCGEventFlagMaskAlternate
	case 0xe3, 0xe7:
		return 1 << 20 // kCGEventFlagMaskCommand
	}
	return 0
}

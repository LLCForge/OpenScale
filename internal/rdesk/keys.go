package rdesk

// Keys travel as USB HID usages (keyboard page 0x07), which do not depend
// on the client's or the server's operating system or layout. Each
// platform maps them to its own key codes: Windows virtual keys here, X11
// keysyms for XTEST. Unknown usages are ignored by the server.

// keyMap holds the Windows virtual key, whether it is an extended key,
// and the X11 keysym of a HID usage.
type keyMap struct {
	vk       uint16
	extended bool
	keysym   uint32
}

var hidKeys = map[uint16]keyMap{
	0x28: {0x0D, false, 0xff0d}, // Enter
	0x29: {0x1B, false, 0xff1b}, // Escape
	0x2A: {0x08, false, 0xff08}, // Backspace
	0x2B: {0x09, false, 0xff09}, // Tab
	0x2C: {0x20, false, 0x0020}, // Space
	0x2D: {0xBD, false, 0x002d}, // - _
	0x2E: {0xBB, false, 0x003d}, // = +
	0x2F: {0xDB, false, 0x005b}, // [ {
	0x30: {0xDD, false, 0x005d}, // ] }
	0x31: {0xDC, false, 0x005c}, // \ |
	0x33: {0xBA, false, 0x003b}, // ; :
	0x34: {0xDE, false, 0x0027}, // ' "
	0x35: {0xC0, false, 0x0060}, // ` ~
	0x36: {0xBC, false, 0x002c}, // , <
	0x37: {0xBE, false, 0x002e}, // . >
	0x38: {0xBF, false, 0x002f}, // / ?
	0x39: {0x14, false, 0xffe5}, // Caps Lock
	0x46: {0x2C, true, 0xff61},  // Print Screen
	0x47: {0x91, false, 0xff14}, // Scroll Lock
	0x48: {0x13, false, 0xff13}, // Pause
	0x49: {0x2D, true, 0xff63},  // Insert
	0x4A: {0x24, true, 0xff50},  // Home
	0x4B: {0x21, true, 0xff55},  // Page Up
	0x4C: {0x2E, true, 0xffff},  // Delete
	0x4D: {0x23, true, 0xff57},  // End
	0x4E: {0x22, true, 0xff56},  // Page Down
	0x4F: {0x27, true, 0xff53},  // Right
	0x50: {0x25, true, 0xff51},  // Left
	0x51: {0x28, true, 0xff54},  // Down
	0x52: {0x26, true, 0xff52},  // Up
	0x53: {0x90, true, 0xff7f},  // Num Lock
	0x54: {0x6F, true, 0xffaf},  // Keypad /
	0x55: {0x6A, false, 0xffaa}, // Keypad *
	0x56: {0x6D, false, 0xffad}, // Keypad -
	0x57: {0x6B, false, 0xffab}, // Keypad +
	0x58: {0x0D, true, 0xff8d},  // Keypad Enter
	0x62: {0x60, false, 0xffb0}, // Keypad 0
	0x63: {0x6E, false, 0xffae}, // Keypad .
	0x64: {0xE2, false, 0x003c}, // ISO \ (the key next to left Shift)
	0x65: {0x5D, true, 0xff67},  // Menu
	0xE0: {0xA2, false, 0xffe3}, // Left Ctrl
	0xE1: {0xA0, false, 0xffe1}, // Left Shift
	0xE2: {0xA4, false, 0xffe9}, // Left Alt
	0xE3: {0x5B, true, 0xffeb},  // Left GUI
	0xE4: {0xA3, true, 0xffe4},  // Right Ctrl
	0xE5: {0xA1, false, 0xffe2}, // Right Shift
	0xE6: {0xA5, true, 0xfe03},  // Right Alt (AltGr, ISO_Level3_Shift)
	0xE7: {0x5C, true, 0xffec},  // Right GUI
}

// lookupKey maps a HID usage; ok is false for usages the server does not
// inject.
func lookupKey(usage uint16) (keyMap, bool) {
	switch {
	case usage >= 0x04 && usage <= 0x1D: // a-z
		i := usage - 0x04
		return keyMap{vk: 'A' + i, keysym: uint32('a' + i)}, true
	case usage >= 0x1E && usage <= 0x26: // 1-9
		i := usage - 0x1E
		return keyMap{vk: '1' + i, keysym: uint32('1' + i)}, true
	case usage == 0x27: // 0
		return keyMap{vk: '0', keysym: '0'}, true
	case usage >= 0x3A && usage <= 0x45: // F1-F12
		i := usage - 0x3A
		return keyMap{vk: 0x70 + i, keysym: 0xffbe + uint32(i)}, true
	case usage >= 0x59 && usage <= 0x61: // Keypad 1-9
		i := usage - 0x59
		return keyMap{vk: 0x61 + i, keysym: 0xffb1 + uint32(i)}, true
	}
	k, ok := hidKeys[usage]
	return k, ok
}

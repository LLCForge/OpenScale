package dbuswire

import "strings"

// maxName is the specification's limit for every name.
const maxName = 255

func isAlpha(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// ValidObjectPath reports whether p is "/" or "/a/b" with [A-Za-z0-9_]
// elements.
func ValidObjectPath(p string) bool {
	if p == "/" {
		return true
	}
	if len(p) < 2 || p[0] != '/' || p[len(p)-1] == '/' || len(p) > 4096 {
		return false
	}
	for _, el := range strings.Split(p[1:], "/") {
		if el == "" {
			return false
		}
		for i := 0; i < len(el); i++ {
			if !isAlpha(el[i]) && !isDigit(el[i]) {
				return false
			}
		}
	}
	return true
}

// ValidInterfaceName reports whether s is an interface (or error) name:
// two or more dot-separated elements, none starting with a digit.
func ValidInterfaceName(s string) bool {
	if len(s) == 0 || len(s) > maxName {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, el := range parts {
		if !validMemberChars(el) {
			return false
		}
	}
	return true
}

// ValidMemberName reports whether s is a method or signal name.
func ValidMemberName(s string) bool { return len(s) <= maxName && validMemberChars(s) }

func validMemberChars(el string) bool {
	if el == "" || isDigit(el[0]) {
		return false
	}
	for i := 0; i < len(el); i++ {
		if !isAlpha(el[i]) && !isDigit(el[i]) {
			return false
		}
	}
	return true
}

// ValidBusName reports whether s is a unique (":1.42") or well-known
// ("org.kde.StatusNotifierWatcher") bus name.
func ValidBusName(s string) bool {
	if len(s) == 0 || len(s) > maxName {
		return false
	}
	unique := s[0] == ':'
	if unique {
		s = s[1:]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, el := range parts {
		if el == "" {
			return false
		}
		if !unique && isDigit(el[0]) {
			return false
		}
		for i := 0; i < len(el); i++ {
			c := el[i]
			if !isAlpha(c) && !isDigit(c) && c != '-' {
				return false
			}
		}
	}
	return true
}

package trust

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxDisplayNameLength is the longest network display name, in characters.
const MaxDisplayNameLength = 64

// ErrInvalidDisplayName is returned for a display name that is empty, too
// long, not valid UTF-8, or has control characters or surrounding spaces.
var ErrInvalidDisplayName = errors.New("display name must be 1-64 characters without control characters or surrounding spaces")

// ValidateDisplayName checks a network display name (F-160). The name is
// shown in the tray menu and the panel, so control and formatting
// characters are refused: they could hide or reorder text (for example a
// right-to-left override).
func ValidateDisplayName(name string) error {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > MaxDisplayNameLength {
		return ErrInvalidDisplayName
	}
	if strings.TrimSpace(name) != name {
		return ErrInvalidDisplayName
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return ErrInvalidDisplayName
		}
	}
	return nil
}

// SetDisplayName sets the network's display name; an empty name removes
// it, and the document then encodes as it did before the field existed.
func (doc *Document) SetDisplayName(name string) error {
	if name != "" {
		if err := ValidateDisplayName(name); err != nil {
			return err
		}
	}
	return doc.transact(func() error {
		doc.DisplayName = name
		return nil
	})
}

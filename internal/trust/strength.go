package trust

import (
	"math"
	"strings"
	"unicode"
)

// Passphrase strength estimate (#12, ADR-0060). Besides the length and
// distinct-character rules, a passphrase is split into the cheapest
// sequence of guessable pieces: words from a local list of common
// passwords and words (no network request), keyboard runs, alphabetic and
// numeric sequences, repeated characters, years, and single characters.
// The sum of their costs is a conservative entropy estimate in bits; a
// whole passphrase that repeats a shorter unit costs that unit. The
// estimate is a heuristic: it catches the guessable passphrases attackers
// try first and accepts word-based passphrases of four or more uncommon
// words.

// MinPassphraseBits is the lowest accepted entropy estimate.
const MinPassphraseBits = 45

type guessableError struct{}

func (guessableError) Error() string {
	return "passphrase is easy to guess: avoid common words, keyboard runs, sequences and repetition"
}

// Is makes the error match ErrWeakPassphrase, so callers that only know
// that error still treat the passphrase as rejected.
func (guessableError) Is(target error) bool { return target == ErrWeakPassphrase }

// ErrGuessablePassphrase is returned for a passphrase that meets the
// length rules but whose entropy estimate is below MinPassphraseBits.
var ErrGuessablePassphrase error = guessableError{}

// sequences are keyboard rows (US and Turkish Q), the alphabet and digits.
// A run of three or more consecutive characters from one of them, forward
// or backward, is cheap to guess.
var sequences = []string{
	"abcdefghijklmnopqrstuvwxyz",
	"abcçdefgğhıijklmnoöprsştuüvyz",
	"01234567890",
	"qwertyuiop",
	"asdfghjkl",
	"zxcvbnm",
	"qwertyuıopğü",
	"asdfghjklşi",
	"zxcvbnmöç",
	"1qaz2wsx3edc4rfv5tgb",
	"qazwsxedcrfvtgbyhnujm",
}

// leet and Turkish folding map a rune to the ASCII letter used in the word
// list, so "P@r0la" and "şifre" match "parola" and "sifre".
var foldRunes = map[rune]rune{
	'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i',
	'ı': 'i', 'ş': 's', 'ğ': 'g', 'ü': 'u', 'ö': 'o', 'ç': 'c', 'â': 'a', 'î': 'i', 'û': 'u',
}

// EstimatePassphraseBits returns a conservative entropy estimate in bits.
func EstimatePassphraseBits(passphrase []byte) float64 {
	original := []rune(string(passphrase))
	if len(original) == 0 {
		return 0
	}
	lower := make([]rune, len(original))
	folded := make([]rune, len(original))
	for i, r := range original {
		l := unicode.ToLower(r)
		lower[i] = l
		if f, ok := foldRunes[l]; ok {
			folded[i] = f
		} else {
			folded[i] = l
		}
	}
	charBits := math.Log2(float64(poolSize(original)))
	bits := segmentBits(lower, folded, charBits)
	// A passphrase that repeats a unit ("parola12parola12") costs the unit.
	n := len(lower)
	for p := 1; p <= n/2; p++ {
		if n%p != 0 || !repeats(lower, p) {
			continue
		}
		unit := segmentBits(lower[:p], folded[:p], charBits) + math.Log2(float64(n/p))
		bits = math.Min(bits, unit)
		break
	}
	return bits
}

// segmentBits finds the cheapest split into guessable pieces.
func segmentBits(lower, folded []rune, charBits float64) float64 {
	n := len(lower)
	best := make([]float64, n+1)
	for i := 1; i <= n; i++ {
		best[i] = math.Inf(1)
	}
	dictBits := math.Log2(float64(len(commonWords))) + 1
	seqBits := math.Log2(float64(2 * len(sequences)))
	for i := 0; i < n; i++ {
		if math.IsInf(best[i], 1) {
			continue
		}
		relax := func(end int, cost float64) {
			if end <= n && best[i]+cost < best[end] {
				best[end] = best[i] + cost
			}
		}
		relax(i+1, charBits)
		for _, w := range commonWords {
			if hasRunePrefix(folded[i:], w) {
				relax(i+len([]rune(w)), dictBits)
			}
		}
		// Repeated character: "aaaa".
		j := i + 1
		for j < n && lower[j] == lower[i] {
			j++
		}
		for end := i + 3; end <= j; end++ {
			relax(end, charBits+math.Log2(float64(end-i)))
		}
		// Sequences and keyboard runs: "abcd", "4321", "qwer".
		for end := i + 3; end <= n; end++ {
			if !isSequence(lower[i:end]) {
				break
			}
			relax(end, seqBits+math.Log2(26)+math.Log2(float64(end-i)))
		}
		// Years 1900-2099.
		if i+4 <= n && isYear(lower[i:i+4]) {
			relax(i+4, math.Log2(200))
		}
	}
	return best[n]
}

func hasRunePrefix(s []rune, w string) bool {
	i := 0
	for _, r := range w {
		if i >= len(s) || s[i] != r {
			return false
		}
		i++
	}
	return true
}

func isSequence(run []rune) bool {
	s := string(run)
	for _, seq := range sequences {
		if strings.Contains(seq, s) || strings.Contains(seq, reverseString(s)) {
			return true
		}
	}
	return false
}

func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func isYear(r []rune) bool {
	for _, c := range r {
		if c < '0' || c > '9' {
			return false
		}
	}
	return (r[0] == '1' && r[1] == '9') || (r[0] == '2' && r[1] == '0')
}

func repeats(r []rune, p int) bool {
	for i := p; i < len(r); i++ {
		if r[i] != r[i-p] {
			return false
		}
	}
	return true
}

// poolSize is the size of the alphabet the characters were drawn from.
func poolSize(r []rune) int {
	var lower, upper, digit, space, symbol, other bool
	for _, c := range r {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		case c == ' ':
			space = true
		case c < 0x80:
			symbol = true
		default:
			other = true
		}
	}
	n := 0
	for _, c := range []struct {
		present bool
		size    int
	}{{lower, 26}, {upper, 26}, {digit, 10}, {space, 1}, {symbol, 33}, {other, 32}} {
		if c.present {
			n += c.size
		}
	}
	return max(n, 2)
}

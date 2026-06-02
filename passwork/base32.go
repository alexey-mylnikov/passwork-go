// Package passwork provides a Go client for the Passwork password manager API.
package passwork

import "strings"

// Custom Base32 alphabet: digits + lowercase letters, omitting i/l/o/s
// to avoid visual confusion with 1/1/0/5.
const b32Alphabet = "0123456789abcdefghjkmnpqrtuvwxyz"

// b32Aliases maps visually confusable characters to their canonical index values.
var b32Aliases = map[rune]int{
	'o': 0, 'i': 1, 'l': 1, 's': 5,
}

// b32Lookup maps each alphabet character (and its aliases) to its 5-bit value.
var b32Lookup = func() map[rune]int {
	m := make(map[rune]int, len(b32Alphabet)+len(b32Aliases))
	for i, c := range b32Alphabet {
		m[c] = i
	}
	for c, v := range b32Aliases {
		m[c] = v
	}
	return m
}()

// b32Encode encodes an arbitrary UTF-8 string into the custom Base32 format.
func b32Encode(input string) string {
	var bitBuffer, bitCount int
	var out strings.Builder
	out.Grow(len(input) * 8 / 5)

	for _, b := range []byte(input) {
		bitBuffer = (bitBuffer << 8) | int(b)
		bitCount += 8
		for bitCount >= 5 {
			out.WriteByte(b32Alphabet[(bitBuffer>>(bitCount-5))&31])
			bitCount -= 5
			bitBuffer &= (1 << bitCount) - 1
		}
	}
	if bitCount > 0 {
		out.WriteByte(b32Alphabet[(bitBuffer<<(5-bitCount))&31])
	}
	return out.String()
}

// b32Decode decodes a custom Base32 string back to the original UTF-8 string.
// Unknown characters are silently skipped, matching the Python implementation.
func b32Decode(input string) string {
	var bitBuffer, bitCount int
	var out []byte

	for _, c := range strings.ToLower(input) {
		val, ok := b32Lookup[c]
		if !ok {
			continue
		}
		bitBuffer = (bitBuffer << 5) | val
		bitCount += 5
		for bitCount >= 8 {
			out = append(out, byte((bitBuffer>>(bitCount-8))&0xFF))
			bitCount -= 8
			bitBuffer &= (1 << bitCount) - 1
		}
	}
	return string(out)
}

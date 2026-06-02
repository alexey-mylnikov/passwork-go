package passwork

import (
	"testing"
)

func TestB32EncodeDecode(t *testing.T) {
	cases := []struct {
		input string
	}{
		{""},
		{"a"},
		{"hello"},
		{"Hello, World!"},
		{"0123456789"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"},
		{"The quick brown fox jumps over the lazy dog"},
		{"SGVsbG8gV29ybGQ="}, // base64 content
		{"Salted__\x01\x02\x03\x04\x05\x06\x07\x08some ciphertext here"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			encoded := b32Encode(tc.input)
			decoded := b32Decode(encoded)
			if decoded != tc.input {
				t.Errorf("roundtrip failed: input=%q encoded=%q decoded=%q", tc.input, encoded, decoded)
			}
		})
	}
}

func TestB32AliasMapping(t *testing.T) {
	// 'o' → 0, 'i' → 1, 'l' → 1, 's' → 5
	// Encoding '0' produces '0'; decoding 'o' should yield the same result.
	encoded := b32Encode("a")
	withAlias := ""
	for _, c := range encoded {
		switch c {
		case '0':
			withAlias += "o"
		case '1':
			withAlias += "i"
		case '5':
			withAlias += "s"
		default:
			withAlias += string(c)
		}
	}
	decoded := b32Decode(withAlias)
	if decoded != "a" {
		t.Errorf("alias mapping failed: got %q", decoded)
	}
}

func TestB32OnlyAlphabetChars(t *testing.T) {
	encoded := b32Encode("test string")
	for _, c := range encoded {
		found := false
		for _, a := range b32Alphabet {
			if c == a {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("encoded char %q not in alphabet", c)
		}
	}
}

package passwork

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestEncryptDecryptAES verifies that encryptAES → decryptAES is a lossless
// roundtrip for a variety of inputs and passphrases.
func TestEncryptDecryptAES(t *testing.T) {
	cases := []struct {
		name       string
		message    string
		passphrase string
	}{
		{"empty passphrase", "hello world", ""},
		{"short passphrase", "hello world", "secret"},
		{"long passphrase", "hello world", strings.Repeat("k", 100)},
		{"empty message with passphrase", "", "mypassphrase"},
		{"unicode", "Привет мир!", "passphrase"},
		{"long message", strings.Repeat("A", 10000), "key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := encryptAES([]byte(tc.message), tc.passphrase)
			if err != nil {
				t.Fatalf("encryptAES error: %v", err)
			}

			if tc.passphrase == "" {
				// Empty passphrase: result is standard base64.
				dec, err := base64.StdEncoding.DecodeString(enc)
				if err != nil {
					t.Fatalf("base64 decode: %v", err)
				}
				if string(dec) != tc.message {
					t.Errorf("got %q want %q", dec, tc.message)
				}
				return
			}

			dec, err := decryptAES(enc, tc.passphrase)
			if err != nil {
				t.Fatalf("decryptAES error: %v", err)
			}
			if string(dec) != tc.message {
				t.Errorf("got %q want %q", string(dec), tc.message)
			}
		})
	}
}

// TestEncryptAESNondeterministic confirms that two encryptions of the same
// plaintext with the same key produce different ciphertexts (random IV/salt).
func TestEncryptAESNondeterministic(t *testing.T) {
	enc1, err := encryptAES([]byte("same plaintext"), "same passphrase")
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := encryptAES([]byte("same plaintext"), "same passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if enc1 == enc2 {
		t.Error("two encryptions of the same plaintext produced identical ciphertext — random salt not working")
	}
}

// TestSHA256Hex verifies the SHA-256 output for known values.
func TestSHA256Hex(t *testing.T) {
	cases := []struct{ input, want string }{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
	}
	for _, tc := range cases {
		if got := sha256Hex(tc.input); got != tc.want {
			t.Errorf("sha256Hex(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestRSAEncryptDecrypt verifies that RSA encrypt/decrypt roundtrips correctly.
func TestRSAEncryptDecrypt(t *testing.T) {
	pub, priv, err := generateRSAKeys()
	if err != nil {
		t.Fatalf("generateRSAKeys: %v", err)
	}

	plaintext := []byte("super secret value 42")

	ct, err := rsaEncrypt(plaintext, pub)
	if err != nil {
		t.Fatalf("rsaEncrypt: %v", err)
	}

	ct64 := base64.StdEncoding.EncodeToString(ct)
	got, err := rsaDecrypt(ct64, priv)
	if err != nil {
		t.Fatalf("rsaDecrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("got %q want %q", got, plaintext)
	}
}

// TestGenerateKey checks length and charset of generated keys.
func TestGenerateKey(t *testing.T) {
	k := generateKey()
	if len(k) != 100 {
		t.Errorf("generateKey length = %d, want 100", len(k))
	}
	for _, c := range k {
		if !strings.ContainsRune(charsetKey, c) {
			t.Errorf("generateKey contains char %q not in charset", c)
		}
	}
}

// TestGenerateUserPassword verifies complexity constraints.
func TestGenerateUserPassword(t *testing.T) {
	c := PasswordComplexity{
		MinLength:                   16,
		IsDigitsRequired:            true,
		IsUppercaseRequired:         true,
		IsSpecialCharactersRequired: true,
	}
	p := GenerateUserPassword(12, c)
	if len(p) < 16 {
		t.Errorf("password length %d < minLength 16", len(p))
	}
	if !strings.ContainsAny(p, "0123456789") {
		t.Error("password missing digits")
	}
	if !strings.ContainsAny(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Error("password missing uppercase")
	}
	if !strings.ContainsAny(p, "!@#$%^") {
		t.Error("password missing special chars")
	}
}

// TestBlobToString verifies the byte→Unicode→UTF-8 mapping.
// Bytes 0–127 produce one UTF-8 byte each; 128–255 produce two bytes each.
func TestBlobToString(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	result := blobToString(data)
	expectedLen := 128 + 128*2
	if len(result) != expectedLen {
		t.Errorf("blobToString length = %d, want %d", len(result), expectedLen)
	}
}

// TestEvpBytesToKey checks that the derived key and IV have the expected lengths.
func TestEvpBytesToKey(t *testing.T) {
	key, iv := evpBytesToKey("password", []byte("saltsalt"), 32, 16)
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
	if len(iv) != 16 {
		t.Errorf("iv length = %d, want 16", len(iv))
	}
}

// TestEncryptDecryptItemFields tests the full item field encryption/decryption pipeline.
func TestEncryptDecryptItemFields(t *testing.T) {
	encKey := generateKey()
	vaultPassword := generateKey()

	// Encrypt
	passwordEnc, err := encryptAES([]byte("my-secret-password"), encKey)
	if err != nil {
		t.Fatalf("encrypt password: %v", err)
	}
	keyEnc, err := encryptAES([]byte(encKey), vaultPassword)
	if err != nil {
		t.Fatalf("encrypt item key: %v", err)
	}
	customs, err := encryptCustomFields([]CustomField{
		{Name: "fn", Type: "text", Value: "fv"},
	}, encKey)
	if err != nil {
		t.Fatalf("encrypt customs: %v", err)
	}

	// Decrypt the item key from the vault
	itemKeyBytes, err := decryptAES(keyEnc, vaultPassword)
	if err != nil {
		t.Fatalf("decrypt item key: %v", err)
	}
	if string(itemKeyBytes) != encKey {
		t.Errorf("item key roundtrip failed: got %q", itemKeyBytes)
	}

	// Decrypt the item itself
	item := Item{
		PasswordEncrypted: passwordEnc,
		Customs: func() []CustomField {
			cf := make([]CustomField, len(customs))
			for i, c := range customs {
				cf[i] = CustomField{
					Name:  c["name"].(string),
					Type:  c["type"].(string),
					Value: c["value"].(string),
				}
			}
			return cf
		}(),
	}
	if err := decryptItem(&item, encKey); err != nil {
		t.Fatalf("decryptItem: %v", err)
	}

	if item.Password != "my-secret-password" {
		t.Errorf("password: got %q", item.Password)
	}
	if item.Customs[0].Name != "fn" {
		t.Errorf("custom name: got %q", item.Customs[0].Name)
	}
	if item.Customs[0].Value != "fv" {
		t.Errorf("custom value: got %q", item.Customs[0].Value)
	}
}

// TestGenerateUserRSAKeys verifies that generated RSA keys can encrypt/decrypt.
func TestGenerateUserRSAKeys(t *testing.T) {
	masterKey := "test-master-key-123"
	pub, privEnc, err := GenerateUserRSAKeys(masterKey)
	if err != nil {
		t.Fatalf("GenerateUserRSAKeys: %v", err)
	}

	if !strings.HasPrefix(pub, "-----BEGIN PUBLIC KEY-----") {
		t.Error("public key not in PEM format")
	}

	// Decrypt the private key
	privBytes, err := decryptAES(privEnc, masterKey)
	if err != nil {
		t.Fatalf("decrypt private key: %v", err)
	}
	if !strings.HasPrefix(string(privBytes), "-----BEGIN PRIVATE KEY-----") {
		t.Error("decrypted private key not in PEM format")
	}

	// Verify the keys work together.
	plaintext := []byte("test message")
	ct, err := rsaEncrypt(plaintext, pub)
	if err != nil {
		t.Fatalf("rsaEncrypt with generated key: %v", err)
	}
	ct64 := base64.StdEncoding.EncodeToString(ct)
	got, err := rsaDecrypt(ct64, string(privBytes))
	if err != nil {
		t.Fatalf("rsaDecrypt with generated key: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("RSA roundtrip: got %q want %q", got, plaintext)
	}
}

package passwork

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" //nolint:gosec // OpenSSL EVP compatibility requires MD5
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// charset constants used for random string generation.
const (
	charsetKey      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@!"
	charsetPassword = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^"
)

// evpBytesToKey derives an AES key and IV from a passphrase and salt using the
// OpenSSL EVP_BytesToKey algorithm (MD5, one iteration).
func evpBytesToKey(passphrase string, salt []byte, keyLen, ivLen int) (key, iv []byte) {
	var d, prev []byte
	for len(d) < keyLen+ivLen {
		h := md5.New() //nolint:gosec
		h.Write(prev)
		h.Write([]byte(passphrase))
		h.Write(salt)
		prev = h.Sum(nil)
		d = append(d, prev...)
	}
	return d[:keyLen], d[keyLen : keyLen+ivLen]
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS7.
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

// pkcs7Unpad removes PKCS7 padding.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(data) {
		return nil, fmt.Errorf("invalid padding size %d", pad)
	}
	return data[:len(data)-pad], nil
}

// encryptAES encrypts message with AES-256-CBC using an OpenSSL-compatible key derivation.
//
// When passphrase is empty the function returns base64(message), matching the
// Python client's behaviour for unencrypted storage.
//
// Output format (passphrase non-empty):
//
//	custom_base32( base64( "Salted__" + salt[8] + aes_ciphertext ) )
func encryptAES(message []byte, passphrase string) (string, error) {
	if passphrase == "" {
		return base64.StdEncoding.EncodeToString(message), nil
	}

	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key, iv := evpBytesToKey(passphrase, salt, 32, 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("new aes cipher: %w", err)
	}

	padded := pkcs7Pad(message, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	raw := append([]byte("Salted__"), salt...)
	raw = append(raw, ciphertext...)
	b64 := base64.StdEncoding.EncodeToString(raw)
	return b32Encode(b64), nil
}

// decryptAES decrypts a value produced by encryptAES.
func decryptAES(ciphertext, passphrase string) ([]byte, error) {
	b64str := b32Decode(ciphertext)
	raw, err := base64.StdEncoding.DecodeString(b64str)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	if len(raw) < 16 || string(raw[:8]) != "Salted__" {
		return nil, errors.New("missing Salted__ header")
	}

	salt := raw[8:16]
	encrypted := raw[16:]

	key, iv := evpBytesToKey(passphrase, salt, 32, 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new aes cipher: %w", err)
	}

	if len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext not a multiple of block size")
	}

	plaintext := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, encrypted)

	return pkcs7Unpad(plaintext)
}

// rsaEncrypt encrypts plaintext with an RSA public key PEM.
// Tries OAEP/SHA-256 first; falls back to PKCS1v15 on failure.
func rsaEncrypt(plaintext []byte, publicKeyPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, plaintext, nil)
	if err == nil {
		return ct, nil
	}
	return rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext)
}

// rsaDecrypt decrypts a base64-encoded RSA ciphertext using a PEM private key.
// Tries OAEP/SHA-256 first; falls back to PKCS1v15 on failure.
func rsaDecrypt(ciphertext64, privateKeyPEM string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM private key")
	}

	var privKey *rsa.PrivateKey
	if priv, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		privKey, ok = priv.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
	} else if privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, raw, nil)
	if err == nil {
		return pt, nil
	}
	return rsa.DecryptPKCS1v15(rand.Reader, privKey, raw)
}

// sha256Hex returns the hex-encoded SHA-256 hash of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// generateRandomString returns a cryptographically random string of the given
// length drawn from the characters in possible.
func generateRandomString(length int, possible string) string {
	n := big.NewInt(int64(len(possible)))
	var sb strings.Builder
	sb.Grow(length)
	for range length {
		idx, _ := rand.Int(rand.Reader, n)
		sb.WriteByte(possible[idx.Int64()])
	}
	return sb.String()
}

// generateKey returns a 100-character random encryption key.
func generateKey() string {
	return generateRandomString(100, charsetKey)
}

// generateSalt returns a 32-character random salt string.
func generateSalt() string {
	return generateRandomString(32, charsetKey)
}

// GeneratePassword returns a random password of the given length.
func GeneratePassword(length int) string {
	return generateRandomString(length, charsetPassword)
}

// GenerateUserPassword returns a password that satisfies the given complexity
// requirements, retrying until all constraints are met.
func GenerateUserPassword(length int, c PasswordComplexity) string {
	const (
		digits  = "0123456789"
		special = "!@#$%^"
		upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower   = "abcdefghijklmnopqrstuvwxyz"
	)
	if c.MinLength > 0 && length < c.MinLength {
		length = c.MinLength
	}
	charset := digits + special + upper + lower
	for {
		p := generateRandomString(length, charset)
		if c.IsDigitsRequired && !strings.ContainsAny(p, digits) {
			continue
		}
		if c.IsUppercaseRequired && !strings.ContainsAny(p, upper) {
			continue
		}
		if c.IsSpecialCharactersRequired && !strings.ContainsAny(p, special) {
			continue
		}
		return p
	}
}

// deriveMasterKeyFromOptionsString parses the options string returned by the
// API (format: "pbkdf:sha256:<iter>:<bytes>:<salt>") and derives the master key
// using PBKDF2-SHA256.
func deriveMasterKeyFromOptionsString(masterPassword, optsStr string) (string, error) {
	parts := strings.Split(optsStr, ":")
	if len(parts) < 5 {
		return "", fmt.Errorf("invalid masterKeyOptions format: %q", optsStr)
	}
	salt := parts[4]
	var iterations, keyLen int
	if _, err := fmt.Sscanf(parts[2], "%d", &iterations); err != nil {
		return "", fmt.Errorf("parse iterations: %w", err)
	}
	if _, err := fmt.Sscanf(parts[3], "%d", &keyLen); err != nil {
		return "", fmt.Errorf("parse key length: %w", err)
	}
	dk := pbkdf2.Key([]byte(masterPassword), []byte(salt), iterations, keyLen, sha256.New)
	return base64.StdEncoding.EncodeToString(dk), nil
}

// deriveMasterKey derives a master key and returns both the base64 key and the
// options string used for derivation.
func deriveMasterKey(masterPassword string, opts MasterKeyNewOptionsResponse) (masterKey, optsStr string, err error) {
	iterations := opts.Iterations
	if iterations == 0 {
		iterations = 300000
	}
	keyLen := opts.Bytes
	if keyLen == 0 {
		keyLen = 64
	}
	digest := opts.Digest
	if digest == "" {
		digest = "sha256"
	}
	dk := pbkdf2.Key([]byte(masterPassword), []byte(opts.Salt), iterations, keyLen, sha256.New)
	masterKey = base64.StdEncoding.EncodeToString(dk)
	optsStr = fmt.Sprintf("pbkdf:%s:%d:%d:%s", digest, iterations, keyLen, opts.Salt)
	return masterKey, optsStr, nil
}

// generateRSAKeys generates a new RSA-2048 key pair and returns PEM strings.
func generateRSAKeys() (publicPEM, privatePEM string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate RSA key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}
	privatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal public key: %w", err)
	}
	publicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return publicPEM, privatePEM, nil
}

// GenerateUserRSAKeys generates an RSA-2048 key pair and returns the public key
// in plain PEM and the private key AES-encrypted with masterKey.
func GenerateUserRSAKeys(masterKey string) (publicKey, privateEncrypted string, err error) {
	pub, priv, err := generateRSAKeys()
	if err != nil {
		return "", "", err
	}
	enc, err := encryptAES([]byte(priv), masterKey)
	if err != nil {
		return "", "", fmt.Errorf("encrypt private key: %w", err)
	}
	return pub, enc, nil
}

// encryptionKeyFromItem decrypts the per-item AES key using the vault master key
// (RSA-decrypted) and then the AES-decrypted item key.
func encryptionKeyFromItem(vaultMasterKeyEncrypted, keyEncrypted, userPrivateKey string) (string, error) {
	vaultMasterKey, err := rsaDecrypt(vaultMasterKeyEncrypted, userPrivateKey)
	if err != nil {
		return "", fmt.Errorf("decrypt vault master key: %w", err)
	}
	itemKey, err := decryptAES(keyEncrypted, string(vaultMasterKey))
	if err != nil {
		return "", fmt.Errorf("decrypt item key: %w", err)
	}
	return string(itemKey), nil
}

// blobToString maps each byte to its Unicode code point, then UTF-8-encodes the
// result. Matches Python's `"".join([chr(b) for b in blob]).encode('utf-8')`.
func blobToString(data []byte) []byte {
	var sb strings.Builder
	for _, b := range data {
		sb.WriteRune(rune(b))
	}
	return []byte(sb.String())
}

// encodeAttachmentFile encodes file bytes for upload.
// With encryption key: encryptAES(base64(data), key).
// Without: base64(base64(data)).
func encodeAttachmentFile(data []byte, encryptionKey string) (string, error) {
	b64data := base64.StdEncoding.EncodeToString(data)
	if encryptionKey == "" {
		return base64.StdEncoding.EncodeToString([]byte(b64data)), nil
	}
	return encryptAES([]byte(b64data), encryptionKey)
}

// decodeAttachmentFile reverses encodeAttachmentFile.
func decodeAttachmentFile(data, encryptedKey string) ([]byte, error) {
	if encryptedKey == "" {
		first, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("outer base64 decode: %w", err)
		}
		return base64.StdEncoding.DecodeString(string(first))
	}
	decrypted, err := decryptAES(data, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt attachment data: %w", err)
	}
	return base64.StdEncoding.DecodeString(string(decrypted))
}

// encryptAttachment produces the encryptedKey, encryptedData, and hash fields
// ready to be sent to the API. encryptionKey is the item's encryption key.
func encryptAttachment(fileData []byte, encryptionKey string) (encKey, encData, hash string, err error) {
	if len(fileData) > 5*1024*1024 {
		return "", "", "", errors.New("attachment max size is 5 MB")
	}

	var fileKey string
	if encryptionKey != "" {
		fileKey = generateKey()
		encKey, err = encryptAES([]byte(fileKey), encryptionKey)
		if err != nil {
			return "", "", "", fmt.Errorf("encrypt attachment key: %w", err)
		}
	} else {
		fileKey = ""
		encKey = base64.StdEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	}

	encData, err = encodeAttachmentFile(fileData, fileKey)
	if err != nil {
		return "", "", "", fmt.Errorf("encode attachment: %w", err)
	}

	blobStr := blobToString(fileData)
	h := sha256.Sum256(blobStr)
	hash = hex.EncodeToString(h[:])
	return encKey, encData, hash, nil
}

// decryptAttachment decrypts attachment bytes and verifies the stored hash.
// encryptionKey is the already-decrypted item encryption key.
func decryptAttachment(a Attachment, encryptionKey string) ([]byte, error) {
	var fileKey string
	if encryptionKey != "" {
		k, err := decryptAES(a.EncryptedKey, encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt attachment key: %w", err)
		}
		fileKey = string(k)
	}

	data, err := decodeAttachmentFile(a.EncryptedData, fileKey)
	if err != nil {
		return nil, err
	}

	blobStr := blobToString(data)
	h := sha256.Sum256(blobStr)
	if hex.EncodeToString(h[:]) != a.Hash {
		return nil, errors.New("attachment hash mismatch")
	}
	return data, nil
}

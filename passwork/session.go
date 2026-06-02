package passwork

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// SaveSession encrypts the current access token, refresh token and optionally
// the master key, then writes the result to filePath.
//
// If encryptionKey is empty a random 32-byte key is generated and returned;
// store it somewhere safe — it is required to load the session later.
//
// When saveMasterKey is true the master key is included in the session file,
// allowing fully automatic re-authentication.
func (c *Client) SaveSession(filePath, encryptionKey string, saveMasterKey bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if encryptionKey == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", fmt.Errorf("generate encryption key: %w", err)
		}
		encryptionKey = base64.StdEncoding.EncodeToString(raw)
	}

	data := sessionData{
		AccessToken:  c.accessToken,
		RefreshToken: c.refreshToken,
	}
	if saveMasterKey {
		data.MasterKey = c.masterKey
	}

	b, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal session: %w", err)
	}

	encrypted, err := encryptAES(b, encryptionKey)
	if err != nil {
		return "", fmt.Errorf("encrypt session: %w", err)
	}

	// Wrap in another base64 layer to match the Python client's file format.
	fileContent := base64.StdEncoding.EncodeToString([]byte(encrypted))

	if err := os.WriteFile(filePath, []byte(fileContent), 0600); err != nil {
		return "", fmt.Errorf("write session file: %w", err)
	}

	c.sessionPath = filePath
	c.sessionEncryptionKey = encryptionKey
	return encryptionKey, nil
}

// LoadSession reads and decrypts a session file written by SaveSession.
// If the session contained a master key it is applied via SetMasterKey.
func (c *Client) LoadSession(ctx context.Context, filePath, encryptionKey string) error {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read session file: %w", err)
	}

	// Unwrap the outer base64 layer.
	inner, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return fmt.Errorf("decode session file: %w", err)
	}

	decrypted, err := decryptAES(string(inner), encryptionKey)
	if err != nil {
		return fmt.Errorf("decrypt session: %w", err)
	}

	var data sessionData
	if err := json.Unmarshal(decrypted, &data); err != nil {
		return fmt.Errorf("parse session: %w", err)
	}

	c.mu.Lock()
	c.accessToken = data.AccessToken
	c.refreshToken = data.RefreshToken
	c.sessionPath = filePath
	c.sessionEncryptionKey = encryptionKey
	c.mu.Unlock()

	if data.MasterKey != "" {
		if err := c.SetMasterKey(ctx, data.MasterKey); err != nil {
			return fmt.Errorf("restore master key: %w", err)
		}
	}

	return nil
}

// saveSessionLocked writes the current session to disk. Must be called with
// c.mu held. It is used internally after token rotation.
func (c *Client) saveSessionLocked(filePath, encryptionKey string, saveMasterKey bool) error {
	data := sessionData{
		AccessToken:  c.accessToken,
		RefreshToken: c.refreshToken,
	}
	if saveMasterKey {
		data.MasterKey = c.masterKey
	}

	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	encrypted, err := encryptAES(b, encryptionKey)
	if err != nil {
		return err
	}
	fileContent := base64.StdEncoding.EncodeToString([]byte(encrypted))
	return os.WriteFile(filePath, []byte(fileContent), 0600)
}

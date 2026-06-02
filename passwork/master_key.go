package passwork

import (
	"context"
	"fmt"
)

// SetMasterPassword derives the master key from the given password and activates
// client-side encryption. It calls GET /api/v1/users/master-key/options to fetch
// PBKDF2 parameters, then GET /api/v1/users/keys to decrypt and cache the user's
// RSA key pair.
//
// Pass an empty string to disable client-side encryption.
func (c *Client) SetMasterPassword(ctx context.Context, masterPassword string) error {
	if masterPassword == "" {
		return c.SetMasterKey(ctx, "")
	}

	var optsResp MasterKeyOptionsResponse
	if err := c.call(ctx, "GET", "/api/v1/users/master-key/options", nil, &optsResp); err != nil {
		return fmt.Errorf("fetch master key options: %w", err)
	}

	masterKey, err := deriveMasterKeyFromOptionsString(masterPassword, optsResp.MasterKeyOptions)
	if err != nil {
		return fmt.Errorf("derive master key: %w", err)
	}

	return c.SetMasterKey(ctx, masterKey)
}

// SetMasterKey activates client-side encryption using the provided base64-encoded
// master key. It fetches and decrypts the user's RSA key pair from the server.
//
// Pass an empty string to disable encryption and clear all cached key material.
func (c *Client) SetMasterKey(ctx context.Context, masterKey string) error {
	if masterKey == "" {
		c.mu.Lock()
		c.isEncrypt = false
		c.masterKey = ""
		c.masterKeyHash = ""
		c.userPrivateKey = ""
		c.userPublicKey = ""
		c.mu.Unlock()
		return nil
	}

	masterKeyHash := sha256Hex(masterKey)

	// Temporarily set the hash so the /keys request is authenticated.
	c.mu.Lock()
	c.masterKeyHash = masterKeyHash
	c.mu.Unlock()

	var keysResp struct {
		Keys UserKeys `json:"keys"`
	}
	if err := c.call(ctx, "GET", "/api/v1/users/keys", nil, &keysResp); err != nil {
		c.mu.Lock()
		c.masterKeyHash = ""
		c.mu.Unlock()
		return fmt.Errorf("fetch user keys: %w", err)
	}

	privateKey, err := decryptAES(keysResp.Keys.PrivateEncrypted, masterKey)
	if err != nil {
		c.mu.Lock()
		c.masterKeyHash = ""
		c.mu.Unlock()
		return fmt.Errorf("decrypt private key: %w", err)
	}

	c.mu.Lock()
	c.isEncrypt = true
	c.masterKey = masterKey
	c.masterKeyHash = masterKeyHash
	c.userPrivateKey = string(privateKey)
	c.userPublicKey = keysResp.Keys.Public
	c.mu.Unlock()

	return nil
}

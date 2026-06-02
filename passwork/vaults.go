package passwork

import (
	"context"
	"encoding/base64"
	"fmt"
)

// CreateVault creates a new vault with the given name. When client-side
// encryption is active a vault master key is generated and RSA-encrypted for
// the current user. If the server requires a vault type (vaultType feature),
// typeID must be provided.
func (c *Client) CreateVault(ctx context.Context, name, typeID string) (string, error) {
	if typeID == "" {
		feat, err := c.FindFeature(ctx, "vaultType")
		if err != nil {
			return "", err
		}
		if feat != nil {
			return "", &PassworkError{
				Message: "vault type is required (pass a typeID)",
				Code:    "vault_type_required",
			}
		}
	}

	payload := map[string]interface{}{"name": name}

	c.mu.Lock()
	isEncrypt := c.isEncrypt
	pubKey := c.userPublicKey
	c.mu.Unlock()

	if isEncrypt {
		vaultMasterKey := generateKey()
		salt := generateSalt()

		encryptedKey, err := rsaEncrypt([]byte(vaultMasterKey), pubKey)
		if err != nil {
			return "", fmt.Errorf("encrypt vault master key: %w", err)
		}

		payload["masterKeyEncrypted"] = base64.StdEncoding.EncodeToString(encryptedKey)
		payload["masterKeyHash"] = sha256Hex(vaultMasterKey + salt)
		payload["salt"] = salt

		if typeID != "" {
			adminsKeys, err := c.getVaultTypeAdminsKeys(ctx, typeID, vaultMasterKey)
			if err != nil {
				return "", err
			}
			payload["typeId"] = typeID
			payload["administratorsKeys"] = adminsKeys
		}
	} else if typeID != "" {
		payload["typeId"] = typeID
	}

	var resp struct {
		ID string `json:"id"`
	}
	if err := c.call(ctx, "POST", "/api/v1/vaults", payload, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

// GetVault returns vault metadata for the given ID.
func (c *Client) GetVault(ctx context.Context, id string) (*Vault, error) {
	var vault Vault
	if err := c.call(ctx, "GET", "/api/v1/vaults/"+id, nil, &vault); err != nil {
		return nil, err
	}
	return &vault, nil
}

// getVaultPassword RSA-decrypts the vault's masterKeyEncrypted field using the
// user's private key. Returns an empty string when encryption is inactive.
func (c *Client) getVaultPassword(vault *Vault) (string, error) {
	c.mu.Lock()
	isEncrypt := c.isEncrypt
	privKey := c.userPrivateKey
	c.mu.Unlock()

	if !isEncrypt || vault.MasterKeyEncrypted == "" {
		return "", nil
	}

	key, err := rsaDecrypt(vault.MasterKeyEncrypted, privKey)
	if err != nil {
		return "", fmt.Errorf("decrypt vault master key: %w", err)
	}
	return string(key), nil
}

package passwork

import (
	"context"
	"encoding/base64"
	"fmt"
)

// GetVaultTypes returns all vault types defined on the server.
func (c *Client) GetVaultTypes(ctx context.Context) ([]VaultType, error) {
	var resp struct {
		Items []VaultType `json:"items"`
	}
	if err := c.call(ctx, "GET", "/api/v1/vault-types/all", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// FindVaultType searches vault types by code, name, or ID. Only one filter
// should be non-empty; the first matching type is returned, or nil if not found.
func (c *Client) FindVaultType(ctx context.Context, code, name, id string) (*VaultType, error) {
	types, err := c.GetVaultTypes(ctx)
	if err != nil {
		return nil, err
	}

	for i := range types {
		switch {
		case code != "" && types[i].Code == code:
			return &types[i], nil
		case name != "" && types[i].Name == name:
			return &types[i], nil
		case id != "" && types[i].ID == id:
			return &types[i], nil
		}
	}
	return nil, nil
}

// getVaultTypeAdminsKeys returns a map of adminID → RSA-encrypted vault master
// key for all administrators of the given vault type. Used when creating a vault
// that belongs to a type with managed access.
func (c *Client) getVaultTypeAdminsKeys(ctx context.Context, vaultTypeID, vaultMasterKey string) (map[string]string, error) {
	c.mu.Lock()
	isEncrypt := c.isEncrypt
	c.mu.Unlock()

	if !isEncrypt || vaultTypeID == "" {
		return map[string]string{}, nil
	}

	var resp struct {
		Items []VaultTypeAdmin `json:"items"`
	}
	if err := c.call(ctx, "GET", "/api/v1/vault-types/"+vaultTypeID+"/administrators", nil, &resp); err != nil {
		return nil, fmt.Errorf("fetch vault type admins: %w", err)
	}

	keys := make(map[string]string, len(resp.Items))
	for _, admin := range resp.Items {
		ct, err := rsaEncrypt([]byte(vaultMasterKey), admin.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt master key for admin %s: %w", admin.ID, err)
		}
		keys[admin.ID] = base64.StdEncoding.EncodeToString(ct)
	}
	return keys, nil
}

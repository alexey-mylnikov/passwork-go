package passwork

import (
	"context"
	"fmt"
)

// GetUserPublicKey returns the RSA public key for the given user ID.
func (c *Client) GetUserPublicKey(ctx context.Context, userID string) (string, error) {
	var resp struct {
		PublicKey string `json:"publicKey"`
	}
	if err := c.call(ctx, "GET", "/api/v1/users/"+userID+"/public-key", nil, &resp); err != nil {
		return "", err
	}
	return resp.PublicKey, nil
}

// CreateUser creates a new user, auto-generating a password (and a master key
// if client-side encryption is active). Returns the user ID, the generated
// password, and the master password (empty when encryption is off).
func (c *Client) CreateUser(ctx context.Context, userData map[string]interface{}) (*CreateUserResult, error) {
	var appSettings struct {
		AuthPasswordComplexity   PasswordComplexity `json:"authPasswordComplexity"`
		MasterPasswordComplexity PasswordComplexity `json:"masterPasswordComplexity"`
	}
	if err := c.call(ctx, "GET", "/api/v1/app/settings", nil, &appSettings); err != nil {
		return nil, fmt.Errorf("fetch app settings: %w", err)
	}

	password := GenerateUserPassword(12, appSettings.AuthPasswordComplexity)
	userData["password"] = password

	masterPassword := ""

	c.mu.Lock()
	isEncrypt := c.isEncrypt
	c.mu.Unlock()

	if isEncrypt {
		masterPassword = GenerateUserPassword(12, appSettings.MasterPasswordComplexity)

		var newOptsResp MasterKeyNewOptionsResponse
		if err := c.call(ctx, "GET", "/api/v1/users/master-key/new-options", nil, &newOptsResp); err != nil {
			return nil, fmt.Errorf("fetch master key new options: %w", err)
		}

		masterKey, optsStr, err := deriveMasterKey(masterPassword, newOptsResp)
		if err != nil {
			return nil, fmt.Errorf("derive master key: %w", err)
		}

		userData["masterKeyHash"] = sha256Hex(masterKey)
		userData["masterKeyOptions"] = optsStr

		pub, privEnc, err := GenerateUserRSAKeys(masterPassword)
		if err != nil {
			return nil, fmt.Errorf("generate user RSA keys: %w", err)
		}
		userData["keys"] = map[string]string{
			"public":           pub,
			"privateEncrypted": privEnc,
		}
	}

	var resp struct {
		ID string `json:"id"`
	}
	if err := c.call(ctx, "POST", "/api/v1/users", userData, &resp); err != nil {
		return nil, err
	}

	return &CreateUserResult{
		UserID:         resp.ID,
		Password:       password,
		MasterPassword: masterPassword,
	}, nil
}

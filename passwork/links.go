package passwork

import (
	"context"
	"fmt"
)

// CreateLink creates a shareable public link for a password item or shortcut.
//
// linkType is one of LinkTypeSingleUse / LinkTypeReusable.
// expirationTime is one of LinkExpirationHour / LinkExpirationWeek /
// LinkExpirationMonth / LinkExpirationUnlimited.
//
// Exactly one of itemID or shortcutID must be non-empty.
//
// Returns the full URL (including the #code= fragment when encryption is active).
func (c *Client) CreateLink(ctx context.Context, linkType, expirationTime, itemID, shortcutID string) (string, error) {
	var item *Item

	if shortcutID != "" {
		sc, err := c.GetShortcut(ctx, shortcutID)
		if err != nil {
			return "", fmt.Errorf("get shortcut: %w", err)
		}
		item = sc.Password
	} else {
		var err error
		item, err = c.GetItem(ctx, itemID)
		if err != nil {
			return "", fmt.Errorf("get item: %w", err)
		}
	}

	itemData := map[string]interface{}{
		"name":        item.Name,
		"login":       item.Login,
		"url":         item.URL,
		"description": item.Description,
	}

	c.mu.Lock()
	isEncrypt := c.isEncrypt
	privKey := c.userPrivateKey
	c.mu.Unlock()

	var code string
	var linkKeyHash, linkKeyEncrypted string

	if isEncrypt {
		code = generateKey()

		encKey, err := encryptionKeyFromItem(item.VaultMasterKeyEncrypted, item.KeyEncrypted, privKey)
		if err != nil {
			return "", fmt.Errorf("derive item key: %w", err)
		}

		linkKeyHash = sha256Hex(code)

		linkKeyEnc, err := encryptAES([]byte(code), encKey)
		if err != nil {
			return "", fmt.Errorf("encrypt link key: %w", err)
		}
		linkKeyEncrypted = linkKeyEnc

		vault, err := c.GetVault(ctx, item.VaultID)
		if err != nil {
			return "", fmt.Errorf("get vault: %w", err)
		}
		vaultPassword, err := c.getVaultPassword(vault)
		if err != nil {
			return "", err
		}

		// Re-encrypt the password under the link code.
		if item.Password != "" {
			enc, err := encryptAES([]byte(item.Password), code)
			if err != nil {
				return "", fmt.Errorf("encrypt password for link: %w", err)
			}
			itemData["passwordEncrypted"] = enc
		}

		// Re-encrypt each attachment's key under the link code.
		if len(item.Attachments) > 0 {
			linkAtts := make([]map[string]interface{}, 0, len(item.Attachments))
			for _, att := range item.Attachments {
				attKey, err := decryptAES(att.EncryptedKey, encKey)
				if err != nil {
					return "", fmt.Errorf("decrypt attachment key for link: %w", err)
				}
				reEnc, err := encryptAES(attKey, code)
				if err != nil {
					return "", fmt.Errorf("re-encrypt attachment key: %w", err)
				}
				linkAtts = append(linkAtts, map[string]interface{}{
					"id":           att.ID,
					"name":         att.Name,
					"encryptedKey": reEnc,
				})
			}
			itemData["attachments"] = linkAtts
		}

		// Re-encrypt custom fields under the link code.
		if len(item.Customs) > 0 {
			enc, err := encryptCustomFields(item.Customs, code)
			if err != nil {
				return "", fmt.Errorf("encrypt custom fields for link: %w", err)
			}
			itemData["customs"] = enc
		}

		_ = vaultPassword // used indirectly via getVaultPassword for context
	} else {
		if item.PasswordEncrypted != "" {
			itemData["passwordEncrypted"] = item.PasswordEncrypted
		}
		if len(item.Attachments) > 0 {
			itemData["attachments"] = item.Attachments
		}

		// Encrypt custom fields without a key (base64 only).
		if len(item.Customs) > 0 {
			enc, err := encryptCustomFields(item.Customs, "")
			if err != nil {
				return "", err
			}
			itemData["customs"] = enc
		}
	}

	payload := map[string]interface{}{
		"itemId":         item.ID,
		"itemData":       itemData,
		"type":           linkType,
		"expirationTime": expirationTime,
	}
	if linkKeyHash != "" {
		payload["keyHash"] = linkKeyHash
	}
	if linkKeyEncrypted != "" {
		payload["keyEncrypted"] = linkKeyEncrypted
	}
	if shortcutID != "" {
		payload["shortcutId"] = shortcutID
	}

	var resp struct {
		URL string `json:"url"`
	}
	if err := c.call(ctx, "POST", "/api/v1/links", payload, &resp); err != nil {
		return "", err
	}

	url := resp.URL
	if code != "" {
		url = url + "#code=" + code
	}
	return url, nil
}

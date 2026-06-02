package passwork

import (
	"context"
	"encoding/base64"
	"fmt"
)

// GetInboxItem fetches a shared inbox item by ID and decrypts it when
// client-side encryption is active.
func (c *Client) GetInboxItem(ctx context.Context, inboxItemID string) (*InboxItem, error) {
	var item InboxItem
	if err := c.call(ctx, "GET", "/api/v1/inbox-items/"+inboxItemID, nil, &item); err != nil {
		return nil, err
	}

	c.mu.Lock()
	isEncrypt := c.isEncrypt
	privKey := c.userPrivateKey
	c.mu.Unlock()

	if isEncrypt && item.Inbox != nil && item.Inbox.KeyEncrypted != "" {
		vaultPassword, err := rsaDecrypt(item.Inbox.KeyEncrypted, privKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt inbox key: %w", err)
		}

		if item.PasswordEncrypted != "" {
			plain, err := decryptAES(item.PasswordEncrypted, string(vaultPassword))
			if err != nil {
				return nil, fmt.Errorf("decrypt inbox password: %w", err)
			}
			item.Password = string(plain)
		}
	} else if item.PasswordEncrypted != "" {
		b, err := base64.StdEncoding.DecodeString(item.PasswordEncrypted)
		if err != nil {
			return nil, fmt.Errorf("decode inbox password: %w", err)
		}
		item.Password = string(b)
	}

	return &item, nil
}

// DownloadInboxAttachment downloads and decrypts all attachments of an inbox
// item, writing each file to downloadDir.
func (c *Client) DownloadInboxAttachment(ctx context.Context, item *InboxItem, downloadDir string) error {
	if len(item.Attachments) == 0 {
		return nil
	}

	c.mu.Lock()
	isEncrypt := c.isEncrypt
	privKey := c.userPrivateKey
	c.mu.Unlock()

	encKey := ""
	if isEncrypt && item.Inbox != nil && item.Inbox.KeyEncrypted != "" {
		key, err := rsaDecrypt(item.Inbox.KeyEncrypted, privKey)
		if err != nil {
			return fmt.Errorf("decrypt inbox key: %w", err)
		}
		encKey = string(key)
	}

	for _, att := range item.Attachments {
		full, err := c.GetItemAttachment(ctx, item.ID, att.ID)
		if err != nil {
			return fmt.Errorf("fetch inbox attachment %s: %w", att.ID, err)
		}
		if err := saveAttachment(ctx, *full, encKey, downloadDir); err != nil {
			return err
		}
	}
	return nil
}

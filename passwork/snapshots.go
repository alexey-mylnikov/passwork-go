package passwork

import (
	"context"
	"fmt"
)

// GetSnapshot fetches a password snapshot and decrypts it when client-side
// encryption is active. The snapshot's encryption key is tied to the parent
// item's vault master key.
func (c *Client) GetSnapshot(ctx context.Context, itemID, snapshotID string) (*Item, error) {
	var snapshot Item
	if err := c.call(ctx, "GET", "/api/v1/items/"+itemID+"/snapshot/"+snapshotID, nil, &snapshot); err != nil {
		return nil, err
	}

	c.mu.Lock()
	isEncrypt := c.isEncrypt
	privKey := c.userPrivateKey
	c.mu.Unlock()

	encKey := ""
	if isEncrypt {
		item, err := c.GetItem(ctx, itemID)
		if err != nil {
			return nil, fmt.Errorf("get parent item for snapshot: %w", err)
		}
		encKey, err = encryptionKeyFromItem(
			item.VaultMasterKeyEncrypted,
			snapshot.KeyEncrypted,
			privKey,
		)
		if err != nil {
			return nil, fmt.Errorf("derive snapshot encryption key: %w", err)
		}
	}

	if err := decryptItem(&snapshot, encKey); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

// GetSnapshotAttachment fetches raw attachment data for a snapshot attachment.
func (c *Client) GetSnapshotAttachment(ctx context.Context, snapshotID, attachmentID string) (*Attachment, error) {
	var att Attachment
	if err := c.call(ctx, "GET", "/api/v1/snapshots/"+snapshotID+"/attachment/"+attachmentID, nil, &att); err != nil {
		return nil, err
	}
	return &att, nil
}

// DownloadSnapshotAttachments downloads and decrypts all attachments of a
// snapshot, writing each file to downloadDir.
func (c *Client) DownloadSnapshotAttachments(ctx context.Context, snapshot *Item, downloadDir string) error {
	if len(snapshot.Attachments) == 0 {
		return nil
	}

	c.mu.Lock()
	isEncrypt := c.isEncrypt
	privKey := c.userPrivateKey
	c.mu.Unlock()

	encKey := ""
	if isEncrypt {
		item, err := c.GetItem(ctx, snapshot.VaultID)
		if err != nil {
			return fmt.Errorf("get parent item for snapshot attachments: %w", err)
		}
		encKey, err = encryptionKeyFromItem(
			item.VaultMasterKeyEncrypted,
			snapshot.KeyEncrypted,
			privKey,
		)
		if err != nil {
			return fmt.Errorf("derive snapshot encryption key: %w", err)
		}
	}

	for _, att := range snapshot.Attachments {
		full, err := c.GetSnapshotAttachment(ctx, snapshot.ID, att.ID)
		if err != nil {
			return fmt.Errorf("fetch snapshot attachment %s: %w", att.ID, err)
		}
		if err := saveAttachment(ctx, *full, encKey, downloadDir); err != nil {
			return err
		}
	}
	return nil
}

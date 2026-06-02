package passwork

import (
	"context"
	"encoding/json"
	"fmt"
)

// CreateShortcut creates a shortcut pointing to itemID in vaultID.
// If client-side encryption is active, the item's encryption key is re-encrypted
// for the target vault.
func (c *Client) CreateShortcut(ctx context.Context, itemID, vaultID string, folderID *string) (string, error) {
	item, err := c.GetItem(ctx, itemID)
	if err != nil {
		return "", fmt.Errorf("get item: %w", err)
	}

	var encKey *string

	c.mu.Lock()
	isEncrypt := c.isEncrypt
	privKey := c.userPrivateKey
	c.mu.Unlock()

	if isEncrypt {
		itemEncKey, err := encryptionKeyFromItem(
			item.VaultMasterKeyEncrypted,
			item.KeyEncrypted,
			privKey,
		)
		if err != nil {
			return "", fmt.Errorf("derive item key: %w", err)
		}

		vault, err := c.GetVault(ctx, vaultID)
		if err != nil {
			return "", fmt.Errorf("get target vault: %w", err)
		}

		vaultPassword, err := c.getVaultPassword(vault)
		if err != nil {
			return "", err
		}

		enc, err := encryptAES([]byte(itemEncKey), vaultPassword)
		if err != nil {
			return "", fmt.Errorf("encrypt shortcut key: %w", err)
		}
		encKey = &enc
	}

	payload := map[string]interface{}{
		"vaultId": vaultID,
		"itemId":  itemID,
	}
	if folderID != nil {
		payload["folderId"] = *folderID
	}
	if encKey != nil {
		payload["keyEncrypted"] = *encKey
	}

	var resp struct {
		ID string `json:"id"`
	}
	if err := c.call(ctx, "POST", "/api/v1/shortcuts", payload, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

// GetShortcut fetches a shortcut by ID. The underlying item is fetched and
// decrypted, and stored in Shortcut.Password.
func (c *Client) GetShortcut(ctx context.Context, shortcutID string) (*Shortcut, error) {
	var sc Shortcut
	if err := c.call(ctx, "GET", "/api/v1/shortcuts/"+shortcutID, nil, &sc); err != nil {
		return nil, err
	}

	item, err := c.GetItem(ctx, sc.ID)
	if err != nil {
		return nil, fmt.Errorf("get shortcut item: %w", err)
	}
	sc.Password = item
	return &sc, nil
}

// SearchShortcut searches for shortcuts matching the given criteria.
func (c *Client) SearchShortcut(ctx context.Context, opts SearchOptions) ([]json.RawMessage, error) {
	payload := map[string]interface{}{}
	if opts.Query != "" {
		payload["query"] = opts.Query
	}
	if len(opts.Tags) > 0 {
		payload["tags"] = opts.Tags
	}
	if len(opts.ColorCodes) > 0 {
		payload["colorCodes"] = opts.ColorCodes
	}
	if len(opts.VaultIDs) > 0 {
		payload["vaultIds"] = opts.VaultIDs
	}
	if len(opts.FolderIDs) > 0 {
		payload["folderIds"] = opts.FolderIDs
	}

	var resp struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := c.call(ctx, "GET", "/api/v1/shortcuts/search", payload, &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// SearchAndDecryptShortcut searches for shortcuts and returns fully decrypted
// results (including the underlying item's password).
func (c *Client) SearchAndDecryptShortcut(ctx context.Context, opts SearchOptions) ([]*Shortcut, error) {
	results, err := c.SearchShortcut(ctx, opts)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}

	// Extract shortcut IDs from search results.
	type searchItem struct {
		Shortcut struct {
			ID string `json:"id"`
		} `json:"shortcut"`
	}

	ids := make([]string, 0, len(results))
	for _, raw := range results {
		var si searchItem
		if err := json.Unmarshal(raw, &si); err == nil && si.Shortcut.ID != "" {
			ids = append(ids, si.Shortcut.ID)
		}
	}

	return c.getShortcutItems(ctx, ids)
}

// getShortcutItems fetches shortcuts in batch and resolves their items.
func (c *Client) getShortcutItems(ctx context.Context, ids []string) ([]*Shortcut, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	reqs := make([]batchRequestItem, len(ids))
	for i, id := range ids {
		reqs[i] = batchRequestItem{Method: "GET", RelativeURL: "/api/v1/shortcuts/" + id}
	}

	raws, err := c.sendBatch(ctx, reqs)
	if err != nil {
		return nil, err
	}

	// Parse shortcuts and collect item IDs for batch item fetch.
	shortcuts := make(map[string]*Shortcut, len(raws))
	itemIDs := make([]string, 0, len(raws))

	for _, raw := range raws {
		var sc Shortcut
		if err := json.Unmarshal(raw, &sc); err != nil {
			return nil, fmt.Errorf("unmarshal shortcut: %w", err)
		}
		shortcuts[sc.ID] = &sc
		itemIDs = append(itemIDs, sc.ID)
	}

	items, err := c.GetItems(ctx, itemIDs)
	if err != nil {
		return nil, err
	}

	for _, item := range items {
		if sc, ok := shortcuts[item.ID]; ok {
			sc.Password = item
		}
	}

	result := make([]*Shortcut, 0, len(shortcuts))
	for _, sc := range shortcuts {
		result = append(result, sc)
	}
	return result, nil
}

// DownloadShortcutAttachment downloads and decrypts attachments for a shortcut.
func (c *Client) DownloadShortcutAttachment(ctx context.Context, sc *Shortcut, downloadDir string) error {
	if sc.Password == nil {
		return fmt.Errorf("shortcut has no resolved item; call GetShortcut first")
	}
	return c.DownloadAttachment(ctx, sc.Password, downloadDir)
}

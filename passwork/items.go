package passwork

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CreateItem creates a new password item. item.VaultID must be set.
// If client-side encryption is active the password and custom fields are
// encrypted before sending to the server.
// Returns the new item's ID.
func (c *Client) CreateItem(ctx context.Context, item Item) (string, error) {
	vault, err := c.GetVault(ctx, item.VaultID)
	if err != nil {
		return "", fmt.Errorf("get vault: %w", err)
	}

	vaultPassword, err := c.getVaultPassword(vault)
	if err != nil {
		return "", err
	}

	encKey := ""
	c.mu.Lock()
	isEncrypt := c.isEncrypt
	c.mu.Unlock()

	if isEncrypt {
		if vault.MasterKeyEncrypted != "" {
			encKey = generateKey()
		} else {
			encKey = vaultPassword
		}
	}

	payload, err := c.encryptItemPayload(item, encKey, vaultPassword)
	if err != nil {
		return "", err
	}
	if _, ok := payload["name"]; !ok {
		payload["name"] = ""
	}

	var resp struct {
		ID string `json:"id"`
	}
	if err := c.call(ctx, "POST", "/api/v1/items", payload, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

// UpdateItem updates an existing item. item.VaultID must be set.
func (c *Client) UpdateItem(ctx context.Context, itemID string, item Item) error {
	vault, err := c.GetVault(ctx, item.VaultID)
	if err != nil {
		return fmt.Errorf("get vault: %w", err)
	}

	vaultPassword, err := c.getVaultPassword(vault)
	if err != nil {
		return err
	}

	encKey := ""
	c.mu.Lock()
	isEncrypt := c.isEncrypt
	privKey := c.userPrivateKey
	c.mu.Unlock()

	if isEncrypt {
		existing, err := c.GetItem(ctx, itemID)
		if err != nil {
			return fmt.Errorf("get existing item: %w", err)
		}
		encKey, err = encryptionKeyFromItem(
			existing.VaultMasterKeyEncrypted,
			existing.KeyEncrypted,
			privKey,
		)
		if err != nil {
			return err
		}
		item.KeyEncrypted = existing.KeyEncrypted
	}

	payload, err := c.encryptItemPayload(item, encKey, vaultPassword)
	if err != nil {
		return err
	}

	return c.call(ctx, "PATCH", "/api/v1/items/"+itemID, payload, nil)
}

// DeleteItem moves an item to the bin. Returns the bin item ID.
func (c *Client) DeleteItem(ctx context.Context, itemID string) (string, error) {
	var resp struct {
		BinItemID string `json:"binItemId"`
	}
	if err := c.call(ctx, "DELETE", "/api/v1/items/"+itemID, nil, &resp); err != nil {
		return "", err
	}
	return resp.BinItemID, nil
}

// GetItem fetches a single item and decrypts it if encryption is active.
func (c *Client) GetItem(ctx context.Context, itemID string) (*Item, error) {
	var item Item
	if err := c.call(ctx, "GET", "/api/v1/items/"+itemID, nil, &item); err != nil {
		return nil, err
	}

	c.mu.Lock()
	isEncrypt := c.isEncrypt
	privKey := c.userPrivateKey
	c.mu.Unlock()

	encKey := ""
	if isEncrypt {
		var err error
		encKey, err = encryptionKeyFromItem(item.VaultMasterKeyEncrypted, item.KeyEncrypted, privKey)
		if err != nil {
			return nil, fmt.Errorf("derive item encryption key: %w", err)
		}
	}

	if err := decryptItem(&item, encKey); err != nil {
		return nil, err
	}
	return &item, nil
}

// GetItems fetches and decrypts multiple items in parallel batch requests.
func (c *Client) GetItems(ctx context.Context, itemIDs []string) ([]*Item, error) {
	if len(itemIDs) == 0 {
		return nil, nil
	}

	reqs := make([]batchRequestItem, len(itemIDs))
	for i, id := range itemIDs {
		reqs[i] = batchRequestItem{Method: "GET", RelativeURL: "/api/v1/items/" + id}
	}

	raws, err := c.sendBatch(ctx, reqs)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	isEncrypt := c.isEncrypt
	privKey := c.userPrivateKey
	c.mu.Unlock()

	items := make([]*Item, 0, len(raws))
	for _, raw := range raws {
		var item Item
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("unmarshal item: %w", err)
		}

		encKey := ""
		if isEncrypt {
			encKey, err = encryptionKeyFromItem(item.VaultMasterKeyEncrypted, item.KeyEncrypted, privKey)
			if err != nil {
				return nil, fmt.Errorf("derive item encryption key: %w", err)
			}
		}

		if err := decryptItem(&item, encKey); err != nil {
			return nil, err
		}
		items = append(items, &item)
	}
	return items, nil
}

// SearchItems searches for items matching the given criteria. Returns summary
// items (not yet decrypted). Use SearchAndDecrypt to get decrypted results.
func (c *Client) SearchItems(ctx context.Context, opts SearchOptions) ([]Item, error) {
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
		Items []Item `json:"items"`
	}
	if err := c.call(ctx, "GET", "/api/v1/items/search", payload, &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// SearchAndDecrypt searches for items and returns fully decrypted results.
func (c *Client) SearchAndDecrypt(ctx context.Context, opts SearchOptions) ([]*Item, error) {
	results, err := c.SearchItems(ctx, opts)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}

	ids := make([]string, len(results))
	for i, item := range results {
		ids[i] = item.ID
	}
	return c.GetItems(ctx, ids)
}

// DownloadAttachment downloads and decrypts all attachments of item, writing
// each file to downloadDir. The item must have been retrieved via GetItem.
func (c *Client) DownloadAttachment(ctx context.Context, item *Item, downloadDir string) error {
	if len(item.Attachments) == 0 {
		return nil
	}

	c.mu.Lock()
	isEncrypt := c.isEncrypt
	privKey := c.userPrivateKey
	c.mu.Unlock()

	encKey := ""
	if isEncrypt {
		var err error
		encKey, err = encryptionKeyFromItem(item.VaultMasterKeyEncrypted, item.KeyEncrypted, privKey)
		if err != nil {
			return err
		}
	}

	for _, att := range item.Attachments {
		full, err := c.GetItemAttachment(ctx, item.ID, att.ID)
		if err != nil {
			return fmt.Errorf("fetch attachment %s: %w", att.ID, err)
		}
		if err := saveAttachment(ctx, *full, encKey, downloadDir); err != nil {
			return err
		}
	}
	return nil
}

// GetItemAttachment fetches raw attachment data for a single attachment.
func (c *Client) GetItemAttachment(ctx context.Context, itemID, attachmentID string) (*Attachment, error) {
	var att Attachment
	if err := c.call(ctx, "GET", "/api/v1/items/"+itemID+"/attachment/"+attachmentID, nil, &att); err != nil {
		return nil, err
	}
	return &att, nil
}

// encryptItemPayload builds the request payload, encrypting sensitive fields.
func (c *Client) encryptItemPayload(item Item, encKey, vaultPassword string) (map[string]interface{}, error) {
	payload := map[string]interface{}{}

	// Scalar fields
	setIfNotEmpty := func(k, v string) {
		if v != "" {
			payload[k] = v
		}
	}
	setIfNotEmpty("name", item.Name)
	setIfNotEmpty("login", item.Login)
	setIfNotEmpty("url", item.URL)
	setIfNotEmpty("description", item.Description)
	setIfNotEmpty("vaultId", item.VaultID)
	setIfNotEmpty("folderId", item.FolderID)
	setIfNotEmpty("keyEncrypted", item.KeyEncrypted)
	if len(item.Tags) > 0 {
		payload["tags"] = item.Tags
	}
	if item.ColorCode != 0 {
		payload["colorCode"] = item.ColorCode
	}

	// Password
	if item.Password != "" {
		enc, err := encryptAES([]byte(item.Password), encKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt password: %w", err)
		}
		payload["passwordEncrypted"] = enc

		if item.KeyEncrypted == "" {
			keyEnc, err := encryptAES([]byte(encKey), vaultPassword)
			if err != nil {
				return nil, fmt.Errorf("encrypt item key: %w", err)
			}
			payload["keyEncrypted"] = keyEnc
		}
	}

	// Custom fields
	if len(item.Customs) > 0 {
		encrypted, err := encryptCustomFields(item.Customs, encKey)
		if err != nil {
			return nil, err
		}
		payload["customs"] = encrypted
	}

	// Attachments (upload path)
	if len(item.Attachments) > 0 {
		atts, err := buildAttachmentPayload(item.Attachments, encKey)
		if err != nil {
			return nil, err
		}
		payload["attachments"] = atts
	}

	return payload, nil
}

// decryptItem decrypts the password and custom fields of an item in place.
func decryptItem(item *Item, encKey string) error {
	if item.PasswordEncrypted != "" {
		var err error
		var plain []byte
		if encKey != "" {
			plain, err = decryptAES(item.PasswordEncrypted, encKey)
		} else {
			plain, err = base64.StdEncoding.DecodeString(item.PasswordEncrypted)
		}
		if err != nil {
			return fmt.Errorf("decrypt password: %w", err)
		}
		item.Password = string(plain)
	}

	for i := range item.Customs {
		if err := decryptCustomField(&item.Customs[i], encKey); err != nil {
			return fmt.Errorf("decrypt custom field: %w", err)
		}
	}
	return nil
}

// decryptCustomField decrypts the name, type, and value of a custom field.
func decryptCustomField(f *CustomField, encKey string) error {
	dec := func(s string) (string, error) {
		if encKey != "" {
			b, err := decryptAES(s, encKey)
			return string(b), err
		}
		b, err := base64.StdEncoding.DecodeString(s)
		return string(b), err
	}
	var err error
	if f.Name, err = dec(f.Name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	if f.Type, err = dec(f.Type); err != nil {
		return fmt.Errorf("type: %w", err)
	}
	if f.Value, err = dec(f.Value); err != nil {
		return fmt.Errorf("value: %w", err)
	}
	return nil
}

// encryptCustomFields encrypts all fields of each custom field entry.
func encryptCustomFields(customs []CustomField, encKey string) ([]map[string]interface{}, error) {
	result := make([]map[string]interface{}, len(customs))
	for i, f := range customs {
		name, err := encryptAES([]byte(f.Name), encKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt custom name: %w", err)
		}
		typ, err := encryptAES([]byte(f.Type), encKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt custom type: %w", err)
		}
		val, err := encryptAES([]byte(f.Value), encKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt custom value: %w", err)
		}
		result[i] = map[string]interface{}{
			"name":  name,
			"type":  typ,
			"value": val,
		}
	}
	return result, nil
}

// buildAttachmentPayload reads local files and encrypts them for upload.
func buildAttachmentPayload(attachments []Attachment, encKey string) ([]map[string]interface{}, error) {
	result := make([]map[string]interface{}, 0, len(attachments))
	for _, att := range attachments {
		if att.Path == "" {
			continue
		}
		data, err := os.ReadFile(att.Path)
		if err != nil {
			return nil, fmt.Errorf("read attachment file %s: %w", att.Path, err)
		}

		encAttKey, encData, hash, err := encryptAttachment(data, encKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt attachment: %w", err)
		}

		name := att.Name
		if name == "" {
			name = filepath.Base(att.Path)
			ext := filepath.Ext(name)
			if ext != "" {
				name = name[:len(name)-len(ext)]
			}
		}

		result = append(result, map[string]interface{}{
			"encryptedKey":  encAttKey,
			"encryptedData": encData,
			"hash":          hash,
			"name":          name,
		})
	}
	return result, nil
}

// saveAttachment decrypts and writes an attachment to disk.
func saveAttachment(_ context.Context, att Attachment, encKey, dir string) error {
	data, err := decryptAttachment(att, encKey)
	if err != nil {
		return fmt.Errorf("decrypt attachment %s: %w", att.Name, err)
	}

	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create download dir: %w", err)
	}

	dest := filepath.Join(dir, att.Name)
	return os.WriteFile(dest, data, 0600)
}

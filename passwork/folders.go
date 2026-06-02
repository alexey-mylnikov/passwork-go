package passwork

import "context"

// CreateFolder creates a new folder in the given vault. parentID may be empty
// for a root-level folder. Returns the new folder's ID.
func (c *Client) CreateFolder(ctx context.Context, name, vaultID, parentID string) (string, error) {
	payload := map[string]interface{}{
		"name":    name,
		"vaultId": vaultID,
	}
	if parentID != "" {
		payload["parentFolderId"] = parentID
	}

	var resp struct {
		ID string `json:"id"`
	}
	if err := c.call(ctx, "POST", "/api/v1/folders", payload, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

// GetFolders returns folders accessible to the current user. vaultID is
// optional; when non-empty only folders belonging to that vault are returned.
func (c *Client) GetFolders(ctx context.Context, vaultID string) ([]Folder, error) {
	var payload map[string]interface{}
	if vaultID != "" {
		payload = map[string]interface{}{"vaultId": vaultID}
	}

	var resp struct {
		Items []Folder `json:"items"`
	}
	if err := c.call(ctx, "GET", "/api/v1/folders", payload, &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// GetFolder returns folder metadata for the given ID, including its path breadcrumb.
func (c *Client) GetFolder(ctx context.Context, id string) (*Folder, error) {
	var folder Folder
	if err := c.call(ctx, "GET", "/api/v1/folders/"+id, nil, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

// UpdateFolder renames the folder identified by id.
func (c *Client) UpdateFolder(ctx context.Context, id, name string) error {
	return c.call(ctx, "POST", "/api/v1/folders/"+id, map[string]interface{}{"name": name}, nil)
}

// DeleteFolder moves the folder to the bin and returns the resulting bin item ID.
func (c *Client) DeleteFolder(ctx context.Context, id string) (string, error) {
	var resp struct {
		BinItemID string `json:"binItemId"`
	}
	if err := c.call(ctx, "DELETE", "/api/v1/folders/"+id, nil, &resp); err != nil {
		return "", err
	}
	return resp.BinItemID, nil
}

package passwork

import "encoding/json"

// Item represents a password item returned by the API.
// Fields may be encrypted when client-side encryption is active;
// the Get/Search methods return decrypted values.
type Item struct {
	ID                      string        `json:"id,omitempty"`
	Name                    string        `json:"name,omitempty"`
	Login                   string        `json:"login,omitempty"`
	Password                string        `json:"password,omitempty"`
	PasswordEncrypted       string        `json:"passwordEncrypted,omitempty"`
	URL                     string        `json:"url,omitempty"`
	Description             string        `json:"description,omitempty"`
	VaultID                 string        `json:"vaultId,omitempty"`
	FolderID                string        `json:"folderId,omitempty"`
	Tags                    []string      `json:"tags,omitempty"`
	ColorCode               int           `json:"colorCode,omitempty"`
	Customs                 []CustomField `json:"customs,omitempty"`
	Attachments             []Attachment  `json:"attachments,omitempty"`
	KeyEncrypted            string        `json:"keyEncrypted,omitempty"`
	VaultMasterKeyEncrypted string        `json:"vaultMasterKeyEncrypted,omitempty"`
	BinItemID               string        `json:"binItemId,omitempty"`
}

// CustomField is a user-defined field attached to an Item.
type CustomField struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Attachment describes a file attached to an Item.
// Path is only used when uploading; it is not returned by the API.
type Attachment struct {
	ID            string `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	EncryptedKey  string `json:"encryptedKey,omitempty"`
	EncryptedData string `json:"encryptedData,omitempty"`
	Hash          string `json:"hash,omitempty"`
	// Path is a local filesystem path used only when uploading attachments.
	Path string `json:"-"`
}

// Vault represents a password vault.
type Vault struct {
	ID                 string `json:"id,omitempty"`
	Name               string `json:"name,omitempty"`
	MasterKeyEncrypted string `json:"masterKeyEncrypted,omitempty"`
	MasterKeyHash      string `json:"masterKeyHash,omitempty"`
	Salt               string `json:"salt,omitempty"`
	TypeID             string `json:"typeId,omitempty"`
}

// VaultType represents a vault type template.
type VaultType struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Code string `json:"code"`
}

// VaultTypeAdmin represents an administrator of a vault type.
type VaultTypeAdmin struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
}

// FolderPathEntry is a breadcrumb segment returned by GetFolder.
type FolderPathEntry struct {
	VaultID  string `json:"vaultId"`
	Name     string `json:"name"`
	FolderID string `json:"folderId,omitempty"`
}

// Folder represents a directory inside a vault.
type Folder struct {
	ID             string            `json:"id,omitempty"`
	Name           string            `json:"name,omitempty"`
	VaultID        string            `json:"vaultId,omitempty"`
	ParentFolderID string            `json:"parentFolderId,omitempty"`
	Color          int               `json:"color,omitempty"`
	Permissions    []string          `json:"permissions,omitempty"`
	Path           []FolderPathEntry `json:"path,omitempty"`
}

// InboxItem represents a password shared via the inbox mechanism.
type InboxItem struct {
	ID                string       `json:"id,omitempty"`
	Password          string       `json:"password,omitempty"`
	PasswordEncrypted string       `json:"passwordEncrypted,omitempty"`
	Attachments       []Attachment `json:"attachments,omitempty"`
	Inbox             *InboxMeta   `json:"inbox,omitempty"`
}

// InboxMeta holds the encryption key for an inbox item.
type InboxMeta struct {
	KeyEncrypted string `json:"keyEncrypted,omitempty"`
}

// Shortcut represents a shortcut (alias) pointing to an item in another vault.
type Shortcut struct {
	ID           string `json:"id,omitempty"`
	VaultID      string `json:"vaultId,omitempty"`
	FolderID     string `json:"folderId,omitempty"`
	ItemID       string `json:"itemId,omitempty"`
	KeyEncrypted string `json:"keyEncrypted,omitempty"`
	// Password is populated by GetShortcut with the underlying item data.
	Password *Item `json:"password,omitempty"`
}

// Feature represents an application feature flag.
type Feature struct {
	Name string `json:"name"`
}

// UserKeys holds the user's RSA key pair as returned by the API.
type UserKeys struct {
	Public           string `json:"public"`
	PrivateEncrypted string `json:"privateEncrypted"`
}

// MasterKeyOptionsResponse is returned by GET /api/v1/users/master-key/options.
type MasterKeyOptionsResponse struct {
	MasterKeyOptions string `json:"masterKeyOptions"`
}

// MasterKeyNewOptionsResponse is returned by GET /api/v1/users/master-key/new-options.
type MasterKeyNewOptionsResponse struct {
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Bytes      int    `json:"bytes"`
	Digest     string `json:"digest"`
}

// TokenPair holds an access/refresh token pair as returned by session endpoints.
type TokenPair struct {
	AccessToken           string `json:"accessToken"`
	RefreshToken          string `json:"refreshToken"`
	AccessTokenExpiredAt  int64  `json:"accessTokenExpiredAt"`
	RefreshTokenExpiredAt int64  `json:"refreshTokenExpiredAt"`
}

// SearchOptions carries optional filters for item/shortcut search.
type SearchOptions struct {
	Query      string
	Tags       []string
	ColorCodes []int
	VaultIDs   []string
	FolderIDs  []string
}

// PasswordComplexity describes server-enforced password requirements.
type PasswordComplexity struct {
	MinLength                   int  `json:"minLength"`
	IsDigitsRequired            bool `json:"isDigitsRequired"`
	IsUppercaseRequired         bool `json:"isUppercaseRequired"`
	IsSpecialCharactersRequired bool `json:"isSpecialCharactersRequired"`
}

// CreateUserResult is returned by CreateUser.
type CreateUserResult struct {
	UserID         string
	Password       string
	MasterPassword string
}

// batchRequestItem is a single request in a batch call.
type batchRequestItem struct {
	Method      string                 `json:"method"`
	RelativeURL string                 `json:"relativeUrl"`
	Body        map[string]interface{} `json:"body,omitempty"`
}

// batchResponseItem is a single response from a batch call.
type batchResponseItem struct {
	StatusCode int             `json:"statusCode"`
	Body       json.RawMessage `json:"body"`
}

// apiErrorItem represents a single error returned in an API error response.
type apiErrorItem struct {
	Code    string `json:"code"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// sessionData is the structure persisted to the session file.
type sessionData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	MasterKey    string `json:"master_key"`
}

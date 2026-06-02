package passwork

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// SetTokens stores an access/refresh token pair obtained externally (e.g. from
// the Passwork UI's "Generate pair" button).
func (c *Client) SetTokens(accessToken, refreshToken string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken = accessToken
	c.refreshToken = refreshToken
}

// UpdateTokens exchanges the current refresh token for a new access/refresh
// token pair via POST /api/v1/sessions/refresh. The old pair becomes invalid.
// This method is safe to call concurrently; only the first caller will perform
// the HTTP request, others will see the updated tokens after the lock is released.
func (c *Client) UpdateTokens(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.refreshToken == "" {
		return &PassworkError{Message: "no refresh token available", Code: "no_refresh_token"}
	}

	// Snapshot and clear tokens to prevent recursive refresh attempts.
	oldAccess := c.accessToken
	oldRefresh := c.refreshToken
	c.accessToken = ""
	c.refreshToken = ""

	result, err := c.tokenRequest(ctx, "/api/v1/sessions/refresh",
		map[string]string{"refreshToken": oldRefresh},
		oldAccess)
	if err != nil {
		// Restore tokens so the caller can handle the error.
		c.accessToken = oldAccess
		c.refreshToken = oldRefresh
		return fmt.Errorf("refresh tokens: %w", err)
	}

	c.accessToken = result.AccessToken
	c.refreshToken = result.RefreshToken

	if c.sessionPath != "" {
		_ = c.saveSessionLocked(c.sessionPath, c.sessionEncryptionKey, false)
	}
	return nil
}

// UpdateAccessToken refreshes only the access token via
// POST /api/v1/sessions/refresh-access-token. The refresh token is not changed.
// Available for API-type sessions (tokens generated in the user's Auth panel).
func (c *Client) UpdateAccessToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken == "" {
		return &PassworkError{Message: "no access token available", Code: "no_access_token"}
	}

	oldAccess := c.accessToken
	c.accessToken = ""

	result, err := c.tokenRequest(ctx, "/api/v1/sessions/refresh-access-token",
		map[string]string{"accessToken": oldAccess}, "")
	if err != nil {
		c.accessToken = oldAccess
		return fmt.Errorf("refresh access token: %w", err)
	}

	c.accessToken = result.AccessToken

	if c.sessionPath != "" {
		_ = c.saveSessionLocked(c.sessionPath, c.sessionEncryptionKey, false)
	}
	return nil
}

// UpdateRefreshToken refreshes only the refresh token via
// POST /api/v1/sessions/refresh-refresh-token. The current access token
// remains valid until its own expiry.
// Available for API-type sessions.
func (c *Client) UpdateRefreshToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.refreshToken == "" {
		return &PassworkError{Message: "no refresh token available", Code: "no_refresh_token"}
	}

	oldRefresh := c.refreshToken
	c.refreshToken = ""

	result, err := c.tokenRequest(ctx, "/api/v1/sessions/refresh-refresh-token",
		map[string]string{"refreshToken": oldRefresh}, "")
	if err != nil {
		c.refreshToken = oldRefresh
		return fmt.Errorf("refresh refresh token: %w", err)
	}

	c.refreshToken = result.RefreshToken

	if c.sessionPath != "" {
		_ = c.saveSessionLocked(c.sessionPath, c.sessionEncryptionKey, false)
	}
	return nil
}

// tokenRequest sends a raw POST to a token endpoint, bypassing the normal
// call() machinery to avoid recursion. Must be called with c.mu held.
func (c *Client) tokenRequest(ctx context.Context, endpoint string, body interface{}, bearerToken string) (*TokenPair, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Response-Format", "raw")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	if c.masterKeyHash != "" {
		req.Header.Set("X-Master-Key-Hash", c.masterKeyHash)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, &PassworkError{
			Message: fmt.Sprintf("token endpoint returned HTTP %d", resp.StatusCode),
			Code:    "token_request_failed",
		}
	}

	var pair TokenPair
	if err := json.Unmarshal(data, &pair); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	return &pair, nil
}

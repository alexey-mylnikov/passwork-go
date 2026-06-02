package passwork

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Call makes an authenticated API request to the given endpoint.
//
// payload is sent as JSON body for non-GET methods, or as query parameters for
// GET (slices are expanded as key[]=v1&key[]=v2, matching the PHP server's
// expectation).
//
// out, if non-nil, must be a pointer; the response body is JSON-unmarshalled
// into it. Pass nil to discard the response body.
func (c *Client) Call(ctx context.Context, method, endpoint string, payload map[string]interface{}, out interface{}) error {
	return c.call(ctx, method, endpoint, payload, out)
}

func (c *Client) call(ctx context.Context, method, endpoint string, payload map[string]interface{}, out interface{}) error {
	raw, err := c.doRequest(ctx, method, endpoint, payload)
	if err != nil {
		return err
	}
	if out != nil && len(raw) > 0 && string(raw) != "null" {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// doRequest executes the HTTP request with automatic token refresh on expiry.
func (c *Client) doRequest(ctx context.Context, method, endpoint string, payload map[string]interface{}) (json.RawMessage, error) {
	raw, expired, err := c.rawRequest(ctx, method, endpoint, payload)
	if err != nil {
		return nil, err
	}
	if !expired {
		return raw, nil
	}

	// Access token expired.
	if !c.autoRefresh {
		return nil, &PassworkError{Message: "access token expired", Code: "token_expired"}
	}

	if err := c.UpdateTokens(ctx); err != nil {
		return nil, fmt.Errorf("token refresh: %w", err)
	}

	raw, _, err = c.rawRequest(ctx, method, endpoint, payload)
	return raw, err
}

// rawRequest builds and executes one HTTP request. expired is true when the
// server signals that the access token has expired.
func (c *Client) rawRequest(ctx context.Context, method, endpoint string, payload map[string]interface{}) (raw json.RawMessage, expired bool, err error) {
	req, err := c.buildRequest(ctx, method, endpoint, payload)
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("read body: %w", err)
	}

	data, err := unwrapResponse(body)
	if err != nil {
		return nil, false, err
	}

	if resp.StatusCode >= 400 {
		exp, apiErr := parseAPIError(data, method, req.URL.String(), resp.StatusCode)
		return nil, exp, apiErr
	}

	return data, false, nil
}

// buildRequest constructs the *http.Request with auth headers.
func (c *Client) buildRequest(ctx context.Context, method, endpoint string, payload map[string]interface{}) (*http.Request, error) {
	u := c.host + endpoint

	var body io.Reader
	if strings.ToUpper(method) == "GET" {
		if len(payload) > 0 {
			u = u + "?" + encodeQueryParams(payload)
		}
	} else {
		if payload == nil {
			payload = map[string]interface{}{}
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), u, body)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Ask the server to return plain JSON instead of the default base64 envelope.
	req.Header.Set("X-Response-Format", "raw")

	c.mu.Lock()
	at := c.accessToken
	mkh := c.masterKeyHash
	c.mu.Unlock()

	if at != "" {
		req.Header.Set("Authorization", "Bearer "+at)
	}
	if mkh != "" {
		req.Header.Set("X-Master-Key-Hash", mkh)
	}

	return req, nil
}

// unwrapResponse handles the optional base64 envelope the server may send.
// When X-Response-Format: raw is set, the body is already plain JSON; this
// function is kept as a safety fallback.
func unwrapResponse(body []byte) (json.RawMessage, error) {
	if len(body) == 0 {
		return json.RawMessage("{}"), nil
	}

	// Try to detect the base64 envelope: {"format":"base64","content":"..."}
	var envelope struct {
		Format  string `json:"format"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Format == "base64" {
		decoded, err := base64.StdEncoding.DecodeString(envelope.Content)
		if err != nil {
			return nil, fmt.Errorf("decode base64 envelope: %w", err)
		}
		return json.RawMessage(decoded), nil
	}

	return json.RawMessage(body), nil
}

// parseAPIError extracts error information from an API error response.
// expired is true if the response contains an accessTokenExpired error code.
func parseAPIError(data json.RawMessage, method, rawURL string, statusCode int) (expired bool, err error) {
	var resp struct {
		Errors []apiErrorItem `json:"errors"`
	}
	_ = json.Unmarshal(data, &resp)

	for _, e := range resp.Errors {
		if e.Code == "accessTokenExpired" {
			return true, nil
		}
	}

	msgs := make([]string, 0, len(resp.Errors))
	for _, e := range resp.Errors {
		if e.Field != "" {
			msgs = append(msgs, e.Field+" => "+e.Message)
		} else {
			msgs = append(msgs, e.Message)
		}
	}

	return false, &PassworkResponseError{
		Message:    strings.Join(msgs, "; "),
		URL:        rawURL,
		Method:     method,
		StatusCode: statusCode,
	}
}

// encodeQueryParams serialises a payload map to URL query parameters.
// Slice values are expanded as key[]=v1&key[]=v2 to match PHP server conventions.
func encodeQueryParams(payload map[string]interface{}) string {
	vals := url.Values{}
	for k, v := range payload {
		switch val := v.(type) {
		case []string:
			for _, s := range val {
				vals.Add(k+"[]", s)
			}
		case []int:
			for _, i := range val {
				vals.Add(k+"[]", fmt.Sprintf("%d", i))
			}
		case []interface{}:
			for _, item := range val {
				vals.Add(k+"[]", fmt.Sprintf("%v", item))
			}
		default:
			vals.Set(k, fmt.Sprintf("%v", val))
		}
	}
	return vals.Encode()
}

package passwork

import (
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

// Client is a Passwork API client. It is safe to call its methods concurrently.
// Token refresh operations are serialised by an internal mutex.
//
// Create a client with New, then call SetTokens (or SetMasterPassword/SetMasterKey
// for encrypted vaults) before making API calls.
type Client struct {
	host       string
	httpClient *http.Client

	mu           sync.Mutex
	accessToken  string
	refreshToken string

	// masterKeyHash is sent as X-Master-Key-Hash when client-side encryption is active.
	masterKeyHash string

	// autoRefresh causes a transparent token refresh when the server returns
	// an accessTokenExpired error.
	autoRefresh bool

	// encryption state — set by SetMasterKey / SetMasterPassword.
	isEncrypt      bool
	masterKey      string
	userPrivateKey string
	userPublicKey  string

	// session persistence — set by SaveSession / LoadSession.
	sessionPath          string
	sessionEncryptionKey string

	// features cache — populated lazily by GetFeatures.
	features []Feature
}

// Option is a functional option for New.
type Option func(*Client)

// WithSkipTLSVerify disables TLS certificate verification.
// Use only in development or against self-signed certificates.
func WithSkipTLSVerify() Option {
	return func(c *Client) {
		tr := c.httpClient.Transport.(*http.Transport)
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
}

// WithTimeout sets the HTTP client timeout (default: 30 s).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// WithAutoRefresh enables automatic token refresh when the server returns an
// accessTokenExpired error. The client will call POST /api/v1/sessions/refresh
// once and retry the original request transparently.
func WithAutoRefresh() Option {
	return func(c *Client) {
		c.autoRefresh = true
	}
}

// WithHTTPClient replaces the default HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// New creates a new Passwork API client for the given host URL
// (e.g. "https://passwork.example.com"). The host must not have a trailing slash.
func New(host string, opts ...Option) *Client {
	c := &Client{
		host: trimRight(host, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{},
			},
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// trimRight removes all trailing occurrences of cutset from s.
func trimRight(s, cutset string) string {
	for len(s) > 0 {
		found := false
		for _, c := range cutset {
			if rune(s[len(s)-1]) == c {
				s = s[:len(s)-1]
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return s
}

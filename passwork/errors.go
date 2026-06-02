package passwork

import "fmt"

// PassworkError is returned for client-side logic errors (missing config, expired token, etc.).
type PassworkError struct {
	Message string
	Code    string
}

func (e *PassworkError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s (code: %s)", e.Message, e.Code)
	}
	return e.Message
}

// PassworkResponseError is returned when the API responds with a 4xx/5xx status.
type PassworkResponseError struct {
	Message    string
	URL        string
	Method     string
	StatusCode int
}

func (e *PassworkResponseError) Error() string {
	return fmt.Sprintf("passwork API error: %s [%s %s] (HTTP %d)",
		e.Message, e.Method, e.URL, e.StatusCode)
}

package passwork

import (
	"context"
	"encoding/json"
)

const batchChunkSize = 25

// sendBatch executes a list of batch request items, splitting them into chunks
// of 25 and collecting successful responses.
func (c *Client) sendBatch(ctx context.Context, requests []batchRequestItem) ([]json.RawMessage, error) {
	var results []json.RawMessage

	for i := 0; i < len(requests); i += batchChunkSize {
		end := i + batchChunkSize
		if end > len(requests) {
			end = len(requests)
		}

		chunk, err := c.batchRequest(ctx, requests[i:end])
		if err != nil {
			return nil, err
		}
		results = append(results, chunk...)
	}

	return results, nil
}

// batchRequest sends a single POST /api/v1/batch call and returns the bodies of
// all responses with status code 200.
func (c *Client) batchRequest(ctx context.Context, requests []batchRequestItem) ([]json.RawMessage, error) {
	payload := map[string]interface{}{
		"requests": requests,
	}

	var resp struct {
		Responses []batchResponseItem `json:"responses"`
	}
	if err := c.call(ctx, "POST", "/api/v1/batch", payload, &resp); err != nil {
		return nil, err
	}

	var results []json.RawMessage
	for _, r := range resp.Responses {
		if r.StatusCode == 200 {
			results = append(results, r.Body)
		}
	}
	return results, nil
}

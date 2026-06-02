package passwork

import "context"

// GetFeatures returns the list of enabled application features.
// Results are cached in memory after the first call.
func (c *Client) GetFeatures(ctx context.Context) ([]Feature, error) {
	c.mu.Lock()
	cached := c.features
	c.mu.Unlock()

	if cached != nil {
		return cached, nil
	}

	var features []Feature
	if err := c.call(ctx, "GET", "/api/v1/app/features", nil, &features); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.features = features
	c.mu.Unlock()

	return features, nil
}

// FindFeature returns the feature with the given name, or nil if not found.
func (c *Client) FindFeature(ctx context.Context, name string) (*Feature, error) {
	features, err := c.GetFeatures(ctx)
	if err != nil {
		return nil, err
	}
	for i := range features {
		if features[i].Name == name {
			return &features[i], nil
		}
	}
	return nil, nil
}

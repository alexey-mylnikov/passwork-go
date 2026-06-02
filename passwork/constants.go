package passwork

// LinkType defines the visibility mode for a shared link.
const (
	LinkTypeSingleUse = "single_use"
	LinkTypeReusable  = "reusable"
)

// LinkExpirationTime defines how long a shared link remains valid.
const (
	LinkExpirationHour      = "1 hour"
	LinkExpirationWeek      = "1 week"
	LinkExpirationMonth     = "1 month"
	LinkExpirationUnlimited = "unlimited"
)

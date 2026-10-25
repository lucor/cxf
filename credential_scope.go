package cxf

import "fmt"

// CredentialScope lists websites and Android apps for an item.
type CredentialScope struct {
	// URLs lists credential locations, preferably as RFC 3986 URIs.
	URLs []string `json:"urls"`
	// AndroidApps lists applications that may use these credentials.
	AndroidApps []AndroidAppID `json:"androidApps"`
}

// Validate checks the required scope arrays and Android application records.
func (scope *CredentialScope) Validate() error {
	if scope == nil {
		return invalid("scope", "must not be nil")
	}
	if scope.URLs == nil || scope.AndroidApps == nil {
		return invalid("scope", "required arrays must not be null")
	}
	for i, url := range scope.URLs {
		if err := validateUTF8String(fmt.Sprintf("scope.urls[%d]", i), url); err != nil {
			return err
		}
	}
	return validateAndroidApps(scope.AndroidApps, "scope.androidApps")
}

// UnmarshalJSON decodes and validates a credential scope atomically.
func (scope *CredentialScope) UnmarshalJSON(data []byte) error {
	if scope == nil {
		return invalid("scope", "must not be nil")
	}
	type plain CredentialScope
	var decoded plain
	if err := decodeObject(data, "scope", []string{"urls", "androidApps"}, nil, &decoded); err != nil {
		return err
	}
	candidate := CredentialScope(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*scope = candidate
	return nil
}

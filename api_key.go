package cxf

// CredentialTypeAPIKey is the CXF API key type.
const CredentialTypeAPIKey = "api-key"

// APIKey stores an API key and its optional metadata.
type APIKey struct {
	// Type must be CredentialTypeAPIKey.
	Type string `json:"type"`
	// Key holds the API secret; FieldTypeConcealedString is recommended.
	Key *EditableField `json:"key,omitempty"`
	// Username identifies the account; FieldTypeString is recommended.
	Username *EditableField `json:"username,omitempty"`
	// KeyType describes the key, such as a bearer token; FieldTypeString is recommended.
	KeyType *EditableField `json:"keyType,omitempty"`
	// URL identifies the API endpoint; FieldTypeString is recommended.
	URL *EditableField `json:"url,omitempty"`
	// ValidFrom records when the key becomes valid; FieldTypeDate is recommended.
	ValidFrom *EditableField `json:"validFrom,omitempty"`
	// ExpiryDate records when the key expires; FieldTypeDate is recommended.
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
}

// Validate checks the API key fields.
func (credential *APIKey) Validate() error {
	if credential == nil || credential.Type != CredentialTypeAPIKey {
		return invalid("api-key.type", "invalid credential type")
	}
	return validateOptionalFields("api-key",
		namedEditableField{"key", credential.Key},
		namedEditableField{"username", credential.Username},
		namedEditableField{"keyType", credential.KeyType},
		namedEditableField{"url", credential.URL},
		namedEditableField{"validFrom", credential.ValidFrom},
		namedEditableField{"expiryDate", credential.ExpiryDate},
	)
}

// UnmarshalJSON decodes and validates an API key credential atomically.
func (credential *APIKey) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeAPIKey, "must not be nil")
	}
	type plain APIKey
	var decoded plain
	if err := decodeCredential(data, CredentialTypeAPIKey, "api-key", []string{"type"}, []string{"key", "username", "keyType", "url", "validFrom", "expiryDate"}, &decoded); err != nil {
		return err
	}
	candidate := APIKey(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

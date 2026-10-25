package cxf

// CredentialTypeBasicAuth is the CXF basic-auth type.
const CredentialTypeBasicAuth = "basic-auth"

// BasicAuth stores a username and password.
type BasicAuth struct {
	// Type must be CredentialTypeBasicAuth.
	Type string `json:"type"`
	// Username is optional; FieldTypeString is recommended.
	Username *EditableField `json:"username,omitempty"`
	// Password is optional; FieldTypeConcealedString is recommended.
	Password *EditableField `json:"password,omitempty"`
}

// Validate checks the credential type and editable values.
func (credential *BasicAuth) Validate() error {
	if credential == nil || credential.Type != CredentialTypeBasicAuth {
		return invalid("basic-auth.type", "invalid credential type")
	}
	if credential.Username != nil {
		if err := validateEditableFieldValue(credential.Username, "basic-auth.username"); err != nil {
			return err
		}
	}
	if credential.Password != nil {
		if err := validateEditableFieldValue(credential.Password, "basic-auth.password"); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalJSON decodes and validates a basic-auth credential atomically.
func (credential *BasicAuth) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeBasicAuth, "must not be nil")
	}
	type plain BasicAuth
	var decoded plain
	if err := decodeCredential(data, CredentialTypeBasicAuth, "basic-auth", []string{"type"}, []string{"username", "password"}, &decoded); err != nil {
		return err
	}
	candidate := BasicAuth(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

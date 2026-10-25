package cxf

// CredentialTypeGeneratedPassword is the CXF generated-password type.
const CredentialTypeGeneratedPassword = "generated-password"

// GeneratedPassword stores a password created by a password generator.
type GeneratedPassword struct {
	// Type must be CredentialTypeGeneratedPassword.
	Type string `json:"type"`
	// Password holds the generated secret and should be concealed in the UI.
	Password string `json:"password"`
}

// Validate checks the credential type.
func (credential *GeneratedPassword) Validate() error {
	if credential == nil || credential.Type != CredentialTypeGeneratedPassword {
		return invalid("generated-password.type", "invalid credential type")
	}
	return validateUTF8String("generated-password.password", credential.Password)
}

// UnmarshalJSON decodes and validates a generated-password credential atomically.
func (credential *GeneratedPassword) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeGeneratedPassword, "must not be nil")
	}
	type plain GeneratedPassword
	var decoded plain
	if err := decodeCredential(data, CredentialTypeGeneratedPassword, "generated-password", []string{"type", "password"}, nil, &decoded); err != nil {
		return err
	}
	candidate := GeneratedPassword(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

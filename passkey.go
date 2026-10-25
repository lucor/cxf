package cxf

// CredentialTypePasskey is the CXF passkey type.
const CredentialTypePasskey = "passkey"

// Passkey stores a WebAuthn credential and its private key.
type Passkey struct {
	// Type must be CredentialTypePasskey.
	Type string `json:"type"`
	// CredentialID is the registration credential's rawId encoded as Base64url.
	CredentialID string `json:"credentialId"`
	// RPID scopes this passkey to its registered relying party; Item.Scope does not apply.
	RPID string `json:"rpId"`
	// Username is the account name, including any edits made by the user.
	Username string `json:"username"`
	// UserDisplayName is the account's display name, including user edits.
	UserDisplayName string `json:"userDisplayName"`
	// UserHandle is the account identifier from registration, encoded as Base64url.
	UserHandle string `json:"userHandle"`
	// Key contains the credential's PKCS#8 DER private key encoded as Base64url.
	Key string `json:"key"`
	// FIDO2Extensions optionally holds associated WebAuthn and CTAP2 extension data.
	FIDO2Extensions *FIDO2Extensions `json:"fido2Extensions,omitempty"`
}

// FIDO2Extensions stores supported WebAuthn extension data.
type FIDO2Extensions struct {
	// HMACCredentials optionally supplies seeds for PRF or hmac-secret operations.
	HMACCredentials *FIDO2HMACCredentials `json:"hmacCredentials,omitempty"`
	// CredBlob optionally holds credential blob bytes encoded as Base64url.
	CredBlob *string `json:"credBlob,omitempty"`
	// LargeBlob optionally holds the credential's compressed large blob.
	LargeBlob *FIDO2LargeBlob `json:"largeBlob,omitempty"`
	// Payments optionally marks the credential for Secure Payment Confirmation.
	Payments *bool `json:"payments,omitempty"`
}

// FIDO2HMACCredentials stores credentials used by the PRF extension.
type FIDO2HMACCredentials struct {
	// Algorithm names the HMAC algorithm; CXF recommends "hmac-sha256".
	Algorithm string `json:"algorithm"`
	// CredWithUV is the Base64url seed used after user verification; 32 bytes are recommended.
	CredWithUV string `json:"credWithUV"`
	// CredWithoutUV is the Base64url seed used without user verification; 32 bytes are recommended.
	CredWithoutUV string `json:"credWithoutUV"`
}

// FIDO2LargeBlob stores compressed large-blob data.
type FIDO2LargeBlob struct {
	// UncompressedSize is the claimed size of the original data, in bytes.
	UncompressedSize uint64 `json:"uncompressedSize"`
	// Data contains DEFLATE-compressed bytes encoded as Base64url.
	Data string `json:"data"`
}

// Validate checks the passkey identifiers, key, and extension data.
func (credential *Passkey) Validate() error {
	if credential == nil || credential.Type != CredentialTypePasskey {
		return invalid("passkey.type", "invalid credential type")
	}
	for _, field := range []struct{ path, value string }{
		{"passkey.rpId", credential.RPID},
		{"passkey.username", credential.Username},
		{"passkey.userDisplayName", credential.UserDisplayName},
	} {
		if err := validateUTF8String(field.path, field.value); err != nil {
			return err
		}
	}
	if _, err := decodeBase64URL(credential.CredentialID); err != nil {
		return invalid("passkey.credentialId", "invalid base64url value")
	}
	if _, err := decodeBase64URL(credential.UserHandle); err != nil {
		return invalid("passkey.userHandle", "invalid base64url value")
	}
	key, err := decodeBase64URL(credential.Key)
	if err != nil {
		return invalid("passkey.key", "invalid base64url value")
	}
	if err := validatePKCS8PrivateKey(key); err != nil {
		return invalid("passkey.key", "invalid PKCS#8 private key")
	}
	if credential.FIDO2Extensions != nil {
		return credential.FIDO2Extensions.Validate()
	}
	return nil
}

// Validate checks FIDO2 extension values.
func (extensions *FIDO2Extensions) Validate() error {
	if extensions == nil {
		return invalid("fido2Extensions", "must not be nil")
	}
	if extensions.CredBlob != nil {
		if _, err := decodeBase64URL(*extensions.CredBlob); err != nil {
			return invalid("fido2Extensions.credBlob", "invalid base64url value")
		}
	}
	if extensions.HMACCredentials != nil {
		if err := extensions.HMACCredentials.Validate(); err != nil {
			return err
		}
	}
	if extensions.LargeBlob != nil {
		if err := extensions.LargeBlob.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks FIDO2 HMAC credentials.
func (credentials *FIDO2HMACCredentials) Validate() error {
	if credentials == nil {
		return invalid("fido2HMACCredentials", "must not be nil")
	}
	if err := validateUTF8String("fido2HMACCredentials.algorithm", credentials.Algorithm); err != nil {
		return err
	}
	if _, err := decodeBase64URL(credentials.CredWithUV); err != nil {
		return invalid("fido2HMACCredentials.credWithUV", "invalid base64url value")
	}
	if _, err := decodeBase64URL(credentials.CredWithoutUV); err != nil {
		return invalid("fido2HMACCredentials.credWithoutUV", "invalid base64url value")
	}
	return nil
}

// Validate checks FIDO2 large-blob data.
func (blob *FIDO2LargeBlob) Validate() error {
	if blob == nil {
		return invalid("fido2LargeBlob", "must not be nil")
	}
	if _, err := decodeBase64URL(blob.Data); err != nil {
		return invalid("fido2LargeBlob.data", "invalid base64url value")
	}
	return nil
}

// UnmarshalJSON decodes and validates a passkey credential atomically.
func (credential *Passkey) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypePasskey, "must not be nil")
	}
	type plain Passkey
	var decoded plain
	if err := decodeCredential(data, CredentialTypePasskey, "passkey", []string{"type", "credentialId", "rpId", "username", "userDisplayName", "userHandle", "key"}, []string{"fido2Extensions"}, &decoded); err != nil {
		return err
	}
	candidate := Passkey(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

// UnmarshalJSON decodes and validates FIDO2 extension data atomically.
func (extensions *FIDO2Extensions) UnmarshalJSON(data []byte) error {
	if extensions == nil {
		return invalid("fido2Extensions", "must not be nil")
	}
	type plain FIDO2Extensions
	var decoded plain
	if err := decodeObject(data, "fido2Extensions", nil, []string{"hmacCredentials", "credBlob", "largeBlob", "payments"}, &decoded); err != nil {
		return err
	}
	candidate := FIDO2Extensions(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*extensions = candidate
	return nil
}

// UnmarshalJSON decodes and validates FIDO2 HMAC credentials atomically.
func (credentials *FIDO2HMACCredentials) UnmarshalJSON(data []byte) error {
	if credentials == nil {
		return invalid("fido2HMACCredentials", "must not be nil")
	}
	type plain FIDO2HMACCredentials
	var decoded plain
	if err := decodeObject(data, "fido2HMACCredentials", []string{"algorithm", "credWithUV", "credWithoutUV"}, nil, &decoded); err != nil {
		return err
	}
	candidate := FIDO2HMACCredentials(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credentials = candidate
	return nil
}

// UnmarshalJSON decodes and validates FIDO2 large-blob data atomically.
func (blob *FIDO2LargeBlob) UnmarshalJSON(data []byte) error {
	if blob == nil {
		return invalid("fido2LargeBlob", "must not be nil")
	}
	type plain FIDO2LargeBlob
	var decoded plain
	if err := decodeObject(data, "fido2LargeBlob", []string{"uncompressedSize", "data"}, nil, &decoded); err != nil {
		return err
	}
	candidate := FIDO2LargeBlob(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*blob = candidate
	return nil
}

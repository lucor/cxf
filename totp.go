package cxf

import (
	"encoding/base32"
	"strings"
)

// CredentialTypeTOTP is the CXF TOTP type.
const CredentialTypeTOTP = "totp"

// TOTP stores a time-based one-time password secret.
type TOTP struct {
	// Type must be CredentialTypeTOTP.
	Type string `json:"type"`
	// Secret is the shared OTP secret encoded as Base32.
	Secret string `json:"secret"`
	// Period is the time step in seconds; CXF recommends 30.
	Period uint16 `json:"period"`
	// Digits is the number of displayed digits; CXF recommends 6.
	Digits uint16 `json:"digits"`
	// Username optionally identifies the account using the OTP.
	Username string `json:"username,omitempty"`
	// Algorithm names the hash, usually "sha1", "sha256", or "sha512".
	// Importers must ignore credentials using an unknown algorithm.
	Algorithm string `json:"algorithm"`
	// Issuer optionally names the service that issued the secret.
	Issuer string `json:"issuer,omitempty"`
}

// Validate checks the credential type and secret encoding.
func (credential *TOTP) Validate() error {
	if credential == nil || credential.Type != CredentialTypeTOTP {
		return invalid("totp.type", "invalid credential type")
	}
	for _, field := range []struct{ path, value string }{
		{"totp.username", credential.Username},
		{"totp.algorithm", credential.Algorithm},
		{"totp.issuer", credential.Issuer},
	} {
		if err := validateUTF8String(field.path, field.value); err != nil {
			return err
		}
	}
	secret := strings.ToUpper(credential.Secret)
	if strings.ContainsAny(secret, "\r\n") {
		return invalid("totp.secret", "invalid Base32 secret")
	}
	encoding := base32.StdEncoding
	if !strings.Contains(secret, "=") {
		encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	}
	if _, err := encoding.DecodeString(secret); err != nil {
		return invalid("totp.secret", "invalid Base32 secret")
	}
	return nil
}

// UnmarshalJSON decodes and validates a TOTP credential atomically.
func (credential *TOTP) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeTOTP, "must not be nil")
	}
	type plain TOTP
	var decoded plain
	if err := decodeCredential(data, CredentialTypeTOTP, "totp", []string{"type", "secret", "period", "digits", "algorithm"}, []string{"username", "issuer"}, &decoded); err != nil {
		return err
	}
	candidate := TOTP(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

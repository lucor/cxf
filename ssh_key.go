package cxf

import "strings"

// CredentialTypeSSHKey is the CXF SSH key type.
const CredentialTypeSSHKey = "ssh-key"

// SSHKey stores an SSH private key in PKCS#8 DER format.
type SSHKey struct {
	// Type must be CredentialTypeSSHKey.
	Type string `json:"type"`
	// KeyType names the SSH algorithm, for example "ssh-ed25519".
	KeyType string `json:"keyType"`
	// PrivateKey contains PKCS#8 DER bytes encoded as Base64url.
	PrivateKey string `json:"privateKey"`
	// KeyComment optionally describes the key.
	KeyComment string `json:"keyComment,omitempty"`
	// CreationDate is optional; FieldTypeDate is recommended.
	CreationDate *EditableField `json:"creationDate,omitempty"`
	// ExpiryDate is optional; FieldTypeDate is recommended.
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
	// KeyGenerationSource optionally names the key's origin; FieldTypeString is recommended.
	KeyGenerationSource *EditableField `json:"keyGenerationSource,omitempty"`
}

// Validate checks the type and PKCS#8 private key.
func (credential *SSHKey) Validate() error {
	if credential == nil || credential.Type != CredentialTypeSSHKey {
		return invalid("ssh-key.type", "invalid credential type")
	}
	if !validSSHKeyType(credential.KeyType) {
		return invalid("ssh-key.keyType", "invalid SSH public-key algorithm")
	}
	if err := validateUTF8String("ssh-key.keyComment", credential.KeyComment); err != nil {
		return err
	}
	key, err := decodeBase64URL(credential.PrivateKey)
	if err != nil {
		return invalid("ssh-key.privateKey", "invalid Base64url key")
	}
	if err := validatePKCS8PrivateKey(key); err != nil {
		return invalid("ssh-key.privateKey", "invalid PKCS#8 key")
	}
	if credential.CreationDate != nil {
		if err := validateEditableFieldValue(credential.CreationDate, "ssh-key.creationDate"); err != nil {
			return err
		}
	}
	if credential.ExpiryDate != nil {
		if err := validateEditableFieldValue(credential.ExpiryDate, "ssh-key.expiryDate"); err != nil {
			return err
		}
	}
	if credential.KeyGenerationSource != nil {
		if err := validateEditableFieldValue(credential.KeyGenerationSource, "ssh-key.keyGenerationSource"); err != nil {
			return err
		}
	}
	return nil
}

// validSSHKeyType checks names and families registered by IANA.
func validSSHKeyType(name string) bool {
	switch name {
	case "ssh-dss", "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512",
		"spki-sign-rsa", "spki-sign-dss", "pgp-sign-rsa", "pgp-sign-dss", "null",
		"x509v3-ssh-dss", "x509v3-ssh-rsa", "x509v3-rsa2048-sha256",
		"ssh-ed25519", "ssh-ed448", "ssh-mldsa-44", "ssh-mldsa-65", "ssh-mldsa-87",
		"ssh-mldsa44-ed25519", "ssh-mldsa87-p384":
		return true
	}
	for _, prefix := range []string{"ecdsa-sha2-", "x509v3-ecdsa-sha2-"} {
		curve := strings.TrimPrefix(name, prefix)
		if curve != name && (curve == "nistp256" || curve == "nistp384" || curve == "nistp521") {
			return true
		}
	}
	return false
}

// UnmarshalJSON decodes and validates an SSH-key credential atomically.
func (credential *SSHKey) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeSSHKey, "must not be nil")
	}
	type plain SSHKey
	var decoded plain
	if err := decodeCredential(data, CredentialTypeSSHKey, "ssh-key", []string{"type", "keyType", "privateKey"}, []string{"keyComment", "creationDate", "expiryDate", "keyGenerationSource"}, &decoded); err != nil {
		return err
	}
	candidate := SSHKey(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

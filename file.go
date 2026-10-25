package cxf

import "crypto/sha256"

// CredentialTypeFile is the CXF file type.
const CredentialTypeFile = "file"

// File stores metadata for a separately transferred binary file.
type File struct {
	// Type must be CredentialTypeFile.
	Type string `json:"type"`
	// ID is the Base64url identifier used to match the separately transferred file.
	ID string `json:"id"`
	// Name is the file name, including its extension when present.
	Name string `json:"name"`
	// DecryptedSize is the size of the decrypted file, in bytes.
	DecryptedSize uint64 `json:"decryptedSize"`
	// IntegrityHash is the decrypted file's SHA-256 digest encoded as Base64url.
	IntegrityHash string `json:"integrityHash"`
}

// Validate checks the file identifier and digest.
func (credential *File) Validate() error {
	if credential == nil || credential.Type != CredentialTypeFile {
		return invalid("file.type", "invalid credential type")
	}
	if err := validateUTF8String("file.name", credential.Name); err != nil {
		return err
	}
	if _, err := decodeID(credential.ID); err != nil {
		return invalid("file.id", "invalid identifier")
	}
	digest, err := decodeBase64URL(credential.IntegrityHash)
	if err != nil || len(digest) != sha256.Size {
		return invalid("file.integrityHash", "expected a SHA-256 digest")
	}
	return nil
}

// UnmarshalJSON decodes and validates file metadata atomically.
func (credential *File) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeFile, "must not be nil")
	}
	type plain File
	var decoded plain
	if err := decodeCredential(data, CredentialTypeFile, "file", []string{"type", "id", "name", "decryptedSize", "integrityHash"}, nil, &decoded); err != nil {
		return err
	}
	candidate := File(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

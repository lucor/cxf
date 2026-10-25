package cxf

// CredentialTypeItemReference is the CXF item reference type.
const CredentialTypeItemReference = "item-reference"

// ItemReference points to another item in or outside the document.
type ItemReference struct {
	// Type must be CredentialTypeItemReference.
	Type string `json:"type"`
	// Reference identifies the linked item and optionally its owning account.
	Reference LinkedItem `json:"reference"`
}

// Validate checks the referenced item identifiers.
func (credential *ItemReference) Validate() error {
	if credential == nil || credential.Type != CredentialTypeItemReference {
		return invalid("item-reference.type", "invalid credential type")
	}
	return credential.Reference.Validate()
}

// UnmarshalJSON decodes and validates an item-reference credential atomically.
func (credential *ItemReference) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeItemReference, "must not be nil")
	}
	type plain ItemReference
	var decoded plain
	if err := decodeCredential(data, CredentialTypeItemReference, "item-reference", []string{"type", "reference"}, nil, &decoded); err != nil {
		return err
	}
	candidate := ItemReference(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

package cxf

// CredentialTypeIdentityDocument is the CXF identity document type.
const CredentialTypeIdentityDocument = "identity-document"

// IdentityDocument stores identity document fields.
type IdentityDocument struct {
	// Type must be CredentialTypeIdentityDocument.
	Type string `json:"type"`
	// IssuingCountry identifies the issuer's country; FieldTypeCountryCode is recommended.
	IssuingCountry *EditableField `json:"issuingCountry,omitempty"`
	// DocumentNumber identifies this issuance of the document; FieldTypeString is recommended.
	DocumentNumber *EditableField `json:"documentNumber,omitempty"`
	// IdentificationNumber identifies the person or entity, such as an SSN or tax ID.
	// FieldTypeString is recommended.
	IdentificationNumber *EditableField `json:"identificationNumber,omitempty"`
	// Nationality records nationality; FieldTypeString is recommended.
	Nationality *EditableField `json:"nationality,omitempty"`
	// FullName names the document holder; FieldTypeString is recommended.
	FullName *EditableField `json:"fullName,omitempty"`
	// BirthDate records the holder's date of birth; FieldTypeDate is recommended.
	BirthDate *EditableField `json:"birthDate,omitempty"`
	// BirthPlace records where the holder was born; FieldTypeString is recommended.
	BirthPlace *EditableField `json:"birthPlace,omitempty"`
	// Sex records sex or gender; FieldTypeString is recommended.
	Sex *EditableField `json:"sex,omitempty"`
	// IssueDate records when the document was issued; FieldTypeDate is recommended.
	IssueDate *EditableField `json:"issueDate,omitempty"`
	// ExpiryDate records when the document expires; FieldTypeDate is recommended.
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
	// IssuingAuthority names the issuer; FieldTypeString is recommended.
	IssuingAuthority *EditableField `json:"issuingAuthority,omitempty"`
}

// Validate checks the identity-document fields.
func (credential *IdentityDocument) Validate() error {
	if credential == nil || credential.Type != CredentialTypeIdentityDocument {
		return invalid("identity-document.type", "invalid credential type")
	}
	return validateOptionalFields("identity-document",
		namedEditableField{"issuingCountry", credential.IssuingCountry},
		namedEditableField{"documentNumber", credential.DocumentNumber},
		namedEditableField{"identificationNumber", credential.IdentificationNumber},
		namedEditableField{"nationality", credential.Nationality},
		namedEditableField{"fullName", credential.FullName},
		namedEditableField{"birthDate", credential.BirthDate},
		namedEditableField{"birthPlace", credential.BirthPlace},
		namedEditableField{"sex", credential.Sex},
		namedEditableField{"issueDate", credential.IssueDate},
		namedEditableField{"expiryDate", credential.ExpiryDate},
		namedEditableField{"issuingAuthority", credential.IssuingAuthority},
	)
}

// UnmarshalJSON decodes and validates an identity-document credential atomically.
func (credential *IdentityDocument) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeIdentityDocument, "must not be nil")
	}
	type plain IdentityDocument
	var decoded plain
	if err := decodeCredential(data, CredentialTypeIdentityDocument, "identity-document", []string{"type"}, []string{"issuingCountry", "documentNumber", "identificationNumber", "nationality", "fullName", "birthDate", "birthPlace", "sex", "issueDate", "expiryDate", "issuingAuthority"}, &decoded); err != nil {
		return err
	}
	candidate := IdentityDocument(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

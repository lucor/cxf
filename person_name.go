package cxf

// CredentialTypePersonName is the CXF person name type.
const CredentialTypePersonName = "person-name"

// PersonName stores the parts of a person's name.
type PersonName struct {
	// Type must be CredentialTypePersonName.
	Type string `json:"type"`
	// Title holds an honorific; FieldTypeString is recommended.
	Title *EditableField `json:"title,omitempty"`
	// Given holds the given name; FieldTypeString is recommended.
	Given *EditableField `json:"given,omitempty"`
	// GivenInformal holds a nickname or preferred name; FieldTypeString is recommended.
	GivenInformal *EditableField `json:"givenInformal,omitempty"`
	// Given2 holds additional given names; FieldTypeString is recommended.
	Given2 *EditableField `json:"given2,omitempty"`
	// SurnamePrefix holds a family-name prefix; FieldTypeString is recommended.
	SurnamePrefix *EditableField `json:"surnamePrefix,omitempty"`
	// Surname holds the family name; FieldTypeString is recommended.
	Surname *EditableField `json:"surname,omitempty"`
	// Surname2 holds a second family name; FieldTypeString is recommended.
	Surname2 *EditableField `json:"surname2,omitempty"`
	// Credentials holds academic or professional suffixes; FieldTypeString is recommended.
	Credentials *EditableField `json:"credentials,omitempty"`
	// Generation holds a suffix such as "Jr."; FieldTypeString is recommended.
	Generation *EditableField `json:"generation,omitempty"`
}

// Validate checks the person-name fields.
func (credential *PersonName) Validate() error {
	if credential == nil || credential.Type != CredentialTypePersonName {
		return invalid("person-name.type", "invalid credential type")
	}
	return validateOptionalFields("person-name",
		namedEditableField{"title", credential.Title},
		namedEditableField{"given", credential.Given},
		namedEditableField{"givenInformal", credential.GivenInformal},
		namedEditableField{"given2", credential.Given2},
		namedEditableField{"surnamePrefix", credential.SurnamePrefix},
		namedEditableField{"surname", credential.Surname},
		namedEditableField{"surname2", credential.Surname2},
		namedEditableField{"credentials", credential.Credentials},
		namedEditableField{"generation", credential.Generation},
	)
}

// UnmarshalJSON decodes and validates a person-name credential atomically.
func (credential *PersonName) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypePersonName, "must not be nil")
	}
	type plain PersonName
	var decoded plain
	if err := decodeCredential(data, CredentialTypePersonName, "person-name", []string{"type"}, []string{"title", "given", "givenInformal", "given2", "surnamePrefix", "surname", "surname2", "credentials", "generation"}, &decoded); err != nil {
		return err
	}
	candidate := PersonName(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

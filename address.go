package cxf

// CredentialTypeAddress is the CXF address type.
const CredentialTypeAddress = "address"

// Address stores address fields used for autofill.
type Address struct {
	// Type must be CredentialTypeAddress.
	Type string `json:"type"`
	// StreetAddress holds address lines separated by newlines; FieldTypeString is recommended.
	StreetAddress *EditableField `json:"streetAddress,omitempty"`
	// PostalCode holds a postal or ZIP code; FieldTypeString is recommended.
	PostalCode *EditableField `json:"postalCode,omitempty"`
	// City names the city; FieldTypeString is recommended.
	City *EditableField `json:"city,omitempty"`
	// Territory identifies a state or province; FieldTypeSubdivisionCode is recommended.
	Territory *EditableField `json:"territory,omitempty"`
	// Country identifies the country; FieldTypeCountryCode is recommended.
	Country *EditableField `json:"country,omitempty"`
	// Tel holds a phone number; FieldTypeString is recommended.
	Tel *EditableField `json:"tel,omitempty"`
}

// Validate checks the address fields.
func (credential *Address) Validate() error {
	if credential == nil || credential.Type != CredentialTypeAddress {
		return invalid("address.type", "invalid credential type")
	}
	return validateOptionalFields("address",
		namedEditableField{"streetAddress", credential.StreetAddress},
		namedEditableField{"postalCode", credential.PostalCode},
		namedEditableField{"city", credential.City},
		namedEditableField{"territory", credential.Territory},
		namedEditableField{"country", credential.Country},
		namedEditableField{"tel", credential.Tel},
	)
}

// UnmarshalJSON decodes and validates an address credential atomically.
func (credential *Address) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeAddress, "must not be nil")
	}
	type plain Address
	var decoded plain
	if err := decodeCredential(data, CredentialTypeAddress, "address", []string{"type"}, []string{"streetAddress", "postalCode", "city", "territory", "country", "tel"}, &decoded); err != nil {
		return err
	}
	candidate := Address(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

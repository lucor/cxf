package cxf

// CredentialTypeDriversLicense is the CXF driver's license type.
const CredentialTypeDriversLicense = "drivers-license"

// DriversLicense stores driver's license fields.
type DriversLicense struct {
	// Type must be CredentialTypeDriversLicense.
	Type string `json:"type"`
	// FullName names the license holder; FieldTypeString is recommended.
	FullName *EditableField `json:"fullName,omitempty"`
	// BirthDate records the holder's birth date; FieldTypeDate is recommended.
	BirthDate *EditableField `json:"birthDate,omitempty"`
	// IssueDate records when the license was issued; FieldTypeDate is recommended.
	IssueDate *EditableField `json:"issueDate,omitempty"`
	// ExpiryDate records when the license expires; FieldTypeDate is recommended.
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
	// IssuingAuthority names the issuer; FieldTypeString is recommended.
	IssuingAuthority *EditableField `json:"issuingAuthority,omitempty"`
	// Territory identifies the issuing region; FieldTypeSubdivisionCode is recommended.
	Territory *EditableField `json:"territory,omitempty"`
	// Country identifies the issuing country; FieldTypeCountryCode is recommended.
	Country *EditableField `json:"country,omitempty"`
	// LicenseNumber holds the issuer's assigned number; FieldTypeString is recommended.
	LicenseNumber *EditableField `json:"licenseNumber,omitempty"`
	// LicenseClass describes permitted vehicle types; FieldTypeString is recommended.
	LicenseClass *EditableField `json:"licenseClass,omitempty"`
}

// Validate checks the driver's-license fields.
func (credential *DriversLicense) Validate() error {
	if credential == nil || credential.Type != CredentialTypeDriversLicense {
		return invalid("drivers-license.type", "invalid credential type")
	}
	return validateOptionalFields("drivers-license",
		namedEditableField{"fullName", credential.FullName},
		namedEditableField{"birthDate", credential.BirthDate},
		namedEditableField{"issueDate", credential.IssueDate},
		namedEditableField{"expiryDate", credential.ExpiryDate},
		namedEditableField{"issuingAuthority", credential.IssuingAuthority},
		namedEditableField{"territory", credential.Territory},
		namedEditableField{"country", credential.Country},
		namedEditableField{"licenseNumber", credential.LicenseNumber},
		namedEditableField{"licenseClass", credential.LicenseClass},
	)
}

// UnmarshalJSON decodes and validates a driver's-license credential atomically.
func (credential *DriversLicense) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeDriversLicense, "must not be nil")
	}
	type plain DriversLicense
	var decoded plain
	if err := decodeCredential(data, CredentialTypeDriversLicense, "drivers-license", []string{"type"}, []string{"fullName", "birthDate", "issueDate", "expiryDate", "issuingAuthority", "territory", "country", "licenseNumber", "licenseClass"}, &decoded); err != nil {
		return err
	}
	candidate := DriversLicense(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

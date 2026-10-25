package cxf

// CredentialTypePassport is the CXF passport type.
const CredentialTypePassport = "passport"

// Passport stores passport fields.
type Passport struct {
	// Type must be CredentialTypePassport.
	Type string `json:"type"`
	// IssuingCountry identifies the issuer's country; FieldTypeCountryCode is recommended.
	IssuingCountry *EditableField `json:"issuingCountry,omitempty"`
	// PassportType holds an ICAO document code; FieldTypeString is recommended.
	PassportType *EditableField `json:"passportType,omitempty"`
	// PassportNumber identifies the passport; FieldTypeString is recommended.
	PassportNumber *EditableField `json:"passportNumber,omitempty"`
	// NationalIdentificationNumber holds the person's national ID; FieldTypeString is recommended.
	NationalIdentificationNumber *EditableField `json:"nationalIdentificationNumber,omitempty"`
	// Nationality records nationality; FieldTypeString is recommended.
	Nationality *EditableField `json:"nationality,omitempty"`
	// FullName names the passport holder; FieldTypeString is recommended.
	FullName *EditableField `json:"fullName,omitempty"`
	// BirthDate records the holder's date of birth; FieldTypeDate is recommended.
	BirthDate *EditableField `json:"birthDate,omitempty"`
	// BirthPlace records where the holder was born; FieldTypeString is recommended.
	BirthPlace *EditableField `json:"birthPlace,omitempty"`
	// Sex records sex or gender; FieldTypeString is recommended.
	Sex *EditableField `json:"sex,omitempty"`
	// IssueDate records when the passport was issued; FieldTypeDate is recommended.
	IssueDate *EditableField `json:"issueDate,omitempty"`
	// ExpiryDate records when the passport expires; FieldTypeDate is recommended.
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
	// IssuingAuthority names the issuer; FieldTypeString is recommended.
	IssuingAuthority *EditableField `json:"issuingAuthority,omitempty"`
}

// Validate checks the passport fields.
func (credential *Passport) Validate() error {
	if credential == nil || credential.Type != CredentialTypePassport {
		return invalid("passport.type", "invalid credential type")
	}
	if err := validateOptionalFields("passport",
		namedEditableField{"issuingCountry", credential.IssuingCountry},
		namedEditableField{"passportType", credential.PassportType},
		namedEditableField{"passportNumber", credential.PassportNumber},
		namedEditableField{"nationalIdentificationNumber", credential.NationalIdentificationNumber},
		namedEditableField{"nationality", credential.Nationality},
		namedEditableField{"fullName", credential.FullName},
		namedEditableField{"birthDate", credential.BirthDate},
		namedEditableField{"birthPlace", credential.BirthPlace},
		namedEditableField{"sex", credential.Sex},
		namedEditableField{"issueDate", credential.IssueDate},
		namedEditableField{"expiryDate", credential.ExpiryDate},
		namedEditableField{"issuingAuthority", credential.IssuingAuthority},
	); err != nil {
		return err
	}
	if credential.PassportType != nil && !validPassportType(credential.PassportType.Value) {
		return invalid("passport.passportType.value", "invalid ICAO document code")
	}
	return nil
}

// validPassportType checks the TD3 passport codes defined by ICAO Doc 9303 Part 4.
func validPassportType(value string) bool {
	switch value {
	case "PP", "PE", "PD", "PO", "PR", "PT", "PS", "PL", "PM":
		return true
	default:
		return false
	}
}

// UnmarshalJSON decodes and validates a passport credential atomically.
func (credential *Passport) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypePassport, "must not be nil")
	}
	type plain Passport
	var decoded plain
	if err := decodeCredential(data, CredentialTypePassport, "passport", []string{"type"}, []string{"issuingCountry", "passportType", "passportNumber", "nationalIdentificationNumber", "nationality", "fullName", "birthDate", "birthPlace", "sex", "issueDate", "expiryDate", "issuingAuthority"}, &decoded); err != nil {
		return err
	}
	candidate := Passport(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

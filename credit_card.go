package cxf

// CredentialTypeCreditCard is the CXF credit card type.
const CredentialTypeCreditCard = "credit-card"

// CreditCard stores payment card fields.
type CreditCard struct {
	// Type must be CredentialTypeCreditCard.
	Type string `json:"type"`
	// Number holds the card number; FieldTypeConcealedString is recommended.
	Number *EditableField `json:"number,omitempty"`
	// FullName is the name printed on the card; FieldTypeString is recommended.
	FullName *EditableField `json:"fullName,omitempty"`
	// CardType names the card brand; FieldTypeString is recommended.
	CardType *EditableField `json:"cardType,omitempty"`
	// VerificationNumber holds the card security code; FieldTypeConcealedString is recommended.
	VerificationNumber *EditableField `json:"verificationNumber,omitempty"`
	// PIN holds the card's PIN; FieldTypeConcealedString is recommended.
	PIN *EditableField `json:"pin,omitempty"`
	// ExpiryDate is the expiry month; FieldTypeYearMonth is recommended.
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
	// ValidFrom is the first valid month; FieldTypeYearMonth is recommended.
	ValidFrom *EditableField `json:"validFrom,omitempty"`
}

// Validate checks the payment card fields.
func (credential *CreditCard) Validate() error {
	if credential == nil || credential.Type != CredentialTypeCreditCard {
		return invalid("credit-card.type", "invalid credential type")
	}
	return validateOptionalFields("credit-card",
		namedEditableField{"number", credential.Number},
		namedEditableField{"fullName", credential.FullName},
		namedEditableField{"cardType", credential.CardType},
		namedEditableField{"verificationNumber", credential.VerificationNumber},
		namedEditableField{"pin", credential.PIN},
		namedEditableField{"expiryDate", credential.ExpiryDate},
		namedEditableField{"validFrom", credential.ValidFrom},
	)
}

// UnmarshalJSON decodes and validates a credit card credential atomically.
func (credential *CreditCard) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeCreditCard, "must not be nil")
	}
	type plain CreditCard
	var decoded plain
	if err := decodeCredential(data, CredentialTypeCreditCard, "credit-card", []string{"type"}, []string{"number", "fullName", "cardType", "verificationNumber", "pin", "expiryDate", "validFrom"}, &decoded); err != nil {
		return err
	}
	candidate := CreditCard(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

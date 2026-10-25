package cxf

import (
	"encoding/json"
	"net/mail"
	"regexp"
	"time"
	"unicode/utf8"
)

// EditableField stores a user-editable credential value.
type EditableField struct {
	// ID is an optional Base64url identifier, at most 64 decoded bytes.
	ID *string `json:"id,omitempty"`
	// FieldType describes the value's format and how it should be displayed.
	FieldType string `json:"fieldType"`
	// Value holds text or the string representation of another value.
	Value string `json:"value"`
	// Label is an optional description shown to the user.
	Label string `json:"label,omitempty"`
	// Extensions holds optional field extension objects as JSON.
	Extensions []json.RawMessage `json:"extensions,omitempty"`
}

// validateEditableFieldValue checks an editable field's type and value.
func validateEditableFieldValue(field *EditableField, path string) error {
	if field == nil {
		return invalid(path, "must not be null")
	}
	if !utf8.ValidString(field.FieldType) || !utf8.ValidString(field.Value) || !utf8.ValidString(field.Label) {
		return invalid(path, "invalid UTF-8")
	}
	// Recommended field types are not mandatory; future types must remain readable.
	if field.ID != nil {
		if _, err := decodeID(*field.ID); err != nil {
			return invalid(path+".id", "invalid identifier")
		}
	}
	if err := validateExtensions(field.Extensions, path+".extensions", false); err != nil {
		return err
	}
	if field.FieldType == FieldTypeDate {
		if _, err := time.Parse("2006-01-02", field.Value); err != nil {
			return invalid(path+".value", "invalid date")
		}
	}
	if field.FieldType == FieldTypeYearMonth {
		if _, err := time.Parse("2006-01", field.Value); err != nil {
			return invalid(path+".value", "invalid year-month")
		}
	}
	if field.FieldType == FieldTypeBoolean {
		if field.Value != "true" && field.Value != "false" {
			return invalid(path+".value", "invalid boolean")
		}
	}
	if field.FieldType == FieldTypeCountryCode && !countryCodePattern.MatchString(field.Value) {
		return invalid(path+".value", "invalid country code format")
	}
	if field.FieldType == FieldTypeSubdivisionCode && !subdivisionCodePattern.MatchString(field.Value) {
		return invalid(path+".value", "invalid subdivision code format")
	}
	if field.FieldType == FieldTypeEmail {
		if _, err := mail.ParseAddressList(field.Value); err != nil {
			return invalid(path+".value", "invalid email address")
		}
	}
	return nil
}

var (
	countryCodePattern     = regexp.MustCompile(`^[A-Z]{2}$`)
	subdivisionCodePattern = regexp.MustCompile(`^[A-Z]{2}-[A-Z0-9]{1,3}$`)
)

// Validate checks the editable field's value and extensions.
func (field *EditableField) Validate() error {
	return validateEditableFieldValue(field, "editableField")
}

// UnmarshalJSON decodes and validates an editable field atomically.
func (field *EditableField) UnmarshalJSON(data []byte) error {
	if field == nil {
		return invalid("editableField", "must not be nil")
	}
	type plain EditableField
	var decoded plain
	if err := decodeObject(data, "editableField", []string{"fieldType", "value"}, []string{"id", "label", "extensions"}, &decoded); err != nil {
		return err
	}
	candidate := EditableField(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*field = candidate
	return nil
}

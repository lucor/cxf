package cxf

import (
	"encoding/json"
	"strconv"
)

// CredentialTypeCustomFields is the CXF custom fields type.
const CredentialTypeCustomFields = "custom-fields"

// CustomFields stores a labeled group of editable fields.
type CustomFields struct {
	// Type must be CredentialTypeCustomFields.
	Type string `json:"type"`
	// ID is an optional Base64url group identifier, at most 64 decoded bytes.
	ID *string `json:"id,omitempty"`
	// Label optionally names the field group.
	Label string `json:"label,omitempty"`
	// Fields lists editable values of any field type; an empty array is allowed.
	Fields []EditableField `json:"fields"`
	// Extensions holds optional group extension objects as JSON.
	Extensions []json.RawMessage `json:"extensions,omitempty"`
}

// Validate checks the custom fields and their extensions.
func (credential *CustomFields) Validate() error {
	if credential == nil || credential.Type != CredentialTypeCustomFields {
		return invalid("custom-fields.type", "invalid credential type")
	}
	if credential.ID != nil {
		if _, err := decodeID(*credential.ID); err != nil {
			return invalid("custom-fields.id", "invalid identifier")
		}
	}
	if credential.Fields == nil {
		return invalid("custom-fields.fields", "required array must not be null")
	}
	for i := range credential.Fields {
		if err := validateEditableFieldValue(&credential.Fields[i], "custom-fields.fields["+strconv.Itoa(i)+"]"); err != nil {
			return err
		}
	}
	return validateExtensions(credential.Extensions, "custom-fields.extensions", false)
}

// UnmarshalJSON decodes and validates custom fields atomically.
func (credential *CustomFields) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeCustomFields, "must not be nil")
	}
	type plain CustomFields
	var decoded plain
	if err := decodeCredential(data, CredentialTypeCustomFields, "custom-fields", []string{"type", "fields"}, []string{"id", "label", "extensions"}, &decoded); err != nil {
		return err
	}
	candidate := CustomFields(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

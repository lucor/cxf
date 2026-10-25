package cxf_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"go.lucor.dev/cxf"
)

// TestUnmarshalHeaderValidatesAtomically checks direct JSON decoding enforces CXF rules.
func TestUnmarshalHeaderValidatesAtomically(t *testing.T) {
	data := fixture(t)
	header := document(t)
	before, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}

	invalid := bytes.Replace(data, []byte("  \"timestamp\": 0,\n"), nil, 1)
	if bytes.Equal(invalid, data) {
		t.Fatal("test input was not changed")
	}
	err = json.Unmarshal(invalid, header)
	var validation *cxf.ValidationError
	if !errors.As(err, &validation) || validation.Path != "header.timestamp" {
		t.Fatalf("expected a field validation error, got %v", err)
	}
	if !errors.Is(err, cxf.ErrInvalidDocument) {
		t.Fatalf("expected invalid-document sentinel, got %v", err)
	}
	after, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("receiver changed after failed decode")
	}
}

// TestUnmarshalKnownCredentialValidatesAtomically checks direct credential decoding.
func TestUnmarshalKnownCredentialValidatesAtomically(t *testing.T) {
	credential := cxf.Note{
		Type:    cxf.CredentialTypeNote,
		Content: cxf.EditableField{FieldType: cxf.FieldTypeString, Value: "original"},
	}
	err := json.Unmarshal([]byte(`{"type":"note","content":{"fieldType":"string"}}`), &credential)
	var validation *cxf.ValidationError
	if !errors.As(err, &validation) || validation.Path != "editableField.value" {
		t.Fatalf("expected a validation error, got %v", err)
	}
	if bytes.Contains([]byte(err.Error()), []byte("original")) {
		t.Fatal("validation error exposed credential data")
	}
	if credential.Content.Value != "original" {
		t.Fatal("receiver changed after failed decode")
	}
	if err := json.Unmarshal([]byte(`{"type":"note","content":{"fieldType":"string","value":"updated"}}`), &credential); err != nil {
		t.Fatal(err)
	}
	if credential.Content.Value != "updated" {
		t.Fatal("valid credential was not decoded")
	}
}

// TestUnmarshalIgnoresCaseVariantMembers checks JSON names remain case-sensitive.
func TestUnmarshalIgnoresCaseVariantMembers(t *testing.T) {
	var note cxf.Note
	data := []byte(`{"type":"note","content":{"fieldType":"string","value":"original","Value":"replacement"}}`)
	if err := json.Unmarshal(data, &note); err != nil {
		t.Fatal(err)
	}
	if note.Content.Value != "original" {
		t.Fatalf("case-variant member replaced the value: %q", note.Content.Value)
	}

	var login cxf.BasicAuth
	if err := json.Unmarshal([]byte(`{"type":"basic-auth","Password":{"fieldType":"string","value":"sample"}}`), &login); err != nil {
		t.Fatal(err)
	}
	if login.Password != nil {
		t.Fatal("case-variant unknown member populated the password")
	}

	var extensions cxf.FIDO2Extensions
	if err := json.Unmarshal([]byte(`{"CredBlob":"not-base64"}`), &extensions); err != nil {
		t.Fatal(err)
	}
	if extensions.CredBlob != nil {
		t.Fatal("case-variant unknown member populated credBlob")
	}
}

// TestValidateRejectsInvalidUTF8 checks validation runs before JSON replaces invalid bytes.
func TestValidateRejectsInvalidUTF8(t *testing.T) {
	header := document(t)
	header.ExporterDisplayName = string([]byte{0xff})
	err := header.Validate()
	var validation *cxf.ValidationError
	if !errors.As(err, &validation) || validation.Path != "header.exporterDisplayName" {
		t.Fatalf("expected an UTF-8 validation error, got %v", err)
	}

	item := cxf.Item{ID: "aXRlbQ", Title: string([]byte{0xff}), Credentials: []json.RawMessage{}}
	err = item.Validate()
	if !errors.As(err, &validation) || validation.Path != "item.title" {
		t.Fatalf("expected an item UTF-8 validation error, got %v", err)
	}

	item = cxf.Item{
		ID:          "aXRlbQ",
		Title:       "Example",
		Credentials: []json.RawMessage{},
		Scope:       &cxf.CredentialScope{URLs: []string{string([]byte{0xff})}, AndroidApps: []cxf.AndroidAppID{}},
	}
	err = item.Validate()
	if !errors.As(err, &validation) || validation.Path != "item.scope.urls[0]" {
		t.Fatalf("expected a scope URL UTF-8 validation error, got %v", err)
	}

	field := cxf.EditableField{FieldType: cxf.FieldTypeString, Value: string([]byte{0xff})}
	if err := field.Validate(); !errors.As(err, &validation) || validation.Path != "editableField" {
		t.Fatalf("expected an editable-field UTF-8 validation error, got %v", err)
	}
}

// TestUnmarshalItemKeepsUnknownCredentials checks forward compatibility.
func TestUnmarshalItemKeepsUnknownCredentials(t *testing.T) {
	data := []byte(`{"id":"aXRlbQ","title":"Example","credentials":[{"type":"future-credential","opaque":{"value":1}}]}`)
	var item cxf.Item
	if err := json.Unmarshal(data, &item); err != nil {
		t.Fatal(err)
	}
	if len(item.Credentials) != 1 || !bytes.Contains(item.Credentials[0], []byte(`"future-credential"`)) {
		t.Fatal("unknown credential was not retained")
	}
}

// TestCredentialTypeOfReadsOnlyTheDiscriminator checks credential dispatch.
func TestCredentialTypeOfReadsOnlyTheDiscriminator(t *testing.T) {
	typeName, err := cxf.CredentialTypeOf(json.RawMessage(`{"type":"future-credential","opaque":42}`))
	if err != nil || typeName != "future-credential" {
		t.Fatalf("unexpected credential type result %q: %v", typeName, err)
	}
	if _, err := cxf.CredentialTypeOf(json.RawMessage(`{"type":42}`)); !errors.Is(err, cxf.ErrInvalidDocument) {
		t.Fatalf("expected invalid credential type, got %v", err)
	}
}

// TestCredentialNilReceiverUsesDiscriminatorPath checks nil receiver paths.
func TestCredentialNilReceiverUsesDiscriminatorPath(t *testing.T) {
	tests := []struct {
		name   string
		decode func() error
	}{
		{cxf.CredentialTypeAddress, func() error { var value *cxf.Address; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeAPIKey, func() error { var value *cxf.APIKey; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeBasicAuth, func() error { var value *cxf.BasicAuth; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeCreditCard, func() error { var value *cxf.CreditCard; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeCustomFields, func() error { var value *cxf.CustomFields; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeDriversLicense, func() error { var value *cxf.DriversLicense; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeFile, func() error { var value *cxf.File; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeGeneratedPassword, func() error { var value *cxf.GeneratedPassword; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeIdentityDocument, func() error { var value *cxf.IdentityDocument; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeItemReference, func() error { var value *cxf.ItemReference; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeNote, func() error { var value *cxf.Note; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypePasskey, func() error { var value *cxf.Passkey; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypePassport, func() error { var value *cxf.Passport; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypePersonName, func() error { var value *cxf.PersonName; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeSSHKey, func() error { var value *cxf.SSHKey; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeTOTP, func() error { var value *cxf.TOTP; return value.UnmarshalJSON(nil) }},
		{cxf.CredentialTypeWiFi, func() error { var value *cxf.WiFi; return value.UnmarshalJSON(nil) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.decode()
			var validation *cxf.ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("expected validation error, got %v", err)
			}
			if validation.Path != test.name {
				t.Fatalf("expected %q path, got %q", test.name, validation.Path)
			}
		})
	}
}

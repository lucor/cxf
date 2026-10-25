package cxf_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"go.lucor.dev/cxf"
)

// TestTypedCredentials checks the credential types Paw uses.
func TestTypedCredentials(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	derKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic file"))
	credBlob := base64.RawURLEncoding.EncodeToString([]byte("synthetic blob"))
	payments := true

	password := "sample-password"
	credentials := []any{
		cxf.BasicAuth{
			Type:     cxf.CredentialTypeBasicAuth,
			Username: &cxf.EditableField{FieldType: cxf.FieldTypeString, Value: "sample-user"},
			Password: &cxf.EditableField{FieldType: cxf.FieldTypeConcealedString, Value: password},
		},
		cxf.GeneratedPassword{Type: cxf.CredentialTypeGeneratedPassword, Password: password},
		cxf.Note{Type: cxf.CredentialTypeNote, Content: cxf.EditableField{FieldType: cxf.FieldTypeString, Value: "sample note"}},
		cxf.TOTP{
			Type:      cxf.CredentialTypeTOTP,
			Secret:    base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("totp secret")),
			Period:    30,
			Digits:    6,
			Algorithm: "sha1",
		},
		cxf.SSHKey{
			Type:       cxf.CredentialTypeSSHKey,
			KeyType:    "ssh-ed25519",
			PrivateKey: base64.RawURLEncoding.EncodeToString(derKey),
		},
		cxf.Address{Type: cxf.CredentialTypeAddress, City: &cxf.EditableField{FieldType: cxf.FieldTypeString, Value: "Example City"}},
		cxf.APIKey{Type: cxf.CredentialTypeAPIKey, Key: &cxf.EditableField{FieldType: cxf.FieldTypeConcealedString, Value: "synthetic-key"}},
		cxf.CreditCard{Type: cxf.CredentialTypeCreditCard, ExpiryDate: &cxf.EditableField{FieldType: cxf.FieldTypeYearMonth, Value: "2030-12"}},
		cxf.CustomFields{Type: cxf.CredentialTypeCustomFields, Fields: []cxf.EditableField{{FieldType: cxf.FieldTypeString, Value: "sample"}}},
		cxf.DriversLicense{Type: cxf.CredentialTypeDriversLicense, BirthDate: &cxf.EditableField{FieldType: cxf.FieldTypeDate, Value: "1990-01-01"}},
		cxf.File{Type: cxf.CredentialTypeFile, ID: "ZmlsZQ", Name: "sample.txt", DecryptedSize: 15, IntegrityHash: base64.RawURLEncoding.EncodeToString(digest[:])},
		cxf.IdentityDocument{Type: cxf.CredentialTypeIdentityDocument, IdentificationNumber: &cxf.EditableField{FieldType: cxf.FieldTypeString, Value: "synthetic-id"}},
		cxf.ItemReference{Type: cxf.CredentialTypeItemReference, Reference: cxf.LinkedItem{Item: "aXRlbQ"}},
		cxf.Passkey{
			Type: cxf.CredentialTypePasskey, CredentialID: "Y3JlZA", RPID: "example.com", Username: "sample",
			UserDisplayName: "Sample", UserHandle: "dXNlcg", Key: base64.RawURLEncoding.EncodeToString(derKey),
			FIDO2Extensions: &cxf.FIDO2Extensions{
				CredBlob: &credBlob, Payments: &payments,
				HMACCredentials: &cxf.FIDO2HMACCredentials{
					Algorithm: "hmac-sha256", CredWithUV: "d2l0aC11dg", CredWithoutUV: "d2l0aG91dC11dg",
				},
				LargeBlob: &cxf.FIDO2LargeBlob{UncompressedSize: 4, Data: "ZGF0YQ"},
			},
		},
		cxf.Passport{Type: cxf.CredentialTypePassport, PassportNumber: &cxf.EditableField{FieldType: cxf.FieldTypeString, Value: "sample-number"}},
		cxf.PersonName{Type: cxf.CredentialTypePersonName, Given: &cxf.EditableField{FieldType: cxf.FieldTypeString, Value: "Sample"}},
		cxf.WiFi{Type: cxf.CredentialTypeWiFi, Hidden: &cxf.EditableField{FieldType: cxf.FieldTypeBoolean, Value: "false"}},
	}

	for _, credential := range credentials {
		data, err := json.Marshal(credential)
		if err != nil {
			t.Fatal(err)
		}
		if err := cxf.ValidateCredential(data); err != nil {
			t.Fatalf("%T: %v", credential, err)
		}
	}
}

// TestAppendixAExample checks the supplied Appendix A payload without changing it.
func TestAppendixAExample(t *testing.T) {
	data, err := os.ReadFile("testdata/appendix-a.json")
	if err != nil {
		t.Fatal(err)
	}
	header, err := cxf.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	types := make(map[string]bool)
	for _, account := range header.Accounts {
		for _, item := range account.Items {
			for _, raw := range item.Credentials {
				var credential struct {
					Type string `json:"type"`
				}
				if err := json.Unmarshal(raw, &credential); err != nil {
					t.Fatal(err)
				}
				types[credential.Type] = true
			}
		}
	}
	// Appendix A omits custom-fields and item-reference credentials.
	if len(types) != 15 || types[cxf.CredentialTypeCustomFields] || types[cxf.CredentialTypeItemReference] {
		t.Fatal("unexpected credential types in the Appendix A fixture")
	}
	var encoded bytes.Buffer
	if err := cxf.Encode(&encoded, header); err != nil {
		t.Fatal(err)
	}
	if semanticJSON(t, data) != semanticJSON(t, encoded.Bytes()) {
		t.Fatal("Appendix A data changed during the round trip")
	}
}

// TestCredentialValidationRejectsInvalidData checks required fields and values.
func TestCredentialValidationRejectsInvalidData(t *testing.T) {
	for _, tc := range []struct{ name, data string }{
		{"nonstring password value", `{"type":"basic-auth","password":{"fieldType":"string","value":123}}`},
		{"missing generated password", `{"type":"generated-password"}`},
		{"missing note value", `{"type":"note","content":{"fieldType":"string"}}`},
		{"invalid TOTP secret", `{"type":"totp","secret":"not-base32!","period":30,"digits":6,"algorithm":"sha1"}`},
		{"invalid SSH key", `{"type":"ssh-key","keyType":"ssh-ed25519","privateKey":"invalid"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := cxf.ValidateCredential([]byte(tc.data)); !errors.Is(err, cxf.ErrInvalidDocument) {
				t.Fatalf("expected invalid credential, got %v", err)
			}
		})
	}
}

// TestSSHKeyChecksPKCS8StructureWithoutAlgorithmDispatch checks PKCS#8 independently of Go key support.
func TestSSHKeyChecksPKCS8StructureWithoutAlgorithmDispatch(t *testing.T) {
	privateKeyInfo, err := asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Version:    0,
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}},
		PrivateKey: []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	credential := cxf.SSHKey{
		Type:       cxf.CredentialTypeSSHKey,
		KeyType:    "ssh-dss",
		PrivateKey: base64.RawURLEncoding.EncodeToString(privateKeyInfo),
	}
	if err := credential.Validate(); err != nil {
		t.Fatalf("valid PKCS#8 envelope with an unknown algorithm was rejected: %v", err)
	}
	credential.KeyType = "ed25519"
	if err := credential.Validate(); !errors.Is(err, cxf.ErrInvalidDocument) {
		t.Fatalf("unregistered SSH key type was accepted: %v", err)
	}
	credential.KeyType = "ssh-ed25519"

	credential.PrivateKey = base64.RawURLEncoding.EncodeToString(append(privateKeyInfo, 0))
	if err := credential.Validate(); !errors.Is(err, cxf.ErrInvalidDocument) {
		t.Fatalf("PKCS#8 envelope with trailing bytes was accepted: %v", err)
	}

	passkey := cxf.Passkey{
		Type: cxf.CredentialTypePasskey, CredentialID: "YQ", RPID: "example.com", Username: "sample",
		UserDisplayName: "Sample", UserHandle: "Yg", Key: base64.RawURLEncoding.EncodeToString(privateKeyInfo),
	}
	if err := passkey.Validate(); err != nil {
		t.Fatalf("passkey rejected a PKCS#8 envelope with an unknown algorithm: %v", err)
	}
}

// TestAdditionalCredentialValidationRejectsInvalidData checks other CXF types.
func TestAdditionalCredentialValidationRejectsInvalidData(t *testing.T) {
	for _, tc := range []struct{ name, data string }{
		{"invalid card date", `{"type":"credit-card","expiryDate":{"fieldType":"year-month","value":"2030-13"}}`},
		{"invalid file digest", `{"type":"file","id":"ZmlsZQ","name":"sample.txt","decryptedSize":1,"integrityHash":"bm90LWEtaGFzaA"}`},
		{"missing custom fields array", `{"type":"custom-fields"}`},
		{"invalid linked item ID", `{"type":"item-reference","reference":{"item":"!"}}`},
		{"missing passkey key", `{"type":"passkey","credentialId":"YQ","rpId":"example.com","username":"sample","userDisplayName":"Sample","userHandle":"Yg"}`},
		{"invalid Wi-Fi boolean", `{"type":"wifi","hidden":{"fieldType":"boolean","value":"yes"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := cxf.ValidateCredential([]byte(tc.data)); !errors.Is(err, cxf.ErrInvalidDocument) {
				t.Fatalf("expected invalid credential, got %v", err)
			}
		})
	}
}

// TestUnknownCredentialTypeIsAccepted checks unknown types remain usable as raw JSON.
func TestUnknownCredentialTypeIsAccepted(t *testing.T) {
	if err := cxf.ValidateCredential([]byte(`{"type":"future-credential","value":"sample"}`)); err != nil {
		t.Fatal(err)
	}
}

// TestItemValidationChecksKnownCredentialTypes checks validation through an item.
func TestItemValidationChecksKnownCredentialTypes(t *testing.T) {
	header := document(t)
	header.Accounts[0].Items[0].Credentials[0] = json.RawMessage(`{"type":"basic-auth","password":{"fieldType":"string","value":123,"label":"sample"}}`)
	err := header.Validate()
	if !errors.Is(err, cxf.ErrInvalidDocument) {
		t.Fatalf("expected invalid credential, got %v", err)
	}
	if strings.Contains(err.Error(), "sample") {
		t.Fatal("error disclosed credential data")
	}
}

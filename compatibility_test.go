package cxf_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"go.lucor.dev/cxf"
)

// TestCXFDocumentCompatibility covers CXF sections 2.1, 3.1, 3.2, and 3.5.
func TestCXFDocumentCompatibility(t *testing.T) {
	base := `{"version":{"major":1,"minor":0},"exporterRpId":"example.com","exporterDisplayName":"Example","timestamp":0,"accounts":[]}`
	account := `{"id":"YQ","username":"","email":"","collections":[],"items":[{"id":"Yg","title":"","credentials":[]}]}`
	withAccount := strings.Replace(base, `"accounts":[]`, `"accounts":[`+account+`]`, 1)
	for _, tc := range []struct {
		name, section, data string
		valid               bool
	}{
		{"empty required arrays", "2.1.2", withAccount, true},
		{"future minor version", "3.1.1", strings.Replace(base, `"minor":0`, `"minor":255`, 1), true},
		{"unknown member", "3.1.1", strings.Replace(base, `"timestamp":0`, `"timestamp":0,"future":{"opaque":null}`, 1), true},
		{"missing timestamp", "3.1", strings.Replace(base, `"timestamp":0,`, "", 1), false},
		{"null timestamp", "3.1", strings.Replace(base, `"timestamp":0`, `"timestamp":null`, 1), false},
		{"missing exporter RP ID", "3.1", strings.Replace(base, `"exporterRpId":"example.com",`, "", 1), false},
		{"missing exporter name", "3.1", strings.Replace(base, `"exporterDisplayName":"Example",`, "", 1), false},
		{"missing minor version", "3.1.1", strings.Replace(base, `,"minor":0`, "", 1), false},
		{"missing major version", "3.1.1", strings.Replace(base, `"major":1,`, "", 1), false},
		{"minor version overflow", "3.1.1", strings.Replace(base, `"minor":0`, `"minor":256`, 1), false},
		{"timestamp overflow", "3.1", strings.Replace(base, `"timestamp":0`, `"timestamp":18446744073709551616`, 1), false},
		{"invalid UTF-8", "3.4.3", strings.Replace(base, "Example", string([]byte{0xff}), 1), false},
		{"missing username", "3.2.1", strings.Replace(withAccount, `"username":"",`, "", 1), false},
		{"missing email", "3.2.1", strings.Replace(withAccount, `"email":"",`, "", 1), false},
		{"missing title", "3.2.3", strings.Replace(withAccount, `"title":"",`, "", 1), false},
		{"missing credentials", "3.2.3", strings.Replace(withAccount, `,"credentials":[]`, "", 1), false},
		{"null optional full name", "3.2.1", strings.Replace(withAccount, `"email":""`, `"email":"","fullName":null`, 1), false},
		{"null optional favorite", "3.2.3", strings.Replace(withAccount, `"credentials":[]`, `"favorite":null,"credentials":[]`, 1), false},
		{"explicit false favorite", "3.2.3", strings.Replace(withAccount, `"credentials":[]`, `"favorite":false,"credentials":[]`, 1), true},
		{"empty optional tags", "2.1.2", strings.Replace(withAccount, `"credentials":[]`, `"tags":[],"credentials":[]`, 1), false},
		{"null tag", "3.2.3", strings.Replace(withAccount, `"credentials":[]`, `"tags":[null],"credentials":[]`, 1), false},
		{"empty optional extensions", "2.1.2", strings.Replace(withAccount, `"credentials":[]`, `"extensions":[],"credentials":[]`, 1), false},
		{"null account", "3.2.1", strings.Replace(base, `"accounts":[]`, `"accounts":[null]`, 1), false},
		{"null URL", "3.2.4", strings.Replace(withAccount, `"credentials":[]`, `"scope":{"urls":[null],"androidApps":[]},"credentials":[]`, 1), false},
		{"missing Android fingerprint", "3.2.4.1.1", strings.Replace(withAccount, `"credentials":[]`, `"scope":{"urls":[],"androidApps":[{"bundleId":"com.example","certificate":{"hashAlg":"sha256"}}]},"credentials":[]`, 1), false},
		{"missing Android hash algorithm", "3.2.4.1.1", strings.Replace(withAccount, `"credentials":[]`, `"scope":{"urls":[],"androidApps":[{"bundleId":"com.example","certificate":{"fingerprint":"Zg"}}]},"credentials":[]`, 1), false},
		{"incorrect Android hash length", "3.2.4.1.1", strings.Replace(withAccount, `"credentials":[]`, `"scope":{"urls":[],"androidApps":[{"bundleId":"com.example","certificate":{"fingerprint":"Zg","hashAlg":"sha256"}}]},"credentials":[]`, 1), false},
		{"future Android hash", "2.1.1", strings.Replace(withAccount, `"credentials":[]`, `"scope":{"urls":[],"androidApps":[{"bundleId":"com.example","certificate":{"fingerprint":"Zg","hashAlg":"future-hash"}}]},"credentials":[]`, 1), true},
		{"null Android certificate", "3.2.4.1", strings.Replace(withAccount, `"credentials":[]`, `"scope":{"urls":[],"androidApps":[{"bundleId":"com.example","certificate":null}]},"credentials":[]`, 1), false},
		{"missing shared accessors", "3.5.1", strings.Replace(withAccount, `"credentials":[]`, `"extensions":[{"name":"shared"}],"credentials":[]`, 1), false},
		{"shared account", "3.5.1", strings.Replace(withAccount, `"collections":[]`, `"extensions":[{"name":"shared","accessors":[]}],"collections":[]`, 1), false},
		{"empty required accessors", "3.5.1", strings.Replace(withAccount, `"credentials":[]`, `"extensions":[{"name":"shared","accessors":[]}],"credentials":[]`, 1), true},
		{"missing accessor permissions", "3.5.1.1", strings.Replace(withAccount, `"credentials":[]`, `"extensions":[{"name":"shared","accessors":[{"type":"user","accountId":"Yw","name":"sample"}]}],"credentials":[]`, 1), false},
		{"unknown accessor and permission", "3.5.1.1", strings.Replace(withAccount, `"credentials":[]`, `"extensions":[{"name":"shared","accessors":[{"type":"future-type","accountId":"Yw","name":"sample","permissions":["future-permission"]}]}],"credentials":[]`, 1), true},
		{"unqualified custom extension", "3.5", strings.Replace(withAccount, `"credentials":[]`, `"extensions":[{"name":"custom"}],"credentials":[]`, 1), false},
		{"opaque custom extension", "3.5", strings.Replace(withAccount, `"credentials":[]`, `"extensions":[{"name":"example.com/custom","arbitrary":{"value":null}}],"credentials":[]`, 1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header, err := cxf.Decode(strings.NewReader(tc.data))
			if !tc.valid {
				if !errors.Is(err, cxf.ErrInvalidDocument) {
					t.Fatalf("CXF %s: expected invalid document, got %v", tc.section, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CXF %s: valid document rejected: %v", tc.section, err)
			}
			var encoded bytes.Buffer
			if err := cxf.Encode(&encoded, header); err != nil {
				t.Fatal(err)
			}
			if _, err := cxf.Decode(&encoded); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestCXFCredentialCompatibility covers CXF sections 2.1.1, 3.3, and 3.4.
func TestCXFCredentialCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, section, data string
		valid               bool
	}{
		{"future credential", "3.3", `{"type":"future-credential","opaque":{"value":null}}`, true},
		{"future editable field", "3.4.2", `{"type":"basic-auth","password":{"fieldType":"future-field","value":"sample"}}`, true},
		{"nonrecommended field type", "3.4.2", `{"type":"basic-auth","password":{"fieldType":"string","value":"sample"}}`, true},
		{"future Wi-Fi field", "3.4.2", `{"type":"wifi","hidden":{"fieldType":"future-boolean","value":"sample"}}`, true},
		{"missing Wi-Fi value", "3.4.2", `{"type":"wifi","ssid":{"fieldType":"string"}}`, false},
		{"missing Wi-Fi field type", "3.4.2", `{"type":"wifi","ssid":{"value":"sample"}}`, false},
		{"null Wi-Fi value", "3.4.2", `{"type":"wifi","ssid":{"fieldType":"string","value":null}}`, false},
		{"literal true", "3.4.3", `{"type":"custom-fields","fields":[{"fieldType":"boolean","value":"true"}]}`, true},
		{"literal false", "3.4.3", `{"type":"custom-fields","fields":[{"fieldType":"boolean","value":"false"}]}`, true},
		{"numeric boolean", "3.4.3", `{"type":"custom-fields","fields":[{"fieldType":"boolean","value":"1"}]}`, false},
		{"uppercase boolean", "3.4.3", `{"type":"custom-fields","fields":[{"fieldType":"boolean","value":"TRUE"}]}`, false},
		{"country code format", "3.4.3", `{"type":"address","country":{"fieldType":"country-code","value":"US"}}`, true},
		{"invalid country format", "3.4.3", `{"type":"address","country":{"fieldType":"country-code","value":"USA"}}`, false},
		{"subdivision code format", "3.4.3", `{"type":"address","territory":{"fieldType":"subdivision-code","value":"US-CA"}}`, true},
		{"invalid subdivision format", "3.4.3", `{"type":"address","territory":{"fieldType":"subdivision-code","value":"California"}}`, false},
		{"leap date", "3.4.3", `{"type":"note","content":{"fieldType":"date","value":"2024-02-29"}}`, true},
		{"invalid date", "3.4.3", `{"type":"note","content":{"fieldType":"date","value":"2023-02-29"}}`, false},
		{"invalid year month", "3.4.3", `{"type":"credit-card","expiryDate":{"fieldType":"year-month","value":"2030-13"}}`, false},
		{"email field", "3.4.3", `{"type":"custom-fields","fields":[{"fieldType":"email","value":"Sample <sample@example.com>"}]}`, true},
		{"invalid email field", "3.4.3", `{"type":"custom-fields","fields":[{"fieldType":"email","value":"invalid address"}]}`, false},
		{"null linked account", "3.2.2.1", `{"type":"item-reference","reference":{"item":"YQ","account":null}}`, false},
		{"external linked account", "3.2.2.1", `{"type":"item-reference","reference":{"item":"YQ","account":"Yg"}}`, true},
		{"empty required fields array", "2.1.2", `{"type":"custom-fields","fields":[]}`, true},
		{"empty optional field extensions", "2.1.2", `{"type":"note","content":{"fieldType":"string","value":"sample","extensions":[]}}`, false},
		{"null custom field", "3.3.5", `{"type":"custom-fields","fields":[null]}`, false},
		{"future TOTP algorithm", "3.3.16", `{"type":"totp","secret":"JBSWY3DPEHPK3PXP","period":30,"digits":6,"algorithm":"future-hash"}`, true},
		{"zero TOTP parameters", "3.3.16", `{"type":"totp","secret":"JBSWY3DPEHPK3PXP","period":0,"digits":0,"algorithm":"sha1"}`, true},
		{"TOTP period overflow", "3.3.16", `{"type":"totp","secret":"JBSWY3DPEHPK3PXP","period":65536,"digits":6,"algorithm":"sha1"}`, false},
		{"ICAO passport code", "3.3.13", `{"type":"passport","passportType":{"fieldType":"string","value":"PP"}}`, true},
		{"invalid ICAO passport code", "3.3.13", `{"type":"passport","passportType":{"fieldType":"string","value":"XX"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := cxf.ValidateCredential([]byte(tc.data))
			if tc.valid && err != nil {
				t.Fatalf("CXF %s: valid credential rejected: %v", tc.section, err)
			}
			if !tc.valid && !errors.Is(err, cxf.ErrInvalidDocument) {
				t.Fatalf("CXF %s: expected invalid credential, got %v", tc.section, err)
			}
			var item cxf.Item
			itemData := `{"id":"YQ","title":"Credential","credentials":[` + tc.data + `]}`
			err = json.Unmarshal([]byte(itemData), &item)
			if (err == nil) != tc.valid {
				t.Fatalf("CXF %s: direct item decoding disagrees: %v", tc.section, err)
			}
			header := document(t)
			header.Accounts[0].Items[0].Credentials = []json.RawMessage{json.RawMessage(tc.data)}
			var encoded bytes.Buffer
			err = cxf.Encode(&encoded, header)
			if !tc.valid {
				if !errors.Is(err, cxf.ErrInvalidDocument) || encoded.Len() != 0 {
					t.Fatal("invalid credential was written")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := cxf.Decode(&encoded)
			if err != nil {
				t.Fatal(err)
			}
			if semanticJSON(t, decoded.Accounts[0].Items[0].Credentials[0]) != semanticJSON(t, []byte(tc.data)) {
				t.Fatal("credential data changed during the round trip")
			}
		})
	}
}

// TestEncodeRejectsInvalidRawCredentials checks validation before any bytes are written.
func TestEncodeRejectsInvalidRawCredentials(t *testing.T) {
	header := document(t)
	header.Accounts[0].Items[0].Credentials = []json.RawMessage{json.RawMessage(`{"type":"wifi","ssid":{"fieldType":"string"}}`)}
	var output bytes.Buffer
	if err := cxf.Encode(&output, header); !errors.Is(err, cxf.ErrInvalidDocument) {
		t.Fatalf("expected invalid credential, got %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("invalid document was partially written")
	}
}

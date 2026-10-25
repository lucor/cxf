package cxf_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"go.lucor.dev/cxf"
)

// TestDecodeAccount checks standalone and document decoding use the same account rules.
func TestDecodeAccount(t *testing.T) {
	const account = `{"id":"YQ","username":"","email":"","collections":[],"items":[{"id":"Yg","title":"Note","credentials":[]}]}`
	for _, tc := range []struct {
		name  string
		data  string
		valid bool
	}{
		{"empty credentials", account, true},
		{"future credential", strings.Replace(account, `"credentials":[]`, `"credentials":[{"type":"future-type","opaque":42}]`, 1), true},
		{"custom extension", strings.Replace(account, `"title":"Note"`, `"title":"Note","extensions":[{"name":"example.com/custom","opaque":42}]`, 1), true},
		{"missing email", strings.Replace(account, `"email":"",`, ``, 1), false},
		{"null array", strings.Replace(account, `"collections":[]`, `"collections":null`, 1), false},
		{"invalid ID", strings.Replace(account, `"id":"Yg"`, `"id":"a+b/"`, 1), false},
		{"duplicate ID", strings.Replace(account, `"id":"Yg"`, `"id":"YQ"`, 1), false},
		{"invalid credential", strings.Replace(account, `"credentials":[]`, `"credentials":[{"type":"note"}]`, 1), false},
		{"null", `null`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := cxf.DecodeAccount([]byte(tc.data))
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, cxf.ErrInvalidDocument) {
				t.Fatalf("expected invalid account, got %v", err)
			}
			data := `{"version":{"major":1,"minor":0},"exporterRpId":"example.com","exporterDisplayName":"Example","timestamp":0,"accounts":[` + tc.data + `]}`
			_, documentErr := cxf.Decode(bytes.NewBufferString(data))
			if (documentErr == nil) != tc.valid {
				t.Fatalf("document validation disagrees: %v", documentErr)
			}
			if tc.valid {
				encoded, err := json.Marshal(decoded)
				if err != nil {
					t.Fatal(err)
				}
				if semanticJSON(t, encoded) != semanticJSON(t, []byte(tc.data)) {
					t.Fatal("account decoding changed supported data")
				}
			}
		})
	}
}

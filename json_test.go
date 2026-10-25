package cxf_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"go.lucor.dev/cxf"
)

// fixture reads the test document.
func fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/document.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// document decodes the test document.
func document(t *testing.T) *cxf.Header {
	t.Helper()
	header, err := cxf.Decode(bytes.NewReader(fixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	return header
}

// semanticJSON sorts object keys before comparison.
func semanticJSON(t *testing.T, data []byte) string {
	t.Helper()
	var value any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		t.Fatal(err)
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(normalized)
}

// TestRoundTripPreservesCredentialsExtensionsAndExplicitZeroValues checks JSON round trips.
func TestRoundTripPreservesCredentialsExtensionsAndExplicitZeroValues(t *testing.T) {
	original := fixture(t)
	header := document(t)
	var out bytes.Buffer
	if err := cxf.Encode(&out, header); err != nil {
		t.Fatal(err)
	}
	if got, want := semanticJSON(t, out.Bytes()), semanticJSON(t, original); got != want {
		t.Fatalf("round trip changed document\ngot: %s\nwant: %s", got, want)
	}

	header.Accounts[0].Items[0].Title = "Renamed"
	out.Reset()
	if err := cxf.Encode(&out, header); err != nil {
		t.Fatal(err)
	}
	want := bytes.Replace(original, []byte("Example login"), []byte("Renamed"), 1)
	if semanticJSON(t, out.Bytes()) != semanticJSON(t, want) {
		t.Fatal("editing a known field changed other data")
	}
}

// TestDecodeRejectsInvalidStructure checks invalid input.
func TestDecodeRejectsInvalidStructure(t *testing.T) {
	for _, tc := range []struct{ name, from, to string }{
		{"missing required array", `"androidApps": []`, `"unused": []`},
		{"missing identifier", `"id": "aXRlbQ",`, ""},
		{"null required array", `"collections": [{`, `"collections": null, "unused": [{`},
		{"wrong primitive type", `"timestamp": 0`, `"timestamp": "synthetic-secret"`},
		{"missing credential type", `"type": "basic-auth",`, ""},
		{"invalid credential object", `{"type": "future-credential", "opaque": {"counter": 9007199254740993}}`, `42`},
		{"null root", string(fixture(t)), "null"},
		{"second document", string(fixture(t)), string(fixture(t)) + "{}"},
		{"trailing junk", string(fixture(t)), string(fixture(t)) + "!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := bytes.Replace(fixture(t), []byte(tc.from), []byte(tc.to), 1)
			_, err := cxf.Decode(bytes.NewReader(data))
			if !errors.Is(err, cxf.ErrInvalidDocument) {
				t.Fatalf("expected invalid document, got %v", err)
			}
			if strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("error disclosed credential data")
			}
		})
	}
}

// TestDecodeIgnoresUnknownMembers checks unknown fields are ignored.
func TestDecodeIgnoresUnknownMembers(t *testing.T) {
	data := bytes.Replace(fixture(t), []byte(`"title": "Example login"`), []byte(`"title": "Example login", "extra": "ignored"`), 1)
	header, err := cxf.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cxf.Encode(&out, header); err != nil {
		t.Fatal(err)
	}
	if semanticJSON(t, fixture(t)) != semanticJSON(t, out.Bytes()) {
		t.Fatal("unknown member changed supported data")
	}
}

// TestVersionCompatibility checks supported versions.
func TestVersionCompatibility(t *testing.T) {
	header := document(t)
	header.Version.Major = 2
	var out bytes.Buffer
	if err := cxf.Encode(&out, header); !errors.Is(err, cxf.ErrUnsupportedVersion) || out.Len() != 0 {
		t.Fatalf("unsupported version was written: %v", err)
	}
	header.Version.Major, header.Version.Minor = 1, 255
	if err := cxf.Encode(&out, header); err != nil {
		t.Fatal(err)
	}
	decoded, err := cxf.Decode(&out)
	if err != nil || decoded.Version.Minor != 255 {
		t.Fatalf("future minor version was not preserved: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"major":2,"minor":0}`), &decoded.Version); !errors.Is(err, cxf.ErrUnsupportedVersion) {
		t.Fatalf("unsupported major version was accepted by json.Unmarshal: %v", err)
	}
}

// TestIdentifiers checks ID formats and uniqueness.
func TestIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*cxf.Header)
	}{
		{"empty", func(h *cxf.Header) { h.Accounts[0].ID = "" }},
		{"not base64url", func(h *cxf.Header) { h.Accounts[0].ID = "a+b/" }},
		{"newline", func(h *cxf.Header) { h.Accounts[0].ID += "\n" }},
		{"too long", func(h *cxf.Header) { h.Accounts[0].ID = base64.RawURLEncoding.EncodeToString(make([]byte, 65)) }},
		{"duplicate accounts", func(h *cxf.Header) { h.Accounts = append(h.Accounts, h.Accounts[0]) }},
		{"duplicate entities", func(h *cxf.Header) { h.Accounts[0].Collections[0].ID = h.Accounts[0].Items[0].ID }},
		{"duplicate padded encoding", func(h *cxf.Header) {
			h.Accounts[0].Items = append(h.Accounts[0].Items, h.Accounts[0].Items[0])
			h.Accounts[0].Items[1].ID = "aXRlbQ=="
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := document(t)
			tc.edit(header)
			if err := header.Validate(); !errors.Is(err, cxf.ErrInvalidDocument) {
				t.Fatalf("expected invalid identifier, got %v", err)
			}
		})
	}
	t.Run("maximum length", func(t *testing.T) {
		h := document(t)
		h.Accounts[0].Items[0].ID = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		if err := h.Validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("external item reference", func(t *testing.T) {
		h := document(t)
		h.Accounts[0].Collections[0].Items[0].Item = "ZXh0ZXJuYWw"
		if err := h.Validate(); err != nil {
			t.Fatal(err)
		}
	})
}

type failingReader struct{ err error }

// Read always returns the configured error.
func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

type failingWriter struct{ err error }

// Write always returns the configured error.
func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

// Write reports a short write.
func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

// TestIOFailuresAndInvalidDocumentsDoNotReportSuccess checks I/O errors.
func TestIOFailuresAndInvalidDocumentsDoNotReportSuccess(t *testing.T) {
	failure := errors.New("I/O unavailable")
	if _, err := cxf.Decode(failingReader{failure}); !errors.Is(err, failure) {
		t.Fatalf("reader error lost: %v", err)
	}
	if _, err := cxf.Decode(io.MultiReader(bytes.NewReader(fixture(t)), failingReader{failure})); !errors.Is(err, failure) {
		t.Fatalf("error while reading document end lost: %v", err)
	}
	if err := cxf.Encode(failingWriter{failure}, document(t)); !errors.Is(err, failure) {
		t.Fatalf("writer error lost: %v", err)
	}
	if err := cxf.Encode(shortWriter{}, document(t)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write reported success: %v", err)
	}
	var out bytes.Buffer
	if err := cxf.Encode(&out, nil); !errors.Is(err, cxf.ErrInvalidDocument) || out.Len() != 0 {
		t.Fatalf("nil document was written: %v", err)
	}
	invalid := document(t)
	invalid.Accounts[0].Items = nil
	if err := cxf.Encode(&out, invalid); !errors.Is(err, cxf.ErrInvalidDocument) || out.Len() != 0 {
		t.Fatalf("invalid document was written: %v", err)
	}
}

// TestStandaloneItemValidationAndRequiredEmptyArrays checks item validation.
func TestStandaloneItemValidationAndRequiredEmptyArrays(t *testing.T) {
	item := cxf.Item{ID: "aXRlbQ", Title: "Empty item", Credentials: []json.RawMessage{}}
	if err := item.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"credentials":[]`)) {
		t.Fatalf("required empty array not written: %s", encoded)
	}
	item.Credentials = nil
	if err := item.Validate(); !errors.Is(err, cxf.ErrInvalidDocument) {
		t.Fatalf("nil credentials accepted: %v", err)
	}
	var missing *cxf.Item
	if err := missing.Validate(); !errors.Is(err, cxf.ErrInvalidDocument) {
		t.Fatalf("nil item accepted: %v", err)
	}
}

// FuzzDecodeEncode checks accepted documents can be encoded and decoded.
func FuzzDecodeEncode(f *testing.F) {
	data, err := os.ReadFile("testdata/document.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, input []byte) {
		header, err := cxf.Decode(bytes.NewReader(input))
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := cxf.Encode(&out, header); err != nil {
			t.Fatalf("accepted document cannot be encoded: %v", err)
		}
		if _, err := cxf.Decode(&out); err != nil {
			t.Fatalf("encoded document cannot be decoded: %v", err)
		}
	})
}

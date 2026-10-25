package cxf

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	// ErrInvalidDocument marks invalid JSON or CXF data.
	ErrInvalidDocument = errors.New("invalid CXF document")
	// ErrUnsupportedVersion marks an unsupported CXF major version.
	ErrUnsupportedVersion = errors.New("unsupported CXF major version")
)

// ValidationError describes a CXF schema violation.
type ValidationError struct {
	// Path is the JSON path of the invalid value.
	Path string
	// Reason describes the violation without including the value.
	Reason string
	cause  error
}

// Error returns the path and reason without including the rejected value.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s: %s", ErrInvalidDocument, e.Path, e.Reason)
}

// Unwrap identifies this error as an invalid CXF document.
func (e *ValidationError) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrInvalidDocument}
	}
	return []error{ErrInvalidDocument, e.cause}
}

// decodeObject checks required members and decodes into a temporary value.
func decodeObject(data []byte, path string, required, optional []string, target any) error {
	fields, err := credentialFields(data, path, required, optional)
	if err != nil {
		return err
	}
	data, err = json.Marshal(knownFields(fields, required, optional))
	if err != nil {
		return invalid(path, "invalid object")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return decodingError(err, path, "invalid field type")
	}
	return nil
}

// knownFields keeps only exact JSON member names from a modeled object.
func knownFields(fields map[string]json.RawMessage, groups ...[]string) map[string]json.RawMessage {
	known := make(map[string]json.RawMessage)
	for _, names := range groups {
		for _, name := range names {
			if value, ok := fields[name]; ok {
				known[name] = value
			}
		}
	}
	return known
}

// validateUTF8String checks a string before JSON can replace invalid bytes.
func validateUTF8String(path, value string) error {
	if !utf8.ValidString(value) {
		return invalid(path, "invalid UTF-8")
	}
	return nil
}

// decodingError keeps nested validation paths and reports JSON type errors by field.
func decodingError(err error, path, reason string) error {
	var validation *ValidationError
	if errors.As(err, &validation) {
		return err
	}
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &typeError) && typeError.Field != "" {
		path += "." + typeError.Field
	}
	return invalid(path, reason)
}

// credentialFields checks an object's required members and array encoding.
func credentialFields(data []byte, path string, required, optional []string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, invalid(path, "invalid UTF-8")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, invalid(path, "expected an object")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return nil, invalid(path+"."+name, "required field is missing")
		}
	}
	for group, names := range [][]string{required, optional} {
		for _, name := range names {
			value, ok := fields[name]
			if !ok {
				continue
			}
			value = bytes.TrimSpace(value)
			if bytes.Equal(value, []byte("null")) {
				return nil, invalid(path+"."+name, "must not be null")
			}
			if len(value) > 0 && value[0] == '[' {
				values, err := fieldArray(fields, name, path)
				if err != nil {
					return nil, err
				}
				if group == 1 && len(values) == 0 {
					return nil, invalid(path+"."+name, "empty optional array must be omitted")
				}
			}
		}
	}
	return fields, nil
}

// validateDocumentFields checks required members before decoding loses their presence.
func validateDocumentFields(data []byte) error {
	fields, err := credentialFields(data, "header", []string{"version", "exporterRpId", "exporterDisplayName", "timestamp", "accounts"}, nil)
	if err != nil {
		return err
	}
	if _, err := credentialFields(fields["version"], "version", []string{"major", "minor"}, nil); err != nil {
		return err
	}
	accounts, err := fieldArray(fields, "accounts", "header")
	if err != nil {
		return err
	}
	for i, raw := range accounts {
		path := fmt.Sprintf("accounts[%d]", i)
		if err := validateAccountFields(raw, path); err != nil {
			return err
		}
	}
	return nil
}

// validateAccountFields checks required account and child members.
func validateAccountFields(data []byte, path string) error {
	account, err := credentialFields(data, path, []string{"id", "username", "email", "collections", "items"}, []string{"fullName", "extensions"})
	if err != nil {
		return err
	}
	items, err := fieldArray(account, "items", path)
	if err != nil {
		return err
	}
	for i, item := range items {
		if err := validateItemFields(item, fmt.Sprintf("%s.items[%d]", path, i)); err != nil {
			return err
		}
	}
	collections, err := fieldArray(account, "collections", path)
	if err != nil {
		return err
	}
	for i, collection := range collections {
		if err := validateCollectionFields(collection, fmt.Sprintf("%s.collections[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

// validateItemFields checks item members and scope arrays.
func validateItemFields(data []byte, path string) error {
	fields, err := credentialFields(data, path, []string{"id", "title", "credentials"}, []string{"creationAt", "modifiedAt", "subtitle", "favorite", "scope", "tags", "extensions"})
	if err != nil {
		return err
	}
	if raw, ok := fields["scope"]; ok {
		scope, err := credentialFields(raw, path+".scope", []string{"urls", "androidApps"}, nil)
		if err != nil {
			return err
		}
		for _, name := range []string{"urls", "androidApps"} {
			if _, err := fieldArray(scope, name, path+".scope"); err != nil {
				return err
			}
		}
	}
	_, err = fieldArray(fields, "credentials", path)
	return err
}

// validateCollectionFields checks collection members and nested collections.
func validateCollectionFields(data []byte, path string) error {
	fields, err := credentialFields(data, path, []string{"id", "title", "items"}, []string{"creationAt", "modifiedAt", "subtitle", "subCollections", "extensions"})
	if err != nil {
		return err
	}
	links, err := fieldArray(fields, "items", path)
	if err != nil {
		return err
	}
	for i, raw := range links {
		if _, err := credentialFields(raw, fmt.Sprintf("%s.items[%d]", path, i), []string{"item"}, []string{"account"}); err != nil {
			return err
		}
	}
	children, err := fieldArray(fields, "subCollections", path)
	if err != nil {
		return err
	}
	for i, raw := range children {
		if err := validateCollectionFields(raw, fmt.Sprintf("%s.subCollections[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

// fieldArray reads a present array without treating JSON null as an empty array.
func fieldArray(fields map[string]json.RawMessage, name, path string) ([]json.RawMessage, error) {
	raw, ok := fields[name]
	if !ok {
		return nil, nil
	}
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, invalid(path+"."+name, "expected an array")
	}
	for _, value := range values {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, invalid(path+"."+name, "array members must not be null")
		}
	}
	return values, nil
}

// validateHeader checks identifiers and nested values after member presence checks.
func validateHeader(header *Header) error {
	if header == nil {
		return invalid("header", "must not be nil")
	}
	if err := validateUTF8String("header.exporterRpId", header.ExporterRPID); err != nil {
		return err
	}
	if err := validateUTF8String("header.exporterDisplayName", header.ExporterDisplayName); err != nil {
		return err
	}
	if err := header.Version.Validate(); err != nil {
		return err
	}
	if header.Accounts == nil {
		return invalid("accounts", "required array must not be null")
	}
	accounts := make(map[string]struct{})
	for i := range header.Accounts {
		account := &header.Accounts[i]
		path := fmt.Sprintf("accounts[%d]", i)
		if err := uniqueID(account.ID, path+".id", accounts); err != nil {
			return err
		}
		if err := validateAccount(account, path); err != nil {
			return err
		}
	}
	return nil
}

// validateAccount checks identifiers and nested values within one account.
func validateAccount(account *Account, path string) error {
	if err := validateUTF8String(path+".username", account.Username); err != nil {
		return err
	}
	if err := validateUTF8String(path+".email", account.Email); err != nil {
		return err
	}
	if account.FullName != nil {
		if err := validateUTF8String(path+".fullName", *account.FullName); err != nil {
			return err
		}
	}
	seen := make(map[string]struct{})
	if err := uniqueID(account.ID, path+".id", seen); err != nil {
		return err
	}
	if account.Collections == nil || account.Items == nil {
		return invalid(path, "required arrays must not be null")
	}
	if err := validateExtensions(account.Extensions, path+".extensions", false); err != nil {
		return err
	}
	for i := range account.Items {
		if err := validateItem(&account.Items[i], fmt.Sprintf("%s.items[%d]", path, i), seen); err != nil {
			return err
		}
	}
	for i := range account.Collections {
		if err := validateCollection(&account.Collections[i], fmt.Sprintf("%s.collections[%d]", path, i), seen); err != nil {
			return err
		}
	}
	return nil
}

// validateItem checks an item's ID, arrays, and JSON envelopes.
func validateItem(item *Item, path string, seen map[string]struct{}) error {
	if err := validateUTF8String(path+".title", item.Title); err != nil {
		return err
	}
	if item.Subtitle != nil {
		if err := validateUTF8String(path+".subtitle", *item.Subtitle); err != nil {
			return err
		}
	}
	for i, tag := range item.Tags {
		if err := validateUTF8String(fmt.Sprintf("%s.tags[%d]", path, i), tag); err != nil {
			return err
		}
	}
	if err := uniqueID(item.ID, path+".id", seen); err != nil {
		return err
	}
	if item.Credentials == nil {
		return invalid(path+".credentials", "required array must not be null")
	}
	if err := validateCredentials(item.Credentials, path+".credentials"); err != nil {
		return err
	}
	if err := validateExtensions(item.Extensions, path+".extensions", true); err != nil {
		return err
	}
	if item.Scope != nil {
		if err := item.Scope.Validate(); err != nil {
			return prefixValidationError(err, path)
		}
	}
	return nil
}

// validateCollection checks a collection and its children.
func validateCollection(collection *Collection, path string, seen map[string]struct{}) error {
	if err := validateUTF8String(path+".title", collection.Title); err != nil {
		return err
	}
	if collection.Subtitle != nil {
		if err := validateUTF8String(path+".subtitle", *collection.Subtitle); err != nil {
			return err
		}
	}
	if err := uniqueID(collection.ID, path+".id", seen); err != nil {
		return err
	}
	if collection.Items == nil {
		return invalid(path+".items", "required array must not be null")
	}
	if err := validateExtensions(collection.Extensions, path+".extensions", true); err != nil {
		return err
	}
	for i := range collection.Items {
		link := &collection.Items[i]
		linkPath := fmt.Sprintf("%s.items[%d]", path, i)
		if _, err := decodeID(link.Item); err != nil {
			return invalid(linkPath+".item", "invalid identifier")
		}
		if link.Account != nil {
			if _, err := decodeID(*link.Account); err != nil {
				return invalid(linkPath+".account", "invalid identifier")
			}
		}
	}
	for i := range collection.SubCollections {
		if err := validateCollection(&collection.SubCollections[i], fmt.Sprintf("%s.subCollections[%d]", path, i), seen); err != nil {
			return err
		}
	}
	return nil
}

// decodeID accepts padded or unpadded URL-safe Base64 IDs.
// Go's decoder ignores CR and LF, so this rejects them first.
func decodeID(id string) ([]byte, error) {
	decoded, err := decodeBase64URL(id)
	if err != nil || len(decoded) == 0 || len(decoded) > 64 {
		return nil, ErrInvalidDocument
	}
	return decoded, nil
}

// validatePKCS8PrivateKey checks the unencrypted PKCS#8 DER envelope.
func validatePKCS8PrivateKey(data []byte) error {
	var key struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
		Attributes asn1.RawValue `asn1:"optional,tag:0"`
	}
	rest, err := asn1.Unmarshal(data, &key)
	if err != nil || len(rest) != 0 || key.Version != 0 || len(key.Algorithm.Algorithm) == 0 || len(key.PrivateKey) == 0 {
		return invalid("privateKey", "invalid PKCS#8 envelope")
	}
	return nil
}

// decodeBase64URL accepts padded or unpadded URL-safe Base64.
// Go's decoder ignores CR and LF, so this rejects them first.
func decodeBase64URL(value string) ([]byte, error) {
	if strings.ContainsAny(value, "\r\n") {
		return nil, ErrInvalidDocument
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		decoded, err = base64.URLEncoding.Strict().DecodeString(value)
	}
	return decoded, err
}

// uniqueID checks an ID and adds it to the set.
func uniqueID(id, path string, seen map[string]struct{}) error {
	decoded, err := decodeID(id)
	if err != nil {
		return invalid(path, "invalid identifier")
	}
	key := string(decoded)
	if _, exists := seen[key]; exists {
		return invalid(path, "duplicate entity identifier")
	}
	seen[key] = struct{}{}
	return nil
}

// invalid returns a schema error without including the rejected value.
func invalid(path, reason string) error {
	return &ValidationError{Path: path, Reason: reason}
}

// prefixValidationError adds a containing path without exposing values.
func prefixValidationError(err error, path string) error {
	var validation *ValidationError
	if !errors.As(err, &validation) {
		return err
	}
	return &ValidationError{
		Path:   path + "." + validation.Path,
		Reason: validation.Reason,
		cause:  validation.cause,
	}
}

type namedEditableField struct {
	name  string
	field *EditableField
}

// validateOptionalFields checks each present editable field.
func validateOptionalFields(path string, fields ...namedEditableField) error {
	for _, field := range fields {
		if field.field != nil {
			if err := validateEditableFieldValue(field.field, path+"."+field.name); err != nil {
				return err
			}
		}
	}
	return nil
}

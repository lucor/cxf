package cxf

import "encoding/json"

// Collection groups item references and nested collections.
type Collection struct {
	// ID is a Base64url identifier, unique within its account and at most 64 decoded bytes.
	ID string `json:"id"`
	// CreationAt is the optional creation time, in Unix seconds.
	CreationAt *uint64 `json:"creationAt,omitempty"`
	// ModifiedAt is the optional last modification time, in Unix seconds.
	ModifiedAt *uint64 `json:"modifiedAt,omitempty"`
	// Title is the collection's display name.
	Title string `json:"title"`
	// Subtitle is an optional description.
	Subtitle *string `json:"subtitle,omitempty"`
	// Items lists linked items. The array is required even when empty.
	Items []LinkedItem `json:"items"`
	// SubCollections optionally lists nested collections.
	SubCollections []Collection `json:"subCollections,omitempty"`
	// Extensions holds optional collection extension objects as JSON.
	Extensions []json.RawMessage `json:"extensions,omitempty"`
}

// UnmarshalJSON decodes and validates a collection atomically.
func (collection *Collection) UnmarshalJSON(data []byte) error {
	if collection == nil {
		return invalid("collection", "must not be nil")
	}
	type plain Collection
	var decoded plain
	if err := decodeObject(data, "collection", []string{"id", "title", "items"}, []string{"creationAt", "modifiedAt", "subtitle", "subCollections", "extensions"}, &decoded); err != nil {
		return err
	}
	candidate := Collection(decoded)
	if err := validateCollection(&candidate, "collection", make(map[string]struct{})); err != nil {
		return err
	}
	*collection = candidate
	return nil
}

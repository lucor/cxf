package cxf

import "encoding/json"

// Item holds related credentials, such as a login and a TOTP secret.
type Item struct {
	// ID is a Base64url identifier, unique within its account and at most 64 decoded bytes.
	ID string `json:"id"`
	// CreationAt is the optional creation time, in Unix seconds.
	CreationAt *uint64 `json:"creationAt,omitempty"`
	// ModifiedAt is the optional last modification time, in Unix seconds.
	ModifiedAt *uint64 `json:"modifiedAt,omitempty"`
	// Title is the item's display name.
	Title string `json:"title"`
	// Subtitle is an optional description.
	Subtitle *string `json:"subtitle,omitempty"`
	// Favorite records whether the user marked the item as a favorite; absent means false.
	Favorite *bool `json:"favorite,omitempty"`
	// Scope optionally identifies where the credentials should be offered.
	Scope *CredentialScope `json:"scope,omitempty"`
	// Credentials groups related credential objects as JSON; an empty array is allowed.
	Credentials []json.RawMessage `json:"credentials"`
	// Tags optionally lists labels chosen by the user.
	Tags []string `json:"tags,omitempty"`
	// Extensions holds optional item extension objects as JSON.
	Extensions []json.RawMessage `json:"extensions,omitempty"`
}

// Validate checks an item without a document header.
func (item *Item) Validate() error {
	if item == nil {
		return invalid("item", "must not be nil")
	}
	if err := validateItem(item, "item", make(map[string]struct{})); err != nil {
		return err
	}
	data, err := json.Marshal(item)
	if err != nil {
		return invalid("item", "cannot encode item")
	}
	if err := validateItemFields(data, "item"); err != nil {
		return err
	}
	return nil
}

// UnmarshalJSON decodes and validates an item atomically.
func (item *Item) UnmarshalJSON(data []byte) error {
	if item == nil {
		return invalid("item", "must not be nil")
	}
	type plain Item
	var decoded plain
	if err := decodeObject(data, "item", []string{"id", "title", "credentials"}, []string{"creationAt", "modifiedAt", "subtitle", "favorite", "scope", "tags", "extensions"}, &decoded); err != nil {
		return err
	}
	candidate := Item(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*item = candidate
	return nil
}

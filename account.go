package cxf

import "encoding/json"

// Account holds one provider account and its items.
type Account struct {
	// ID is a Base64url identifier of at most 64 decoded bytes.
	ID string `json:"id"`
	// Username is the account's chosen name, or an empty string if unset.
	Username string `json:"username"`
	// Email is the address used to register the account.
	Email string `json:"email"`
	// FullName optionally records the account owner's full name.
	FullName *string `json:"fullName,omitempty"`
	// Collections lists collections owned by this account, excluding those shared with it.
	Collections []Collection `json:"collections"`
	// Items lists items owned by this account, excluding those shared with it.
	Items []Item `json:"items"`
	// Extensions holds optional account extension objects as JSON.
	Extensions []json.RawMessage `json:"extensions,omitempty"`
}

// DecodeAccount reads and validates one account, including its items and collections.
func DecodeAccount(data []byte) (Account, error) {
	var account Account
	if err := json.Unmarshal(data, &account); err != nil {
		return Account{}, err
	}
	return account, nil
}

// UnmarshalJSON decodes and validates an account atomically.
func (account *Account) UnmarshalJSON(data []byte) error {
	if account == nil {
		return invalid("account", "must not be nil")
	}
	type plain Account
	var decoded plain
	if err := decodeObject(data, "account", []string{"id", "username", "email", "collections", "items"}, []string{"fullName", "extensions"}, &decoded); err != nil {
		return err
	}
	candidate := Account(decoded)
	if err := validateAccount(&candidate, "account"); err != nil {
		return err
	}
	*account = candidate
	return nil
}

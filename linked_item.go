package cxf

// LinkedItem refers to an item, which may be outside this document.
type LinkedItem struct {
	// Item is the referenced item's Base64url ID; the item may be outside the document.
	Item string `json:"item"`
	// Account is the owning account's Base64url ID; absent means the current account.
	Account *string `json:"account,omitempty"`
}

// Validate checks the referenced item and optional account identifiers.
func (item *LinkedItem) Validate() error {
	if item == nil {
		return invalid("linkedItem", "must not be nil")
	}
	if _, err := decodeID(item.Item); err != nil {
		return invalid("linkedItem.item", "invalid identifier")
	}
	if item.Account != nil {
		if _, err := decodeID(*item.Account); err != nil {
			return invalid("linkedItem.account", "invalid identifier")
		}
	}
	return nil
}

// UnmarshalJSON decodes and validates a linked item atomically.
func (item *LinkedItem) UnmarshalJSON(data []byte) error {
	if item == nil {
		return invalid("linkedItem", "must not be nil")
	}
	type plain LinkedItem
	var decoded plain
	if err := decodeObject(data, "linkedItem", []string{"item"}, []string{"account"}, &decoded); err != nil {
		return err
	}
	candidate := LinkedItem(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*item = candidate
	return nil
}

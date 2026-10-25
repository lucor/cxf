package cxf

// CredentialTypeNote is the CXF note type.
const CredentialTypeNote = "note"

// Note stores a text note.
type Note struct {
	// Type must be CredentialTypeNote.
	Type string `json:"type"`
	// Content holds the note text; FieldTypeString is recommended.
	Content EditableField `json:"content"`
}

// Validate checks the credential type and content field.
func (credential *Note) Validate() error {
	if credential == nil || credential.Type != CredentialTypeNote {
		return invalid("note.type", "invalid credential type")
	}
	return validateEditableFieldValue(&credential.Content, "note.content")
}

// UnmarshalJSON decodes and validates a note credential atomically.
func (credential *Note) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeNote, "must not be nil")
	}
	type plain Note
	var decoded plain
	if err := decodeCredential(data, CredentialTypeNote, "note", []string{"type", "content"}, nil, &decoded); err != nil {
		return err
	}
	candidate := Note(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

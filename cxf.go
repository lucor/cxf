package cxf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Decode reads and validates one CXF document.
func Decode(r io.Reader) (*Header, error) {
	dec := json.NewDecoder(r)
	var data json.RawMessage
	if err := dec.Decode(&data); err != nil {
		// Avoid returning parser errors that may include input values.
		var syntax *json.SyntaxError
		var fieldType *json.UnmarshalTypeError
		if errors.As(err, &syntax) || errors.As(err, &fieldType) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: cannot decode document", ErrInvalidDocument)
		}
		return nil, fmt.Errorf("read CXF document: %w", err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		var syntax *json.SyntaxError
		if err != nil && !errors.As(err, &syntax) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("read end of CXF document: %w", err)
		}
		return nil, fmt.Errorf("%w: trailing data", ErrInvalidDocument)
	}
	var header Header
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, err
	}
	return &header, nil
}

// Encode validates a document before writing it.
func Encode(w io.Writer, header *Header) error {
	if err := header.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("%w: cannot encode document", ErrInvalidDocument)
	}
	n, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("write CXF document: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("write CXF document: %w", io.ErrShortWrite)
	}
	return nil
}

package cxf

import "encoding/json"

// Header is a CXF document.
type Header struct {
	// Version identifies the CXF revision used by this document.
	Version Version `json:"version"`
	// ExporterRPID is the exporting application's relying party identifier.
	ExporterRPID string `json:"exporterRpId"`
	// ExporterDisplayName is the exporting application's display name.
	ExporterDisplayName string `json:"exporterDisplayName"`
	// Timestamp is the export completion time, in Unix seconds.
	Timestamp uint64 `json:"timestamp"`
	// Accounts lists the exported accounts. The array is required even when empty.
	Accounts []Account `json:"accounts"`
}

// Validate checks the CXF data represented by the header.
func (header *Header) Validate() error {
	if err := validateHeader(header); err != nil {
		return err
	}
	data, err := json.Marshal(header)
	if err != nil {
		return invalid("header", "cannot encode document")
	}
	return validateDocumentFields(data)
}

// UnmarshalJSON decodes and validates a CXF document atomically.
func (header *Header) UnmarshalJSON(data []byte) error {
	if header == nil {
		return invalid("header", "must not be nil")
	}
	type plain Header
	var decoded plain
	if err := decodeObject(data, "header", []string{"version", "exporterRpId", "exporterDisplayName", "timestamp", "accounts"}, nil, &decoded); err != nil {
		return err
	}
	candidate := Header(decoded)
	if err := validateHeader(&candidate); err != nil {
		return err
	}
	*header = candidate
	return nil
}

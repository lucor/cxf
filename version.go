package cxf

import "fmt"

// Version identifies the CXF schema version.
type Version struct {
	// Major changes when the format introduces incompatible changes.
	Major uint8 `json:"major"`
	// Minor changes for additions compatible with the same major version.
	Minor uint8 `json:"minor"`
}

// UnmarshalJSON decodes a CXF version atomically.
func (version *Version) UnmarshalJSON(data []byte) error {
	if version == nil {
		return invalid("version", "must not be nil")
	}
	type plain Version
	var decoded plain
	if err := decodeObject(data, "version", []string{"major", "minor"}, nil, &decoded); err != nil {
		return err
	}
	candidate := Version(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*version = candidate
	return nil
}

// Validate checks whether the major version is supported.
func (version *Version) Validate() error {
	if version == nil {
		return invalid("version", "must not be nil")
	}
	if version.Major != 1 {
		return &ValidationError{Path: "version.major", Reason: fmt.Sprintf("unsupported major version %d", version.Major), cause: ErrUnsupportedVersion}
	}
	return nil
}

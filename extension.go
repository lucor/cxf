package cxf

import (
	"encoding/json"
	"fmt"
	"strings"
)

// validateExtensions checks extension names and the defined sharing structure.
func validateExtensions(extensions []json.RawMessage, path string, allowShared bool) error {
	for i, raw := range extensions {
		extensionPath := fmt.Sprintf("%s[%d]", path, i)
		fields, err := credentialFields(raw, extensionPath, []string{"name"}, nil)
		if err != nil {
			return err
		}
		var name string
		if err := json.Unmarshal(fields["name"], &name); err != nil {
			return invalid(extensionPath+".name", "expected a string")
		}
		if name == "shared" {
			if !allowShared {
				return invalid(extensionPath, "shared is only allowed on items and collections")
			}
			if err := validateShared(raw, extensionPath); err != nil {
				return err
			}
			continue
		}
		provider, extension, ok := strings.Cut(name, "/")
		if !ok || provider == "" || extension == "" || strings.ContainsAny(provider, " \t\r\n:") {
			return invalid(extensionPath+".name", "expected an exporter RP ID and extension name")
		}
	}
	return nil
}

// validateShared checks accessors without enforcing application permissions.
func validateShared(data json.RawMessage, path string) error {
	var shared Shared
	if err := json.Unmarshal(data, &shared); err != nil {
		return prefixValidationError(err, path)
	}
	return nil
}

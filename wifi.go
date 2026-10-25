package cxf

// CredentialTypeWiFi is the CXF Wi-Fi type.
const CredentialTypeWiFi = "wifi"

// WiFi stores wireless network fields.
type WiFi struct {
	// Type must be CredentialTypeWiFi.
	Type string `json:"type"`
	// SSID names the network; FieldTypeString is recommended.
	SSID *EditableField `json:"ssid,omitempty"`
	// NetworkSecurityType describes network security; FieldTypeWiFiNetworkSecurityType or FieldTypeString is recommended.
	NetworkSecurityType *EditableField `json:"networkSecurityType,omitempty"`
	// Passphrase holds the network secret; FieldTypeConcealedString is recommended.
	Passphrase *EditableField `json:"passphrase,omitempty"`
	// Hidden marks a hidden network; FieldTypeBoolean is recommended.
	Hidden *EditableField `json:"hidden,omitempty"`
}

// Validate checks the wireless network fields.
func (credential *WiFi) Validate() error {
	if credential == nil || credential.Type != CredentialTypeWiFi {
		return invalid("wifi.type", "invalid credential type")
	}
	return validateOptionalFields("wifi",
		namedEditableField{"ssid", credential.SSID},
		namedEditableField{"networkSecurityType", credential.NetworkSecurityType},
		namedEditableField{"passphrase", credential.Passphrase},
		namedEditableField{"hidden", credential.Hidden},
	)
}

// UnmarshalJSON decodes and validates a Wi-Fi credential atomically.
func (credential *WiFi) UnmarshalJSON(data []byte) error {
	if credential == nil {
		return invalid(CredentialTypeWiFi, "must not be nil")
	}
	type plain WiFi
	var decoded plain
	if err := decodeCredential(data, CredentialTypeWiFi, "wifi", []string{"type"}, []string{"ssid", "networkSecurityType", "passphrase", "hidden"}, &decoded); err != nil {
		return err
	}
	candidate := WiFi(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*credential = candidate
	return nil
}

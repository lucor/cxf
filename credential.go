package cxf

import (
	"encoding/json"
	"fmt"
)

// FieldTypeString is the CXF editable string field type.
const FieldTypeString = "string"

// FieldTypeEmail is the CXF editable email field type.
const FieldTypeEmail = "email"

// FieldTypeNumber is the CXF editable numeric field type.
const FieldTypeNumber = "number"

// FieldTypeConcealedString is the CXF editable secret field type.
const FieldTypeConcealedString = "concealed-string"

// FieldTypeDate is the CXF editable date field type.
const FieldTypeDate = "date"

// FieldTypeCountryCode is the CXF country code field type.
const FieldTypeCountryCode = "country-code"

// FieldTypeSubdivisionCode is the CXF subdivision code field type.
const FieldTypeSubdivisionCode = "subdivision-code"

// FieldTypeYearMonth is the CXF year-month field type.
const FieldTypeYearMonth = "year-month"

// FieldTypeBoolean is the CXF boolean field type.
const FieldTypeBoolean = "boolean"

// FieldTypeWiFiNetworkSecurityType is the CXF Wi-Fi security field type.
const FieldTypeWiFiNetworkSecurityType = "wifi-network-security-type"

// OTPHashAlgorithmSHA1 is the SHA-1 algorithm used by TOTP credentials.
const OTPHashAlgorithmSHA1 = "sha1"

// OTPHashAlgorithmSHA256 is the SHA-256 algorithm used by TOTP credentials.
const OTPHashAlgorithmSHA256 = "sha256"

// OTPHashAlgorithmSHA512 is the SHA-512 algorithm used by TOTP credentials.
const OTPHashAlgorithmSHA512 = "sha512"

// FIDO2HMACCredentialAlgorithmSHA256 is the supported FIDO2 HMAC algorithm.
const FIDO2HMACCredentialAlgorithmSHA256 = "hmac-sha256"

// WiFiNetworkSecurityTypeUnsecured identifies an unsecured Wi-Fi network.
const WiFiNetworkSecurityTypeUnsecured = "unsecured"

// WiFiNetworkSecurityTypeWPAPersonal identifies a WPA-Personal network.
const WiFiNetworkSecurityTypeWPAPersonal = "wpa-personal"

// WiFiNetworkSecurityTypeWPA2Personal identifies a WPA2-Personal network.
const WiFiNetworkSecurityTypeWPA2Personal = "wpa2-personal"

// WiFiNetworkSecurityTypeWPA3Personal identifies a WPA3-Personal network.
const WiFiNetworkSecurityTypeWPA3Personal = "wpa3-personal"

// WiFiNetworkSecurityTypeWEP identifies a WEP network.
const WiFiNetworkSecurityTypeWEP = "wep"

// CredentialTypeOf returns a credential's type without decoding its contents.
func CredentialTypeOf(raw json.RawMessage) (string, error) {
	return credentialTypeOf(raw, "credential")
}

// credentialTypeOf reads a discriminator and reports errors at the given path.
func credentialTypeOf(raw json.RawMessage, path string) (string, error) {
	fields, err := credentialFields(raw, path, []string{"type"}, nil)
	if err != nil {
		return "", err
	}
	var credentialType string
	if err := json.Unmarshal(fields["type"], &credentialType); err != nil {
		return "", invalid(path+".type", "expected a string")
	}
	return credentialType, nil
}

// ValidateCredential checks a supported credential and accepts unknown types.
func ValidateCredential(data []byte) error {
	return validateCredential(data, "credential")
}

// validateCredentials checks each credential in a list.
func validateCredentials(credentials []json.RawMessage, path string) error {
	for i, raw := range credentials {
		if err := validateCredential(raw, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

// validateCredential decodes a known credential and leaves unknown types raw.
func validateCredential(data []byte, path string) error {
	credentialType, err := credentialTypeOf(data, path)
	if err != nil {
		return err
	}
	switch credentialType {
	case CredentialTypeAddress:
		var credential Address
		err = json.Unmarshal(data, &credential)
	case CredentialTypeAPIKey:
		var credential APIKey
		err = json.Unmarshal(data, &credential)
	case CredentialTypeBasicAuth:
		var credential BasicAuth
		err = json.Unmarshal(data, &credential)
	case CredentialTypeCreditCard:
		var credential CreditCard
		err = json.Unmarshal(data, &credential)
	case CredentialTypeCustomFields:
		var credential CustomFields
		err = json.Unmarshal(data, &credential)
	case CredentialTypeDriversLicense:
		var credential DriversLicense
		err = json.Unmarshal(data, &credential)
	case CredentialTypeFile:
		var credential File
		err = json.Unmarshal(data, &credential)
	case CredentialTypeGeneratedPassword:
		var credential GeneratedPassword
		err = json.Unmarshal(data, &credential)
	case CredentialTypeIdentityDocument:
		var credential IdentityDocument
		err = json.Unmarshal(data, &credential)
	case CredentialTypeItemReference:
		var credential ItemReference
		err = json.Unmarshal(data, &credential)
	case CredentialTypeNote:
		var credential Note
		err = json.Unmarshal(data, &credential)
	case CredentialTypePasskey:
		var credential Passkey
		err = json.Unmarshal(data, &credential)
	case CredentialTypePassport:
		var credential Passport
		err = json.Unmarshal(data, &credential)
	case CredentialTypePersonName:
		var credential PersonName
		err = json.Unmarshal(data, &credential)
	case CredentialTypeSSHKey:
		var credential SSHKey
		err = json.Unmarshal(data, &credential)
	case CredentialTypeTOTP:
		var credential TOTP
		err = json.Unmarshal(data, &credential)
	case CredentialTypeWiFi:
		var credential WiFi
		err = json.Unmarshal(data, &credential)
	default:
		return nil
	}
	if err != nil {
		return prefixValidationError(err, path)
	}
	return nil
}

// decodeCredential checks a credential's discriminator and fields before decoding it.
func decodeCredential(data []byte, expected, path string, required, optional []string, target any) error {
	fields, err := credentialFields(data, path, required, optional)
	if err != nil {
		return err
	}
	var credentialType string
	if err := json.Unmarshal(fields["type"], &credentialType); err != nil {
		return invalid(path+".type", "expected a string")
	}
	if credentialType != expected {
		return invalid(path+".type", "unexpected credential type")
	}
	data, err = json.Marshal(knownFields(fields, required, optional))
	if err != nil {
		return invalid(path, "invalid credential")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return decodingError(err, path, "invalid credential fields")
	}
	return nil
}

package cxf

import "strconv"

// AndroidAppID identifies an Android application.
type AndroidAppID struct {
	// BundleID is the application identifier.
	BundleID string `json:"bundleId"`
	// Certificate is the optional signing certificate fingerprint.
	Certificate *AndroidAppCertificateFingerprint `json:"certificate,omitempty"`
	// Name is the optional display name.
	Name *string `json:"name,omitempty"`
}

// AndroidAppCertificateFingerprint identifies an Android signing certificate.
type AndroidAppCertificateFingerprint struct {
	// Fingerprint is the Base64url-encoded certificate digest.
	Fingerprint string `json:"fingerprint"`
	// HashAlg names the digest algorithm.
	HashAlg string `json:"hashAlg"`
}

// Validate checks an Android application identifier.
func (app *AndroidAppID) Validate() error {
	if app == nil {
		return invalid("androidApp", "must not be nil")
	}
	if err := validateUTF8String("androidApp.bundleId", app.BundleID); err != nil {
		return err
	}
	if app.Name != nil {
		if err := validateUTF8String("androidApp.name", *app.Name); err != nil {
			return err
		}
	}
	if app.Certificate != nil {
		if err := app.Certificate.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalJSON decodes and validates Android application data atomically.
func (app *AndroidAppID) UnmarshalJSON(data []byte) error {
	if app == nil {
		return invalid("androidApp", "must not be nil")
	}
	type plain AndroidAppID
	var decoded plain
	if err := decodeObject(data, "androidApp", []string{"bundleId"}, []string{"certificate", "name"}, &decoded); err != nil {
		return err
	}
	candidate := AndroidAppID(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*app = candidate
	return nil
}

// Validate checks an Android certificate fingerprint.
func (certificate *AndroidAppCertificateFingerprint) Validate() error {
	if certificate == nil {
		return invalid("androidApp.certificate", "must not be nil")
	}
	if err := validateUTF8String("androidApp.certificate.hashAlg", certificate.HashAlg); err != nil {
		return err
	}
	fingerprint, err := decodeBase64URL(certificate.Fingerprint)
	if err != nil {
		return invalid("androidApp.certificate.fingerprint", "invalid base64url value")
	}
	if certificate.HashAlg == "sha256" && len(fingerprint) != 32 || certificate.HashAlg == "sha512" && len(fingerprint) != 64 {
		return invalid("androidApp.certificate.fingerprint", "incorrect hash length")
	}
	return nil
}

// UnmarshalJSON decodes and validates an Android certificate fingerprint atomically.
func (certificate *AndroidAppCertificateFingerprint) UnmarshalJSON(data []byte) error {
	if certificate == nil {
		return invalid("androidApp.certificate", "must not be nil")
	}
	type plain AndroidAppCertificateFingerprint
	var decoded plain
	if err := decodeObject(data, "androidApp.certificate", []string{"fingerprint", "hashAlg"}, nil, &decoded); err != nil {
		return err
	}
	candidate := AndroidAppCertificateFingerprint(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*certificate = candidate
	return nil
}

// validateAndroidApps checks application records in a credential scope.
func validateAndroidApps(apps []AndroidAppID, path string) error {
	for i := range apps {
		if err := apps[i].Validate(); err != nil {
			return prefixValidationError(err, path+"["+strconv.Itoa(i)+"]")
		}
	}
	return nil
}

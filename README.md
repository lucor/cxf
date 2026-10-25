# cxf

[![Go Reference](https://pkg.go.dev/badge/go.lucor.dev/cxf.svg)](https://pkg.go.dev/go.lucor.dev/cxf)
[![Dependencies](https://badges.api.sourcespotter.com/deps?package=go.lucor.dev%2Fcxf)](https://sourcespotter.com/deps/?package=go.lucor.dev%2Fcxf)
[![CXF 1.0 Spec](https://img.shields.io/badge/CXF-1.0%20Spec-4C7CAC)](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html)

`cxf` reads, writes, and validates the [FIDO Credential Exchange Format](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html),
a JSON format for moving credentials between password managers. It implements
CXF 1.0 with the March 2026 errata, requires Go 1.26, and uses only the standard
library at runtime.

## Install

```sh
go get go.lucor.dev/cxf
```

## Usage

Decode a document and write it back:

```go
document, err := cxf.Decode(reader)
if err != nil {
    return err
}
return cxf.Encode(writer, document)
```

Each item groups related credentials, such as a login and its TOTP secret.
`Item.Credentials` holds `json.RawMessage` values. Decode a known credential
with `encoding/json`, or keep its raw JSON when you do not need to interpret it.
Extensions are also kept as raw JSON.

## Credential types

| CXF type | Go type | Contents |
| --- | --- | --- |
| `address` | `Address` | Postal address and phone number |
| `api-key` | `APIKey` | API key, username, URL, and validity dates |
| `basic-auth` | `BasicAuth` | Username and password |
| `credit-card` | `CreditCard` | Payment card details |
| `custom-fields` | `CustomFields` | A group of editable fields |
| `drivers-license` | `DriversLicense` | Driver's license details |
| `file` | `File` | Metadata and hash for a separately transferred file |
| `generated-password` | `GeneratedPassword` | A password generated independently of a login |
| `identity-document` | `IdentityDocument` | Identity document or identification number |
| `item-reference` | `ItemReference` | A link to another item |
| `note` | `Note` | Text content |
| `passkey` | `Passkey` | WebAuthn credential and private key |
| `passport` | `Passport` | Passport details |
| `person-name` | `PersonName` | Individual parts of a person's name |
| `ssh-key` | `SSHKey` | SSH private key and metadata |
| `totp` | `TOTP` | OTP secret, algorithm, period, and digits |
| `wifi` | `WiFi` | Network name, security type, and passphrase |

## Validation

`Decode` validates one complete document and rejects trailing data. `Encode`
validates before writing. Direct `json.Unmarshal` into modeled CXF types also
validates them atomically. Unknown credential types remain available as raw JSON
so applications can preserve data they do not support.

CXF documents contain credentials in plaintext. Applications are responsible
for protecting them during storage and transfer.

## License

MIT. See [LICENSE](LICENSE).

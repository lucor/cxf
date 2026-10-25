# Development Guide

This is a standalone Go library for CXF document handling.

- Keep the public API independent of applications, storage engines, and CLIs.
- Use the [CXF 1.0 Proposed Standard with March 2026 errata](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html)
  as the schema reference. Do not copy implementation code from incompatible licenses.
- Keep implementations minimal and solve current requirements. Use plain structs
  and standard JSON encoding; add abstractions only for demonstrated needs.
- Add short Go doc comments. Use plain English and explain non-obvious choices.
- Retain credential bodies and extensions as raw JSON until their types are
  supported. Unknown members of modeled structs are ignored by standard decoding.
  Do not imply full schema conformance from basic structural validation.
- Do not add lint suppression directives. Explain diagnostics and resolve their
  cause when a change is appropriate.
- Use synthetic fixtures only. Do not add actual credentials, exported vaults,
  private keys, or diagnostics that expose credential values.
- Cover malformed input and supported round-trip behavior when
  changing serialization. Use only the standard library at runtime.

The module supports Go 1.26 and Go 1.27. `mise.toml` pins the development toolchain.

Run these tasks from the repository root:

- `mise run setup` downloads pinned development tools.
- `mise run fmt` formats source files.
- `mise run test` runs automated tests and fuzz seeds.
- `mise run test-race` runs tests with the race detector.
- `mise run lint` runs Go vet and Staticcheck.
- `mise run vuln` checks known vulnerabilities.
- `mise run check` runs the normal validation gate.

For a longer fuzz run, use
`mise exec -- go test -run=^$ -fuzz=FuzzDecodeEncode -fuzztime=10s`.

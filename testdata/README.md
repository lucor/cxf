# CXF example fixtures

`appendix-a.json` contains the Appendix A JSON supplied by the project owner,
preserved verbatim. Its source is the [CXF 1.0 Proposed Standard with March 2026
errata, Appendix A](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html#appendix-a-example-payload).
The source document identifies FIDO Alliance as its copyright holder.

The credential values and private keys are published example data. The test
reads them directly without replacing values or generating substitute keys.
This fixture is an informative specification example, not a formal conformance
test suite, and is not project-authored material under the module's MIT license.

The supplied example contains 15 of the 17 credential types defined by CXF 1.0.
It omits `custom-fields` and `item-reference`; synthetic cases in
`credential_test.go` cover those types alongside the others.

## Compatibility regression cases

`compatibility_test.go` keeps the synthetic cases found while reviewing the
implementation against the same CXF revision. Each case records its source
section and whether the input should be accepted.

- Sections 2.1.1 and 3.1.1: unknown members, field types, algorithms, and minor versions.
- Section 2.1.2: empty required arrays, omitted optional arrays, and invalid null members.
- Sections 3.1 and 3.2: required members, numeric limits, scopes, and Android certificate records.
- Sections 3.3 and 3.4: credential structure, linked items, editable values, and encodings.
- Section 3.5: extension names, sharing placement, and accessor structure.

Valid cases must survive encoding and decoding. Invalid credentials must fail
both direct validation and document encoding without writing any bytes. These
regression cases and the supplied example do not establish that an application's
import, export, or credential-use behavior meets every CXF requirement.

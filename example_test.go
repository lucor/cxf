package cxf_test

import (
	"bytes"
	"fmt"

	"go.lucor.dev/cxf"
)

// ExampleEncode encodes and decodes a document.
func ExampleEncode() {
	document := &cxf.Header{
		Version:             cxf.Version{Major: 1, Minor: 0},
		ExporterRPID:        "example.com",
		ExporterDisplayName: "Example manager",
		Accounts:            []cxf.Account{},
	}
	var output bytes.Buffer
	if err := cxf.Encode(&output, document); err != nil {
		panic(err)
	}
	decoded, err := cxf.Decode(&output)
	if err != nil {
		panic(err)
	}
	fmt.Println(decoded.Version.Major, len(decoded.Accounts))
	// Output: 1 0
}

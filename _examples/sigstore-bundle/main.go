package main

import (
	"fmt"
	"os"

	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/options"
)

// When working with bundles, sigstore-go can only verify in-toto
// attestations. Any other data format can be signed but verification
// is hardcoded to fail.
// See https://github.com/sigstore/sigstore-go/issues/509

// Sample in-toto attestation to sign and verify
var attData = `{
  "predicateType": "https://example.com/my-predicate/v1",
  "predicate": { "something": "custom" },
  "type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    { "name": "MY-POLICY" }
  ]
}
`

func main() {
	s := signer.NewSigner()

	// Sign a string and wrap it in a bundle
	bundle, err := s.SignBundle(
		//[]byte("This is a test, nothing else. No JSON"),
		[]byte(attData),
		options.WithPayloadType("application/vnd.in-toto+json"),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// Output the bundle to STDOUT
	if err := s.WriteBundle(bundle, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// Now verify the resulting bundle:
	v := signer.NewVerifier()
	v.Options.SkipIdentityCheck = true

	result, err := v.VerifyParsedBundle(bundle)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fmt.Println(result)
}

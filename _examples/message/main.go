package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/options"
)

// Sample data to sign and verify
var data = `
# Random Data

This is just some random data to be signed as a message
`

func main() {
	// ====================================================================
	// PART 1: SIGNING
	s := signer.NewSigner()

	// Sign a string and wrap it in a bundle
	bundle, err := s.SignMessage([]byte(data))
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// Output the bundle to STDOUT
	fmt.Println("SIGNED BUNDLE")
	fmt.Println("=============")
	if err := s.WriteBundle(bundle, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// ====================================================================
	// PART 2: VERIFICATION
	v := signer.NewVerifier()

	result, err := v.VerifyParsedBundle(
		bundle,
		options.WithArtifactData([]byte(data)),
		options.WithSkipIdentityCheck(true),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println()
	fmt.Println("VERIFICATION RESULTS")
	fmt.Println("====================")
	res, err := json.MarshalIndent(result, "", " ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Println(string(res))
}

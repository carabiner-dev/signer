// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Sign an in-toto attestation with an X.509 SVID obtained from the SPIFFE
// Workload API, then verify it against a pinned SPIRE upstream root and
// apply a SPIFFE identity policy via the api/v1 layer.
//
// Demonstrates the SignerSet/VerifierSet OptionsSet plumbing: a CLI
// surface registers --spiffe-* flags, the SPIFFE_ENDPOINT_SOCKET and
// SPIFFE_TRUST_BUNDLE env vars are picked up automatically as
// fallbacks, BuildSigner / BuildCredentialProvider produce the
// configured signer, and BuildVerifier the configured verifier.
//
// To run against the local SPIRE fixture:
//
//	make spire-up   (start the spire server in a container)
//	export SPIFFE_ENDPOINT_SOCKET="unix://$(pwd)/hack/spire/socket/api.sock"
//	export SPIFFE_TRUST_BUNDLE="$(pwd)/hack/spire/bundle.pem"
//	go run ./_examples/spiffe
//	make spire-down (tear down the spire container)
//
// The fixture registers a workload entry for the calling user's UID
// under the SPIFFE ID spiffe://test.local/workload — the policy check
// below pins that identity.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/signer"
	api "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/options"
)

// Sample in-toto statement to sign.
const attData = `{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
		"name": "example",
		"digest": { "sha256": "0000000000000000000000000000000000000000000000000000000000000000" }
	}
  ],
  "predicateType": "https://example.com/my-predicate/v1",
  "predicate": {
    "something": "cool"
  }
}
`

func main() {
	signSet := options.DefaultSignerSet()
	signSet.Backend = string(options.BackendSpiffe)

	verifySet := options.DefaultVerifierSet()

	cmd := &cobra.Command{
		Use:   "spiffe-example",
		Short: "Sign and verify an in-toto attestation against a SPIRE fixture",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(signSet, verifySet)
		},
	}
	signSet.AddFlags(cmd)
	verifySet.AddFlags(cmd)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(signSet *options.SignerSet, verifySet *options.VerifierSet) error {
	if err := signSet.Validate(); err != nil {
		return fmt.Errorf("sign options: %w", err)
	}
	if err := verifySet.Validate(); err != nil {
		return fmt.Errorf("verify options: %w", err)
	}

	// ====================================================================
	// PART 1: SIGNING
	s, err := signer.NewSignerFromSet(signSet)
	if err != nil {
		return fmt.Errorf("building signer: %w", err)
	}
	defer func() { _ = s.Close() }()

	bundle, err := s.SignStatementBundle([]byte(attData))
	if err != nil {
		return fmt.Errorf("signing statement: %w", err)
	}

	fmt.Println("SIGNED BUNDLE")
	fmt.Println("=============")
	if err := s.WriteBundle(bundle, os.Stdout); err != nil {
		return fmt.Errorf("writing bundle: %w", err)
	}

	// ====================================================================
	// PART 2: VERIFICATION against the pinned SPIRE upstream root
	v, err := signer.NewVerifierFromSet(verifySet)
	if err != nil {
		return fmt.Errorf("building verifier: %w", err)
	}

	result, err := v.VerifyParsedBundle(bundle)
	if err != nil {
		return fmt.Errorf("verifying bundle: %w", err)
	}

	fmt.Println()
	fmt.Println()
	fmt.Println("VERIFICATION RESULTS")
	fmt.Println("====================")
	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling result: %w", err)
	}
	fmt.Println(string(out))

	// ====================================================================
	// PART 3: POLICY MATCH via api/v1
	// The verifier reports what was signed; a policy says what's allowed.
	// Here we pin the exact SPIFFE ID the hack/spire fixture registers.
	sv := api.SignatureVerificationFromResult(result)
	policy := &api.Identity{
		Spiffe: &api.IdentitySpiffe{
			Svid: "spiffe://test.local/workload",
		},
	}

	fmt.Println()
	fmt.Println("POLICY MATCH")
	fmt.Println("============")
	if sv.MatchesIdentity(policy) {
		fmt.Println("OK — signer matches policy spiffe://test.local/workload")
		return nil
	}
	return fmt.Errorf("REJECTED — signer does not match the pinned policy identity")
}

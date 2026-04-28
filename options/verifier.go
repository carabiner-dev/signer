// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/sigstore"
)

type VerifierOptFunc func(*Verifier)

// KeyVerification options
type KeyVerification struct {
	// PubKeys are the public-key providers used as a fallback when the
	// per-call keys argument to VerifyParsedDSSE is empty. Lets a CLI
	// wire its --key flag into the verifier once and call VerifyDSSE
	// without re-passing the keys.
	PubKeys []key.PublicKeyProvider
}

// Verifier options
type Verifier struct {
	// The verifier options embed a set of verification options. These are
	// treated as defaults when calling the sigstore/dsse verifiers
	Verification

	// SigstoreRootsPath is the path to a sigstore roots file
	SigstoreRootsPath string

	// SigstoreRootsData holds raw json with data about the configured roots
	SigstoreRootsData []byte
}

// DefaultVerifier default options to configure the verifier
var DefaultVerifier = Verifier{
	Verification:      DefaultVerification,
	SigstoreRootsData: sigstore.DefaultRoots, // Embedded data from the file
}

// WithSigstoreRootsPath sets the path to the sigstore roots configuration file
func WithSigstoreRootsPath(path string) VerifierOptFunc {
	return func(v *Verifier) {
		v.SigstoreRootsPath = path
	}
}

// WithSigstoreRootsData sets the sigstore roots data from raw json
func WithSigstoreRoots(raw []byte) VerifierOptFunc {
	return func(v *Verifier) {
		v.SigstoreRootsData = raw
	}
}

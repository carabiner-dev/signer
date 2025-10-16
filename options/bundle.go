// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

// SigstoreVerification configures how we verify signatures using a particular
// instance.
type SigstoreVerification struct {
	// ExpectedIssuer and ExpectedSan define the issuer and SAN to look for in
	// the fulcio cert. For a broader matching behavior, choose the *Regex
	// alternatives.
	//
	// Verification will fail if thse are not set. To skip the identity check
	// set SkipIdentityCheck to true.
	ExpectedIssuer      string
	ExpectedIssuerRegex string
	ExpectedSan         string
	ExpectedSanRegex    string

	// SkipIdentityCheck makes the verifier skip the identity check. This
	// will ignore any setting in ExpectedIssuer ExpectedIssuerRegex
	// ExpectedSan or ExpectedSanRegex
	SkipIdentityCheck bool

	// Artifact digest to check when verifier in addition to the signature
	ArtifactDigestAlgo string
	ArtifactDigest     string
}

type BundleVerifier struct {
	// RootsFile path to roots file
	RootsFile string
}

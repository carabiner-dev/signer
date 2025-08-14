// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import "github.com/carabiner-dev/signer/internal/tuf"

type Verifier struct {
	tuf.TufOptions
	// Artifact digest to check when verifier in addition to the signature
	ArtifactDigestAlgo string
	ArtifactDigest     string

	// ExpectedIssuer and ExpectedSan define the issuer and SAN to look for in
	// the fulcio cert. For a borader matching behavior, choose the *Regex
	// alternatives.
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

	RequireCTlog     bool
	RequireTimestamp bool
	RequireTlog      bool
}

var DefaultVerifier = Verifier{
	TufOptions: tuf.TufOptions{
		TufRootURL:  tuf.SigstorePublicGoodBaseURL,
		TufRootPath: "",
		Fetcher:     tuf.Defaultfetcher(),
	},
	ArtifactDigestAlgo: "sha256",
	RequireCTlog:       true,
	RequireTimestamp:   true,
	RequireTlog:        true,
}

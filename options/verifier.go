// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import "github.com/carabiner-dev/signer/internal/tuf"

type Verifier struct {
	tuf.TufOptions
	ArtifactDigest      string
	ArtifactDigestAlgo  string
	ExpectedIssuer      string
	ExpectedIssuerRegex string
	ExpectedSan         string
	ExpectedSanRegex    string
	SkipIdentityCheck   bool
	RequireCTlog        bool
	RequireTimestamp    bool
	RequireTlog         bool
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

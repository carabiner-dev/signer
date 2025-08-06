// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tuf

import (
	"fmt"
	"runtime"

	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"sigs.k8s.io/release-utils/version"
)

const SigstorePublicGoodBaseURL = "https://tuf-repo-cdn.sigstore.dev"

// TufOptions captures the TUF options handled by bind
type TufOptions struct {
	Fetcher     fetcher.Fetcher
	TufRootPath string
	TufRootURL  string
}

// GetClient returns a TUF client configured with the options
func GetClient(opts *TufOptions) (*tuf.Client, error) {
	// Build the TUF client:
	tufOpts := tuf.DefaultOptions()
	tufOpts.RepositoryBaseURL = SigstorePublicGoodBaseURL
	tufOpts.Fetcher = Defaultfetcher()

	if opts.Fetcher != nil {
		tufOpts.Fetcher = opts.Fetcher
	}

	if opts.TufRootURL != "" {
		tufOpts.RepositoryBaseURL = opts.TufRootURL
	}

	client, err := tuf.New(tufOpts)
	if err != nil {
		return nil, fmt.Errorf("creating TUF client: %w", err)
	}
	return client, nil
}

// GetRoot fetches the trusted root from the configured URL or from
// the sigstore public instance.
func GetRoot(opts *TufOptions) ([]byte, error) {
	client, err := GetClient(opts)
	if err != nil {
		return nil, fmt.Errorf("creating TUF client: %w", err)
	}

	data, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("fetching TUF root data: %w", err)
	}

	return data, nil
}

// Defaultfetcher returns a default TUF fetcher configured with the bind UA
func Defaultfetcher() fetcher.Fetcher {
	f := fetcher.NewDefaultFetcher()
	agentString := fmt.Sprintf(
		"Carabiner Signer/%s (%s; %s; Carabiner Systems; https://github.com/carabiner-dev/signer)",
		version.GetVersionInfo().GitVersion,
		runtime.GOOS, runtime.GOARCH,
	)
	f.SetHTTPUserAgent(agentString)
	return f
}

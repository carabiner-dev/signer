// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tuf

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"sigs.k8s.io/release-utils/version"
)

// TUF metadata initialization is brittle on transient filesystem
// contention: on Windows the atomic rename of the freshly-created
// temp metadata file fails when antivirus / indexer briefly locks it
// ("Access is denied"), and on slow disks any platform can hit a
// short window where the rename or initial fetch fails. The
// failure mode is recoverable on retry, so we bound a few attempts
// here rather than blow up the verifier on a sub-second I/O blip.
const (
	tufInitMaxAttempts  = 3
	tufInitInitialDelay = 250 * time.Millisecond
)

// TufOptions captures the TUF options handled by bind
type TufOptions struct {
	Fetcher     fetcher.Fetcher
	TufRootPath string `json:"tuf-root-path"`
	TufRootURL  string `json:"tuf-root-url"`
	RootData    []byte `json:"root-data"`
}

// GetClient returns a TUF client configured with the options. The
// underlying tuf.New call is retried with exponential backoff on
// transient errors (see the tufInit* constants for rationale); the
// last error is returned after exhausting attempts so legitimate
// configuration problems still surface.
func GetClient(opts *TufOptions) (*tuf.Client, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fall back to using a TUF repository in the temp location
		home = os.TempDir()
	}

	tufOpts := &tuf.Options{
		CacheValidity:             0,
		ForceCache:                false,
		Root:                      opts.RootData,
		CachePath:                 filepath.Join(home, ".sigstore", "root"),
		RepositoryBaseURL:         opts.TufRootURL,
		DisableLocalCache:         false,
		DisableConsistentSnapshot: false,
		Fetcher:                   Defaultfetcher(),
	}

	var (
		client  *tuf.Client
		lastErr error
		delay   = tufInitInitialDelay
	)
	for attempt := 1; attempt <= tufInitMaxAttempts; attempt++ {
		client, lastErr = tuf.New(tufOpts)
		if lastErr == nil {
			return client, nil
		}
		if attempt < tufInitMaxAttempts {
			time.Sleep(delay)
			delay *= 2
		}
	}
	return nil, fmt.Errorf("creating TUF client (after %d attempts): %w", tufInitMaxAttempts, lastErr)
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
		version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH,
	)
	f.SetHTTPUserAgent(agentString)
	return f
}

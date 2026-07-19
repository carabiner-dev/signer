// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/root"
)

//go:embed sigstore-roots.json
var DefaultRoots []byte

//go:embed roots
var rootFiles embed.FS

// readEmbeddedRoot reads the embedded TUF bootstrap root data for an ID
func readEmbeddedRoot(id string) ([]byte, error) {
	return rootFiles.ReadFile(fmt.Sprintf("roots/%s.json", id))
}

// readEmbeddedTrustedRoot reads the embedded sigstore trusted_root.json for an
// ID. Unlike readEmbeddedRoot (which returns the TUF bootstrap root), this
// returns the resolved trust material consumed by TrustedRoot. Note that some
// instances may not ship their embedded trusted root
func readEmbeddedTrustedRoot(id string) ([]byte, error) {
	return rootFiles.ReadFile(fmt.Sprintf("roots/%s.trusted_root.json", id))
}

type CaCertMatcher func()

type SigstoreRoots struct {
	Roots []InstanceConfig `json:"roots"`
}

type InstanceConfig struct {
	IssuerOrg        string          `json:"issuer-org"`
	SigningConfigRaw json.RawMessage `json:"signing-config"`
	Instance
}

// ParseRootsFile parses a sigstore roots file
func ParseRootsFile(path string) (*SigstoreRoots, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening roots file: %w", err)
	}
	return ParseRoots(data)
}

// ParseRoots parses a roots file
func ParseRoots(data []byte) (*SigstoreRoots, error) {
	roots := &SigstoreRoots{}

	//nolint:musttag
	if err := json.Unmarshal(data, roots); err != nil {
		return nil, fmt.Errorf("unmarshaling sigstore roots: %w", err)
	}

	for i := range roots.Roots {
		if len(roots.Roots[i].RootData) > 0 {
			continue
		}
		data, err := readEmbeddedRoot(roots.Roots[i].ID)
		if err != nil {
			return nil, fmt.Errorf("reading root data for %q: %w", roots.Roots[i].ID, err)
		}
		roots.Roots[i].RootData = data
	}

	// Parse the official signing config for each root.
	for i := range roots.Roots {
		if len(roots.Roots[i].SigningConfigRaw) == 0 {
			continue
		}

		sc, err := root.NewSigningConfigFromJSON(roots.Roots[i].SigningConfigRaw)
		if err != nil {
			return nil, fmt.Errorf("parsing signing config for %q: %w", roots.Roots[i].ID, err)
		}
		roots.Roots[i].SigningConfig = sc
	}

	return roots, nil
}

// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/carabiner-dev/signer/options"
)

//go:embed roots
var rootFiles embed.FS

// readEmbeddedRoot reads the embedded root data for an ID
func readEmbeddedRoot(id string) ([]byte, error) {
	return rootFiles.ReadFile(fmt.Sprintf("roots/%s.json", id))
}

type CaCertMatcher func()

type SigstoreRoots struct {
	Roots []InstanceConfig `json:"roots"`
}

type InstanceConfig struct {
	ID        string `json:"id"`
	IssuerOrg string `json:"issuer-org"`
	options.Sigstore
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

	return roots, nil
}

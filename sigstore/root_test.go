// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRoots(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		file        string
		expectedLen int
		mustErr     bool
	}{
		{"real", "testdata/roots1.json", 2, false},
		{"err", "testdata/invalid.json", 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(tt.file)
			require.NoError(t, err)
			roots, err := ParseRoots(data)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, roots.Roots, tt.expectedLen)
		})
	}
}

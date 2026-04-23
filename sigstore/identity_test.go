// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRunOIDCFlowFailsInCI verifies that when no ambient or pre-provided token
// is available and the environment is CI (no TTY, CI env var set),
// runOIDCFlow returns a descriptive error instead of hanging on the device flow.
func TestRunOIDCFlowFailsInCI(t *testing.T) {
	id := &Identity{Instance: &Instance{}}

	t.Setenv("CI", "true")

	_, err := id.runOIDCFlow()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no OIDC ambient credentials found in CI environment")
}

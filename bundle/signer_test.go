// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/options"
)

func TestGetOidcTokenFailsInCI(t *testing.T) {
	bs := &DefaultSigner{}
	opts := &options.Signer{}

	// Simulate a CI environment with no terminal and no ambient token
	t.Setenv("CI", "true")

	err := bs.GetOidcToken(opts)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no OIDC ambient credentials found in CI environment")
}

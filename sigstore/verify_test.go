// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	signer "github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/options"
)

func TestVerifyBundle(t *testing.T) {
	t.Parallel()
	v := signer.NewVerifier()
	res, err := v.VerifyBundle(
		"testdata/cosign-3.0.5-1.aarch64.rpm.sigstore.json",
		options.WithSkipIdentityCheck(true),
	)
	require.NoError(t, err)
	require.NotNil(t, res)
}

// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConclusionErrors(t *testing.T) {
	t.Parallel()

	cause := errors.New("x509: certificate signed by unknown authority")

	err := VerificationFailedError("chain verification failed", cause)
	require.ErrorIs(t, err, ErrVerificationFailed)
	require.ErrorIs(t, err, cause)
	require.NotErrorIs(t, err, ErrUnverifiable)
	assert.Equal(t, "signature verification failed: chain verification failed: x509: certificate signed by unknown authority", err.Error())

	err = UnverifiableError("no spiffe verifier configured", nil)
	require.ErrorIs(t, err, ErrUnverifiable)
	require.NotErrorIs(t, err, ErrVerificationFailed)
	assert.Equal(t, "signature could not be verified: no spiffe verifier configured", err.Error())
}

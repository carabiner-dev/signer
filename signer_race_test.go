// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// Concurrency regression tests. Run with -race: they exercise the lazy
// persistent-backend construction and the sigstore backend preparation
// from many goroutines at once.

const raceTestStatement = `{
  "predicateType": "https://example.com/my-predicate/v1",
  "predicate": { "something": "custom" },
  "type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    { "name": "MY-POLICY" }
  ]
}
`

func TestSignStatementBundleConcurrent(t *testing.T) {
	t.Parallel()

	h := newTestHarness()
	sut := h.signer(t)

	const workers = 32
	errs := make([]error, workers)

	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = sut.SignStatementBundle([]byte(raceTestStatement))
		}()
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "worker %d", i)
	}

	// Preparation must have run exactly once across all workers.
	require.Equal(t, 1, h.credentials.PrepareCallCount())
	require.Equal(t, 1, h.bundleSigner.BuildBundleOptionsCallCount())
	require.Equal(t, workers, h.bundleSigner.SignBundleCallCount())
}

func TestSignStatementBundleConcurrentPrepareRetry(t *testing.T) {
	t.Parallel()

	h := newTestHarness()
	// The first preparation attempt fails; the error must not be cached,
	// so exactly one worker errors out and the rest retry and succeed.
	h.credentials.PrepareReturnsOnCall(0, errors.New("transient failure"))
	sut := h.signer(t)

	const workers = 16
	errs := make([]error, workers)

	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = sut.SignStatementBundle([]byte(raceTestStatement))
		}()
	}
	wg.Wait()

	failures := 0
	for _, err := range errs {
		if err != nil {
			failures++
		}
	}

	require.Equal(t, 1, failures, "only the worker that hit the transient failure should error")
	require.Equal(t, 2, h.credentials.PrepareCallCount(), "prepare should retry once after the failure")
}

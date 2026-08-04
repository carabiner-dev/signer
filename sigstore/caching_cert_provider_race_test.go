// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/stretchr/testify/require"
)

// countingCertProvider implements sign.CertificateProvider, issuing a fresh
// leaf from the fake CA on every call and counting how often it is hit. With
// expired set, the issued certificates are already outside their validity
// window, forcing the caching wrapper down the refresh path on every call.
type countingCertProvider struct {
	ca      *fakeCA
	expired bool
	calls   atomic.Int32
}

func (c *countingCertProvider) GetCertificate(_ context.Context, kp sign.Keypair, _ *sign.CertificateProviderOptions) ([]byte, error) {
	c.calls.Add(1)

	notBefore, notAfter := time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute)
	if c.expired {
		notBefore, notAfter = time.Now().Add(-time.Hour), time.Now().Add(-time.Minute)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "signer@example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	return x509.CreateCertificate(rand.Reader, tmpl, c.ca.interCert, kp.GetPublicKey(), c.ca.interKey)
}

// TestCachingCertProviderConcurrent hammers the cache with a valid
// certificate: exactly one Fulcio request should be made and every caller
// must observe the same certificate. Run with -race.
func TestCachingCertProviderConcurrent(t *testing.T) {
	t.Parallel()

	inner := &countingCertProvider{ca: newFakeCA(t)}
	cache := &cachingCertProvider{inner: inner}

	kp, err := sign.NewEphemeralKeypair(nil)
	require.NoError(t, err)

	const workers = 32
	certs := make([][]byte, workers)
	errs := make([]error, workers)

	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			certs[i], errs[i] = cache.GetCertificate(context.Background(), kp, nil)
		}()
	}
	wg.Wait()

	for i := range workers {
		require.NoError(t, errs[i], "worker %d", i)
		require.Equal(t, certs[0], certs[i], "worker %d got a different certificate", i)
	}

	require.Equal(t, int32(1), inner.calls.Load(), "concurrent signs should share one certificate request")
}

// TestCachingCertProviderConcurrentRefresh drives the cache with
// certificates that are already expired, so every call takes the refresh
// path under contention. The point is the -race run: refreshes must not
// tear the cached certificate/validity fields.
func TestCachingCertProviderConcurrentRefresh(t *testing.T) {
	t.Parallel()

	inner := &countingCertProvider{ca: newFakeCA(t), expired: true}
	cache := &cachingCertProvider{inner: inner}

	kp, err := sign.NewEphemeralKeypair(nil)
	require.NoError(t, err)

	const workers = 16
	errs := make([]error, workers)

	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = cache.GetCertificate(context.Background(), kp, nil)
		}()
	}
	wg.Wait()

	for i := range workers {
		require.NoError(t, errs[i], "worker %d", i)
	}

	require.Equal(t, int32(workers), inner.calls.Load(), "expired certificates must not be served from the cache")
}

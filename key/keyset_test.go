// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockKey implements the Key interface for testing.
type mockKey struct {
	id        string
	notBefore *time.Time
	notAfter  *time.Time
}

func (m *mockKey) GetType() Type            { return "" }
func (m *mockKey) GetScheme() Scheme        { return "" }
func (m *mockKey) GetHashType() crypto.Hash { return 0 }
func (m *mockKey) GetData() string          { return m.id }
func (m *mockKey) GetKey() crypto.PublicKey { return nil }
func (m *mockKey) GetNotBefore() *time.Time { return m.notBefore }
func (m *mockKey) GetNotAfter() *time.Time  { return m.notAfter }

func timePtr(t time.Time) *time.Time {
	return &t
}

func TestKeySet_GetLatestKey(t *testing.T) {
	t.Parallel()
	now := time.Now()

	for _, tc := range []struct {
		name     string
		keys     KeySet
		expected string // expected key id, empty if nil expected
	}{
		{
			name:     "empty keyset",
			keys:     KeySet{},
			expected: "",
		},
		{
			name: "single valid key with no dates",
			keys: KeySet{
				&mockKey{id: "key1"},
			},
			expected: "key1",
		},
		{
			name: "expired key only",
			keys: KeySet{
				&mockKey{id: "expired", notAfter: timePtr(now.Add(-time.Hour))},
			},
			expected: "",
		},
		{
			name: "future key only",
			keys: KeySet{
				&mockKey{id: "future", notBefore: timePtr(now.Add(time.Hour))},
			},
			expected: "",
		},
		{
			name: "keys with NotBefore - returns latest",
			keys: KeySet{
				&mockKey{id: "older", notBefore: timePtr(now.Add(-2 * time.Hour))},
				&mockKey{id: "newer", notBefore: timePtr(now.Add(-1 * time.Hour))},
			},
			expected: "newer",
		},
		{
			name: "keys with NotAfter only - returns latest expiry",
			keys: KeySet{
				&mockKey{id: "expires-soon", notAfter: timePtr(now.Add(time.Hour))},
				&mockKey{id: "expires-later", notAfter: timePtr(now.Add(2 * time.Hour))},
			},
			expected: "expires-later",
		},
		{
			name: "mixed keys - NotBefore takes priority",
			keys: KeySet{
				&mockKey{id: "no-dates"},
				&mockKey{id: "only-notafter", notAfter: timePtr(now.Add(time.Hour))},
				&mockKey{id: "has-notbefore", notBefore: timePtr(now.Add(-time.Hour))},
			},
			expected: "has-notbefore",
		},
		{
			name: "keys without dates preserve order",
			keys: KeySet{
				&mockKey{id: "first"},
				&mockKey{id: "second"},
				&mockKey{id: "third"},
			},
			expected: "first",
		},
		{
			name: "filter expired and future, return valid",
			keys: KeySet{
				&mockKey{id: "expired", notAfter: timePtr(now.Add(-time.Hour))},
				&mockKey{id: "valid", notBefore: timePtr(now.Add(-time.Hour)), notAfter: timePtr(now.Add(time.Hour))},
				&mockKey{id: "future", notBefore: timePtr(now.Add(time.Hour))},
			},
			expected: "valid",
		},
		{
			name: "all invalid keys",
			keys: KeySet{
				&mockKey{id: "expired", notAfter: timePtr(now.Add(-time.Hour))},
				&mockKey{id: "future", notBefore: timePtr(now.Add(time.Hour))},
			},
			expected: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := tc.keys.GetLatestKey()
			if tc.expected == "" {
				require.Nil(t, result)
			} else {
				require.NotNil(t, result)
				require.Equal(t, tc.expected, result.GetData())
			}
		})
	}
}

func TestKeySet_ActiveKeys(t *testing.T) {
	t.Parallel()
	now := time.Now()

	for _, tc := range []struct {
		name     string
		keys     KeySet
		expected []string
	}{
		{
			name:     "empty keyset",
			keys:     KeySet{},
			expected: nil,
		},
		{
			name: "all active keys",
			keys: KeySet{
				&mockKey{id: "key1"},
				&mockKey{id: "key2"},
			},
			expected: []string{"key1", "key2"},
		},
		{
			name: "filter expired keys",
			keys: KeySet{
				&mockKey{id: "active"},
				&mockKey{id: "expired", notAfter: timePtr(now.Add(-time.Hour))},
			},
			expected: []string{"active"},
		},
		{
			name: "filter future keys",
			keys: KeySet{
				&mockKey{id: "active"},
				&mockKey{id: "future", notBefore: timePtr(now.Add(time.Hour))},
			},
			expected: []string{"active"},
		},
		{
			name: "key with valid date range",
			keys: KeySet{
				&mockKey{id: "valid", notBefore: timePtr(now.Add(-time.Hour)), notAfter: timePtr(now.Add(time.Hour))},
			},
			expected: []string{"valid"},
		},
		{
			name: "all keys invalid",
			keys: KeySet{
				&mockKey{id: "expired", notAfter: timePtr(now.Add(-time.Hour))},
				&mockKey{id: "future", notBefore: timePtr(now.Add(time.Hour))},
			},
			expected: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := tc.keys.ActiveKeys()
			if tc.expected == nil {
				require.Empty(t, result)
			} else {
				require.Len(t, result, len(tc.expected))
				for i, id := range tc.expected {
					require.Equal(t, id, result[i].GetData())
				}
			}
		})
	}
}

func TestKeySet_ActiveOrRecentlyExpiredKeys(t *testing.T) {
	t.Parallel()
	now := time.Now()

	for _, tc := range []struct {
		name      string
		keys      KeySet
		threshold time.Duration
		expected  []string
	}{
		{
			name:      "empty keyset",
			keys:      KeySet{},
			threshold: time.Hour,
			expected:  nil,
		},
		{
			name: "includes recently expired key",
			keys: KeySet{
				&mockKey{id: "active"},
				&mockKey{id: "recently-expired", notAfter: timePtr(now.Add(-30 * time.Minute))},
			},
			threshold: time.Hour,
			expected:  []string{"active", "recently-expired"},
		},
		{
			name: "excludes key expired beyond threshold",
			keys: KeySet{
				&mockKey{id: "active"},
				&mockKey{id: "old-expired", notAfter: timePtr(now.Add(-2 * time.Hour))},
			},
			threshold: time.Hour,
			expected:  []string{"active"},
		},
		{
			name: "zero threshold same as ActiveKeys",
			keys: KeySet{
				&mockKey{id: "active"},
				&mockKey{id: "expired", notAfter: timePtr(now.Add(-time.Minute))},
			},
			threshold: 0,
			expected:  []string{"active"},
		},
		{
			name: "still filters future keys",
			keys: KeySet{
				&mockKey{id: "recently-expired", notAfter: timePtr(now.Add(-30 * time.Minute))},
				&mockKey{id: "future", notBefore: timePtr(now.Add(time.Hour))},
			},
			threshold: time.Hour,
			expected:  []string{"recently-expired"},
		},
		{
			name: "key expired just within threshold",
			keys: KeySet{
				&mockKey{id: "within-threshold", notAfter: timePtr(now.Add(-time.Hour + time.Minute))},
			},
			threshold: time.Hour,
			expected:  []string{"within-threshold"},
		},
		{
			name: "key expired just beyond threshold",
			keys: KeySet{
				&mockKey{id: "beyond-boundary", notAfter: timePtr(now.Add(-time.Hour - time.Second))},
			},
			threshold: time.Hour,
			expected:  nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := tc.keys.ActiveOrRecentlyExpiredKeys(tc.threshold)
			if tc.expected == nil {
				require.Empty(t, result)
			} else {
				require.Len(t, result, len(tc.expected))
				for i, id := range tc.expected {
					require.Equal(t, id, result[i].GetData())
				}
			}
		})
	}
}

func TestKeySet_GetLatestKey_DoesNotModifyOriginal(t *testing.T) {
	t.Parallel()
	now := time.Now()

	keys := KeySet{
		&mockKey{id: "c", notBefore: timePtr(now.Add(-3 * time.Hour))},
		&mockKey{id: "a", notBefore: timePtr(now.Add(-1 * time.Hour))},
		&mockKey{id: "b", notBefore: timePtr(now.Add(-2 * time.Hour))},
	}

	// Store original order
	originalOrder := make([]string, len(keys))
	for i, k := range keys {
		originalOrder[i] = k.GetData()
	}

	// Call GetLatestKey
	result := keys.GetLatestKey()
	require.NotNil(t, result)
	require.Equal(t, "a", result.GetData())

	// Verify original order unchanged
	for i, k := range keys {
		require.Equal(t, originalOrder[i], k.GetData())
	}
}

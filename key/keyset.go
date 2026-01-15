// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"slices"
	"time"
)

type KeySet []Key

// GetLatestKey returns the most "recent" key from the set based on validity
// dates. It filters out expired keys and keys whose NotBefore date hasn't
// passed yet, then orders by NotBefore date (descending), then by NotAfter
// date for keys without NotBefore, and finally by original array order for
// keys with neither date.
func (ks KeySet) GetLatestKey() Key {
	if len(ks) == 0 {
		return nil
	}

	now := time.Now()

	// Create a slice of indices for valid keys to preserve original order info
	type indexedKey struct {
		index int
		key   Key
	}

	var validKeys []indexedKey
	for i, k := range ks {
		// Skip expired keys
		if notAfter := k.GetNotAfter(); notAfter != nil && notAfter.Before(now) {
			continue
		}
		// Skip keys whose NotBefore hasn't passed yet
		if notBefore := k.GetNotBefore(); notBefore != nil && notBefore.After(now) {
			continue
		}
		validKeys = append(validKeys, indexedKey{index: i, key: k})
	}

	if len(validKeys) == 0 {
		return nil
	}

	// Sort the valid keys
	slices.SortStableFunc(validKeys, func(a, b indexedKey) int {
		aNotBefore := a.key.GetNotBefore()
		bNotBefore := b.key.GetNotBefore()
		aNotAfter := a.key.GetNotAfter()
		bNotAfter := b.key.GetNotAfter()

		// Determine categories:
		// 1 = has NotBefore
		// 2 = no NotBefore but has NotAfter
		// 3 = neither
		category := func(notBefore, notAfter *time.Time) int {
			if notBefore != nil {
				return 1
			}
			if notAfter != nil {
				return 2
			}
			return 3
		}

		aCat := category(aNotBefore, aNotAfter)
		bCat := category(bNotBefore, bNotAfter)

		// Different categories: lower category number comes first
		if aCat != bCat {
			return aCat - bCat
		}

		// Same category: sort within category
		switch aCat {
		case 1:
			// Both have NotBefore: sort by NotBefore descending (latest first)
			if aNotBefore.After(*bNotBefore) {
				return -1
			}
			if aNotBefore.Before(*bNotBefore) {
				return 1
			}
			return 0
		case 2:
			// Both have NotAfter but no NotBefore: sort by NotAfter descending
			if aNotAfter.After(*bNotAfter) {
				return -1
			}
			if aNotAfter.Before(*bNotAfter) {
				return 1
			}
			return 0
		default:
			// Neither has dates: preserve original order
			return a.index - b.index
		}
	})

	return validKeys[0].key
}

// ActiveKeys returns all keys whose dates are currently valid or have no dates.
// A key is active if its NotBefore date has passed (or is nil) and its
// NotAfter date has not passed (or is nil).
func (ks KeySet) ActiveKeys() KeySet {
	return ks.activeKeys(time.Now(), 0)
}

// ActiveOrRecentlyExpiredKeys returns all active keys plus keys that expired
// within the given threshold duration.
func (ks KeySet) ActiveOrRecentlyExpiredKeys(threshold time.Duration) KeySet {
	return ks.activeKeys(time.Now(), threshold)
}

// activeKeys is the internal implementation for filtering keys by validity.
func (ks KeySet) activeKeys(now time.Time, expiredThreshold time.Duration) KeySet {
	var result KeySet
	for _, k := range ks {
		// Skip keys whose NotBefore hasn't passed yet
		if notBefore := k.GetNotBefore(); notBefore != nil && notBefore.After(now) {
			continue
		}
		// Skip expired keys (unless within threshold)
		if notAfter := k.GetNotAfter(); notAfter != nil && notAfter.Before(now) {
			if expiredThreshold == 0 || now.Sub(*notAfter) > expiredThreshold {
				continue
			}
		}
		result = append(result, k)
	}
	return result
}

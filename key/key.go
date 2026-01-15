// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"time"
)

// Key is an interface to group both public and private keys
type Key interface {
	GetType() Type
	GetScheme() Scheme
	GetHashType() crypto.Hash
	GetData() string
	GetKey() crypto.PublicKey
	GetNotBefore() *time.Time
	GetNotAfter() *time.Time
}

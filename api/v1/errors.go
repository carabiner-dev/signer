// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"fmt"
)

var (
	// ErrVerificationFailed marks a verification error whose cause is a
	// negative conclusion: the signatures were checked against the
	// available key or trust material and none verified. Verifiers wrap
	// it (see VerificationFailedError) so callers can tell a failed
	// verification apart from a verification that could not run, and
	// translate it into VerificationStatus_FAILED.
	ErrVerificationFailed = errors.New("signature verification failed")

	// ErrUnverifiable marks a verification error whose cause is missing
	// material: the statement is signed, but the verifier has no key,
	// trust root or backend able to check the signatures. It translates
	// into VerificationStatus_UNVERIFIABLE.
	ErrUnverifiable = errors.New("signature could not be verified")
)

// VerificationFailedError builds an error wrapping ErrVerificationFailed
// with a message describing what did not verify and, when non-nil, the
// underlying cause. Both the sentinel and the cause are matchable with
// errors.Is.
func VerificationFailedError(msg string, cause error) error {
	return wrapConclusion(ErrVerificationFailed, msg, cause)
}

// UnverifiableError builds an error wrapping ErrUnverifiable with a
// message describing the material the verifier lacked and, when
// non-nil, the underlying cause.
func UnverifiableError(msg string, cause error) error {
	return wrapConclusion(ErrUnverifiable, msg, cause)
}

func wrapConclusion(sentinel error, msg string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", sentinel, msg)
	}
	return fmt.Errorf("%w: %s: %w", sentinel, msg, cause)
}

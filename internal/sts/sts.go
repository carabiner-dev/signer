// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sts

import (
	"context"

	"github.com/sigstore/sigstore/pkg/oauthflow"

	"github.com/carabiner-dev/signer/internal/sts/providers/github"
	"github.com/carabiner-dev/signer/internal/sts/providers/gitlab"
)

// Ensure the provider implement
var (
	_ Provider = &github.Actions{}
	_ Provider = &gitlab.CI{}
)

var DefaultProviders = map[string]Provider{
	"gitlab": &gitlab.CI{},
	"actions": &github.Actions{},
}

type Provider interface {
	Provide(context.Context, string) (*oauthflow.OIDCIDToken, error)
}

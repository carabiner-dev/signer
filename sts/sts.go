// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sts

import (
	"context"
	"sync"

	"github.com/sigstore/sigstore/pkg/oauthflow"

	"github.com/carabiner-dev/signer/sts/providers/gcp"
	"github.com/carabiner-dev/signer/sts/providers/github"
	"github.com/carabiner-dev/signer/sts/providers/gitlab"
)

// Ensure the provider implement
var (
	_ Provider = &github.Actions{}
	_ Provider = &gitlab.CI{}
	_ Provider = &gcp.Metadata{}
	_ Provider = &gcp.Provider{}
)

// These are the default STS providers, the signer project has additional
// providers in https://github.com/carabiner-dev/signer-extras which have a
// heavier dependency footprint. gcp mints a service-account identity token
// from $GOOGLE_APPLICATION_CREDENTIALS or the Google Cloud metadata server
// and, like the others, reports no token when its environment is absent.
// Build it with gcp.New to pin a service account key explicitly.
var DefaultProviders = map[string]Provider{
	"gitlab":  &gitlab.CI{},
	"actions": &github.Actions{},
	"gcp":     &gcp.Provider{},
}

var mtx sync.Mutex

// RegisterProvider registers a new provider
func RegisterProvider(key string, p Provider) {
	mtx.Lock()
	DefaultProviders[key] = p
	mtx.Unlock()
}

// RegisterProvider registers a new provider
func UnregisterProvider(key string, p Provider) {
	mtx.Lock()
	delete(DefaultProviders, key)
	mtx.Unlock()
}

type Provider interface {
	Provide(context.Context, string) (*oauthflow.OIDCIDToken, error)
}

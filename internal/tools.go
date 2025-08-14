// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build tools

// This file forces the import of modules used for build scripts and tests
// not directly used by the codebase.

package internal

import (
	_ "github.com/maxbrunsfeld/counterfeiter/v6"
)

# SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
# SPDX-License-Identifier: Apache-2.0

BOLD :=  \033[1m
CYAN :=  \033[36m
GREEN := \033[32m
WHITE := \033[37m
RESET := \033[0m

.PHONY: help
help:
	@printf "${BOLD}${WHITE}Carabiner Signer Makefile Help\n=================================${RESET}\n"
	@grep -Eh '^[a-zA-Z_-]+:.*?## .*$$' ${MAKEFILE_LIST} | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "${BOLD}${CYAN}%-25s${RESET}%s\n", $$1, $$2}'

.PHONY: fakes
fakes: ## Rebuild the implementation fakes
	go generate ./...

.PHONY: proto
proto: ## Rebuild the code from the protobuf definitions
	hack/generate-protos.sh

.PHONY: spire-up
spire-up: ## Start a local SPIRE server+agent fixture for e2e tests
	hack/spire/up.sh

.PHONY: spire-down
spire-down: ## Tear down the local SPIRE fixture
	hack/spire/down.sh

.PHONY: spire-logs
spire-logs: ## Follow logs from the local SPIRE server+agent
	cd hack/spire && docker compose logs -f

.PHONY: spiffe-tests
spiffe-tests: ## Run the SPIFFE end-to-end tests against the local fixture (spire-up first)
	SPIFFE_ENDPOINT_SOCKET="unix://$(CURDIR)/hack/spire/socket/api.sock" \
	SPIFFE_TRUST_BUNDLE="$(CURDIR)/hack/spire/bundle.pem" \
	go test -tags=e2e -v ./spiffe/...

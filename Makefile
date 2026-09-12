SHELL := bash
.DEFAULT_GOAL := help

GO      ?= go
FUZZTIME ?= 30s

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Compile everything
	$(GO) build ./...

.PHONY: test
test: ## Run unit tests with the race detector
	$(GO) test -race -count=1 ./...

.PHONY: cover
cover: ## Run tests and report coverage
	$(GO) test -race -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: fuzz
fuzz: ## Short fuzzing pass over parsing and verification
	@for pkg in $$($(GO) list ./...); do \
		for target in $$($(GO) test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
			echo "fuzzing $$target in $$pkg"; \
			$(GO) test -run '^$$' -fuzz "^$$target$$" -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

.PHONY: lint
lint: ## Run golangci-lint
	@command -v golangci-lint >/dev/null 2>&1 \
		|| { echo "golangci-lint not found: https://golangci-lint.run/welcome/install/"; exit 127; }
	golangci-lint run

.PHONY: license-check
license-check: ## Fail on dependency licenses outside the CNCF allowlist
	./hack/check-licenses.sh

.PHONY: translations
translations: ## Re-stamp translations as current with their English source
	./hack/translations.sh update

.PHONY: translations-check
translations-check: ## Report translations whose English source has changed
	./hack/translations.sh check

.PHONY: markdown
markdown: ## Lint markdown
	npx --yes markdownlint-cli2 "**/*.md"

.PHONY: tidy
tidy: ## Tidy and verify module dependencies
	$(GO) mod tidy
	$(GO) mod verify
	@# porcelain rather than 'git diff', so this works before go.sum exists
	@# (a module with no dependencies has none) and still catches tidy
	@# creating one for the first time.
	@changed="$$(git status --porcelain -- go.mod go.sum)"; \
	if [ -n "$$changed" ]; then \
		echo "go.mod or go.sum changed; commit the result of 'make tidy':"; \
		echo "$$changed"; \
		exit 1; \
	fi

.PHONY: verify
verify: build test lint license-check markdown ## Everything CI runs, in CI's order
	@echo "verify: ok"

.PHONY: clean
clean: ## Remove build and coverage artifacts
	rm -f coverage.out
	$(GO) clean -cache -testcache

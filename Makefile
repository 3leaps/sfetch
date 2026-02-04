-include buildconfig.mk

# Read version from VERSION file, fallback to dev
VERSION ?= $(shell cat VERSION 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
NAME ?= sfetch
MAIN ?= .

# LDFLAGS for version injection
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)

# Defaults
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
EXT :=
ifeq ($(GOOS),windows)
EXT := .exe
endif

INSTALL_PREFIX ?= $(HOME)
INSTALL_BINDIR ?= $(INSTALL_PREFIX)/.local/bin
ifeq ($(GOOS),windows)
INSTALL_PREFIX ?= $(USERPROFILE)
INSTALL_BINDIR ?= $(INSTALL_PREFIX)/bin
endif
INSTALL_TARGET ?= $(INSTALL_BINDIR)/$(NAME)$(EXT)
BUILD_ARTIFACT := bin/$(NAME)_$(GOOS)_$(GOARCH)$(EXT)
DIST_RELEASE := dist/release
RELEASE_TAG ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo v$(VERSION))
PUBLIC_KEY_NAME ?= sfetch-release-signing-key.asc
SFETCH_MINISIGN_KEY ?=
SFETCH_MINISIGN_PUB ?=
SFETCH_PGP_KEY_ID ?=
SFETCH_GPG_HOMEDIR ?=
MINISIGN_PUB_NAME ?= sfetch-minisign.pub

# Tool installation directory (repo-local)
BIN_DIR := $(CURDIR)/bin

# Pinned tool versions (minimums; existing installs are respected)
SFETCH_VERSION := v0.3.4
GONEAT_VERSION ?= v0.5.1

# Tool paths (prefer repo-local, fall back to PATH)
SFETCH = $(shell [ -x "$(BIN_DIR)/sfetch" ] && echo "$(BIN_DIR)/sfetch" || command -v sfetch 2>/dev/null)
GONEAT = $(shell [ -x "$(BIN_DIR)/goneat" ] && echo "$(BIN_DIR)/goneat" || command -v goneat 2>/dev/null)

CORPUS_DEST ?= test-corpus

.PHONY: all help build test clean install fmt lint assess tools bootstrap bootstrap-force
.PHONY: precommit prepush version corpus corpus-all corpus-dryrun corpus-validate
.PHONY: release release-download release-checksums release-verify-checksums release-sign
.PHONY: release-notes release-upload verify-release-key verify-minisign-pubkey release-export-minisign-key
.PHONY: release-clean bootstrap-script build-all gosec gosec-high
.PHONY: version-check version-set version-patch version-minor version-major

all: build

help: ## Show this help
	@echo "sfetch - secure, verifying binary fetcher for GitHub releases"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Current version: $(VERSION)"

# -----------------------------------------------------------------------------
# Bootstrap - Trust Anchor Chain
# -----------------------------------------------------------------------------
#
# Trust chain: curl -> sfetch (self-bootstrap) -> goneat
#
# sfetch bootstraps itself via curl, then uses itself to install goneat.
# This demonstrates sfetch eating its own dogfood.

bootstrap: ## Install development tools via trust chain
	@echo "Bootstrapping sfetch development environment..."
	@echo ""
	@# Step 0: Verify curl is available (required trust anchor)
	@if ! command -v curl >/dev/null 2>&1; then \
		echo "[!!] curl not found (required for bootstrap)"; \
		echo ""; \
		echo "Install curl for your platform:"; \
		echo "  macOS:  brew install curl"; \
		echo "  Ubuntu: sudo apt install curl"; \
		echo "  Fedora: sudo dnf install curl"; \
		exit 1; \
	fi
	@echo "[ok] curl found"
	@echo ""
	@# Step 1: Install sfetch via curl (self-bootstrap trust anchor)
	@mkdir -p "$(BIN_DIR)"
	@if [ ! -x "$(BIN_DIR)/sfetch" ] && ! command -v sfetch >/dev/null 2>&1; then \
		echo "[..] Installing sfetch $(SFETCH_VERSION) (self-bootstrap)..."; \
		curl -fsSL https://github.com/3leaps/sfetch/releases/download/$(SFETCH_VERSION)/install-sfetch.sh | bash -s -- --dest "$(BIN_DIR)"; \
	else \
		echo "[ok] sfetch already installed"; \
	fi
	@# Verify sfetch
	@SFETCH_BIN=""; \
	if [ -x "$(BIN_DIR)/sfetch" ]; then SFETCH_BIN="$(BIN_DIR)/sfetch"; \
	elif command -v sfetch >/dev/null 2>&1; then SFETCH_BIN="$$(command -v sfetch)"; fi; \
	if [ -z "$$SFETCH_BIN" ]; then echo "[!!] sfetch installation failed"; exit 1; fi; \
	echo "[ok] sfetch: $$SFETCH_BIN"
	@echo ""
	@# Step 2: Install goneat via sfetch (dogfooding!)
	@SFETCH_BIN=""; \
	if [ -x "$(BIN_DIR)/sfetch" ]; then SFETCH_BIN="$(BIN_DIR)/sfetch"; \
	elif command -v sfetch >/dev/null 2>&1; then SFETCH_BIN="$$(command -v sfetch)"; fi; \
	if [ ! -x "$(BIN_DIR)/goneat" ] && ! command -v goneat >/dev/null 2>&1; then \
		echo "[..] Installing goneat $(GONEAT_VERSION) via sfetch..."; \
		$$SFETCH_BIN --repo fulmenhq/goneat --tag $(GONEAT_VERSION) --dest-dir "$(BIN_DIR)"; \
	else \
		echo "[ok] goneat already installed"; \
	fi
	@# Verify goneat
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -z "$$GONEAT_BIN" ]; then echo "[!!] goneat installation failed"; exit 1; fi; \
	echo "[ok] goneat: $$($$GONEAT_BIN version 2>&1 | head -n1)"
	@echo ""
	@# Step 3: Install foundation tools via goneat
	@echo "[..] Installing foundation tools via goneat..."
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	$$GONEAT_BIN doctor tools --scope foundation --install --yes 2>/dev/null || \
		echo "[!!] goneat doctor tools failed, some tools may need manual installation"
	@echo ""
	@echo "[ok] Bootstrap complete"
	@echo ""
	@echo "Repo-local tools installed to $(BIN_DIR)"
	@echo "Run 'make build' to build sfetch"

bootstrap-force: ## Force reinstall all tools
	@rm -f "$(BIN_DIR)/sfetch" "$(BIN_DIR)/goneat"
	@$(MAKE) bootstrap

tools: ## Verify external tools are available
	@echo "Verifying tools..."
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -n "$$GONEAT_BIN" ]; then \
		$$GONEAT_BIN doctor tools --scope foundation 2>&1 || true; \
	else \
		echo "[!!] goneat not found (run 'make bootstrap')"; \
		echo ""; \
		echo "Fallback checks:"; \
		if command -v go >/dev/null 2>&1; then echo "[ok] go: $$(go version | cut -d' ' -f3)"; else echo "[!!] go not found"; fi; \
		if command -v staticcheck >/dev/null 2>&1; then echo "[ok] staticcheck found"; else echo "[!!] staticcheck not found"; fi; \
	fi
	@echo ""

# -----------------------------------------------------------------------------
# Format, Lint, Assess (via goneat)
# -----------------------------------------------------------------------------

fmt: ## Format code (Go + shell via goneat)
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -n "$$GONEAT_BIN" ]; then \
		$$GONEAT_BIN assess --categories format --fix; \
	else \
		go fmt ./...; \
		echo "[!!] goneat not found, shell/markdown formatting skipped (run 'make bootstrap')"; \
	fi

lint: ## Run linters (via goneat)
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -n "$$GONEAT_BIN" ]; then \
		$$GONEAT_BIN assess --categories lint --check; \
	else \
		echo "[!!] goneat not found (run 'make bootstrap')"; \
		go vet ./...; \
	fi

assess: ## Run goneat assess (format, lint, security)
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -z "$$GONEAT_BIN" ]; then echo "[!!] goneat not found (run 'make bootstrap')"; exit 1; fi; \
	$$GONEAT_BIN assess --categories format,lint,security --format concise

# -----------------------------------------------------------------------------
# Build, Test, Quality
# -----------------------------------------------------------------------------

build: ## Build for current platform
	@mkdir -p bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-ldflags="$(LDFLAGS)" \
		-trimpath \
		-o $(BUILD_ARTIFACT) $(MAIN)
	@echo "[ok] Built $(BUILD_ARTIFACT)"

build-all: ## Build for all platforms
	@mkdir -p dist/release
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-darwin-amd64     $(MAIN)
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-darwin-arm64     $(MAIN)
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-linux-amd64      $(MAIN)
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-linux-arm64      $(MAIN)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-windows-amd64.exe $(MAIN)
	@echo "[ok] Built all platforms to dist/release/"

test: ## Run tests
	go test -v -race ./...

gosec: ## Run gosec security scanner
	gosec ./...

gosec-high: ## Run gosec (high confidence only)
	gosec -confidence high -exclude G301,G302,G107,G304 ./...

# -----------------------------------------------------------------------------
# Pre-commit / Pre-push (via goneat hooks)
# -----------------------------------------------------------------------------

precommit: ## Run pre-commit checks (goneat assess + Go tests + build)
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	if [ -z "$$GONEAT_BIN" ]; then echo "[!!] goneat not found (run 'make bootstrap')"; exit 1; fi; \
	$$GONEAT_BIN assess --categories format,lint --check --fail-on critical
	go run github.com/santhosh-tekuri/jsonschema/cmd/jv@latest testdata/corpus.schema.json testdata/corpus.json
	go test -v -race ./...
	$(MAKE) gosec-high
	$(MAKE) build-all
	@echo "[ok] Pre-commit checks passed"

prepush: precommit ## Run pre-push checks (same as precommit + security)
	@GONEAT_BIN=""; \
	if [ -x "$(BIN_DIR)/goneat" ]; then GONEAT_BIN="$(BIN_DIR)/goneat"; \
	elif command -v goneat >/dev/null 2>&1; then GONEAT_BIN="$$(command -v goneat)"; fi; \
	$$GONEAT_BIN assess --categories format,lint,security --check --fail-on high
	@echo "[ok] Pre-push checks passed"

# -----------------------------------------------------------------------------
# Corpus Testing
# -----------------------------------------------------------------------------

corpus: build ## Run corpus tests (dry-run, fast repos)
	@mkdir -p $(CORPUS_DEST)
	@echo "Note: set GITHUB_TOKEN to avoid API rate limits"
	go run ./scripts/run-corpus.go --manifest testdata/corpus.json --dry-run --dest $(CORPUS_DEST) --sfetch-bin $(BUILD_ARTIFACT)

corpus-dryrun: corpus ## Alias for corpus

corpus-all: build ## Run corpus tests (all repos including slow)
	@mkdir -p $(CORPUS_DEST)
	@echo "Note: set GITHUB_TOKEN to avoid API rate limits"
	go run ./scripts/run-corpus.go --manifest testdata/corpus.json --dry-run --include-slow --dest $(CORPUS_DEST) --sfetch-bin $(BUILD_ARTIFACT)

corpus-validate: corpus-all ## Alias for corpus-all

# -----------------------------------------------------------------------------
# Release
# -----------------------------------------------------------------------------

release: build-all ## Prepare release (build all platforms)
	@echo "Release preparation for $(VERSION)"
	@echo "Build all platforms and prepare assets"

release-download: ## Download release assets for signing
	@mkdir -p $(DIST_RELEASE)
	./scripts/download-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

bootstrap-script: ## Copy install script into release directory
	@mkdir -p $(DIST_RELEASE)
	cp scripts/install-sfetch.sh $(DIST_RELEASE)/install-sfetch.sh
	@echo "[ok] Copied install-sfetch.sh to $(DIST_RELEASE)"

release-checksums: bootstrap-script ## Generate SHA256SUMS and SHA2-512SUMS
	go run ./scripts/cmd/generate-checksums --dir $(DIST_RELEASE)

release-verify-checksums: ## Verify checksums in dist/release
	@if [ ! -d "$(DIST_RELEASE)" ]; then echo "error: $(DIST_RELEASE) not found (run make release-download first)" >&2; exit 1; fi
	@echo "Verifying checksums in $(DIST_RELEASE)..."
	@cd $(DIST_RELEASE) && \
	if [ -f SHA256SUMS ]; then \
		echo "=== SHA256SUMS ===" && \
		shasum -a 256 -c SHA256SUMS 2>&1 | grep -v ': OK$$' || echo "All SHA256 checksums OK"; \
	fi && \
	if [ -f SHA2-512SUMS ]; then \
		echo "=== SHA2-512SUMS ===" && \
		shasum -a 512 -c SHA2-512SUMS 2>&1 | grep -v ': OK$$' || echo "All SHA512 checksums OK"; \
	fi
	@echo "[ok] Checksum verification complete"

release-notes: ## Copy release notes into dist/release
	@if [ -z "$(RELEASE_TAG)" ]; then echo "error: RELEASE_TAG not set" >&2; exit 1; fi
	@mkdir -p $(DIST_RELEASE)
	@src="docs/releases/$(RELEASE_TAG).md"; \
	if [ ! -f "$$src" ]; then \
		echo "error: release notes file $$src not found (did you set RELEASE_TAG?)" >&2; \
		exit 1; \
	fi; \
	cp "$$src" "$(DIST_RELEASE)/release-notes-$(RELEASE_TAG).md"
	@echo "[ok] Release notes copied to $(DIST_RELEASE)"

release-sign: release-checksums ## Sign checksum manifests
	SFETCH_MINISIGN_KEY=$(SFETCH_MINISIGN_KEY) SFETCH_PGP_KEY_ID=$(SFETCH_PGP_KEY_ID) SFETCH_GPG_HOMEDIR=$(SFETCH_GPG_HOMEDIR) ./scripts/sign-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

release-export-key: ## Export PGP public key to dist/release
	SFETCH_GPG_HOMEDIR=$(SFETCH_GPG_HOMEDIR) ./scripts/export-release-key.sh $(SFETCH_PGP_KEY_ID) $(DIST_RELEASE)

release-export-minisign-key: build ## Copy minisign public key to dist/release
	@if [ -z "$(SFETCH_MINISIGN_KEY)" ] && [ -z "$(SFETCH_MINISIGN_PUB)" ]; then echo "SFETCH_MINISIGN_KEY or SFETCH_MINISIGN_PUB not set" >&2; exit 1; fi
	@mkdir -p $(DIST_RELEASE)
	@if [ -n "$(SFETCH_MINISIGN_PUB)" ]; then \
		pubkey="$(SFETCH_MINISIGN_PUB)"; \
	else \
		pubkey="$$(echo "$(SFETCH_MINISIGN_KEY)" | sed 's/\.key$$/.pub/')"; \
	fi; \
	if [ -f "$$pubkey" ]; then \
		echo "Verifying $$pubkey is a valid minisign public key..."; \
		./$(BUILD_ARTIFACT) --verify-minisign-pubkey "$$pubkey" || exit 1; \
		cp "$$pubkey" "$(DIST_RELEASE)/$(MINISIGN_PUB_NAME)"; \
		echo "[ok] Copied minisign public key to $(DIST_RELEASE)/$(MINISIGN_PUB_NAME)"; \
	else \
		echo "error: public key $$pubkey not found" >&2; \
		exit 1; \
	fi

verify-release-key: ## Verify PGP key is public-only
	./scripts/verify-public-key.sh $(DIST_RELEASE)/$(PUBLIC_KEY_NAME)

verify-minisign-pubkey: build ## Verify minisign public key (usage: make verify-minisign-pubkey FILE=path/to/key.pub)
	@if [ -z "$(FILE)" ]; then echo "usage: make verify-minisign-pubkey FILE=path/to/key.pub" >&2; exit 1; fi
	@if [ ! -f "$(FILE)" ]; then echo "error: file $(FILE) not found" >&2; exit 1; fi
	./$(BUILD_ARTIFACT) --verify-minisign-pubkey "$(FILE)"

release-upload: release-notes verify-release-key ## Upload assets and update release notes
	./scripts/upload-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

release-clean: ## Remove dist/release contents
	rm -rf $(DIST_RELEASE)
	@echo "[ok] Cleaned $(DIST_RELEASE)"

# -----------------------------------------------------------------------------
# Install / Clean
# -----------------------------------------------------------------------------

install: build ## Install to INSTALL_BINDIR
	@mkdir -p "$(INSTALL_BINDIR)"
	cp "$(BUILD_ARTIFACT)" "$(INSTALL_TARGET)"
ifeq ($(GOOS),windows)
	@echo "[ok] Installed $(NAME)$(EXT) to $(INSTALL_TARGET)"
else
	chmod 755 "$(INSTALL_TARGET)"
	@echo "[ok] Installed $(NAME)$(EXT) to $(INSTALL_TARGET)"
endif

clean: ## Clean build artifacts
	rm -rf bin/ dist/ coverage.out
	@echo "[ok] Cleaned build artifacts"

# -----------------------------------------------------------------------------
# Version Management
# -----------------------------------------------------------------------------

version: ## Show current version
	@echo "$(VERSION)"

version-check: ## Show current version (verbose)
	@echo "Current version: $(VERSION)"

version-set: ## Set version (usage: make version-set V=X.Y.Z)
	@if [ -z "$(V)" ]; then echo "usage: make version-set V=X.Y.Z" >&2; exit 1; fi
	@echo "$(V)" > VERSION
	@echo "[ok] Version set to $(V)"

version-patch: ## Bump patch version
	@current=$(VERSION); \
	major=$$(echo $$current | cut -d. -f1); \
	minor=$$(echo $$current | cut -d. -f2); \
	patch=$$(echo $$current | cut -d. -f3); \
	newpatch=$$((patch + 1)); \
	newver="$$major.$$minor.$$newpatch"; \
	echo "$$newver" > VERSION; \
	echo "[ok] Version bumped: $$current -> $$newver"

version-minor: ## Bump minor version
	@current=$(VERSION); \
	major=$$(echo $$current | cut -d. -f1); \
	minor=$$(echo $$current | cut -d. -f2); \
	newminor=$$((minor + 1)); \
	newver="$$major.$$newminor.0"; \
	echo "$$newver" > VERSION; \
	echo "[ok] Version bumped: $$current -> $$newver"

version-major: ## Bump major version
	@current=$(VERSION); \
	major=$$(echo $$current | cut -d. -f1); \
	newmajor=$$((major + 1)); \
	newver="$$newmajor.0.0"; \
	echo "$$newver" > VERSION; \
	echo "[ok] Version bumped: $$current -> $$newver"

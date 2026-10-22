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
# PDR-0008: the release tag is an explicit input (SFETCH_RELEASE_TAG only).
# A Makefile ?= that lets an inherited bare variable win is a derived input
# and is not accepted (bare RELEASE_TAG is not accepted).
PUBLIC_KEY_NAME ?= sfetch-release-signing-key.asc
SFETCH_MINISIGN_KEY ?=
SFETCH_MINISIGN_PUB ?=
SFETCH_PGP_KEY_ID ?=
SFETCH_GPG_HOMEDIR ?=
MINISIGN_PUB_NAME ?= sfetch-minisign.pub
SCOOP_BUCKET_DIR ?= ../scoop-bucket
SCOOP_BUCKET_REPO ?= https://github.com/3leaps/scoop-bucket.git

# Tool installation directory (repo-local)
BIN_DIR := $(CURDIR)/bin

# Pinned tool versions (every gate/release tool is version-pinned; no @latest)
# SFETCH_VERSION is the N-1 self-bootstrap pin AND the CI install-script smoke
# pin (see .github/workflows/ci.yml). Always a fully-signed published release —
# never "latest" and never the in-flight cut — so main CI cannot 404 during the
# tag/upload window. Advance after each release publishes + signs.
SFETCH_VERSION := v0.4.13
GONEAT_VERSION ?= v0.6.6
GOVULNCHECK_VERSION ?= v1.8.0
GOLANGCI_LINT_VERSION ?= v2.14.0
GOSEC_VERSION ?= v2.29.0

# Tool paths (sfetch bootstrap may land in bin/; goneat must be on PATH)
SFETCH = $(shell [ -x "$(BIN_DIR)/sfetch" ] && echo "$(BIN_DIR)/sfetch" || command -v sfetch 2>/dev/null)

CORPUS_DEST ?= test-corpus

.PHONY: all help build test clean install fmt lint assess tools bootstrap bootstrap-force
.PHONY: precommit prepush version corpus corpus-all corpus-dryrun corpus-validate
.PHONY: release release-download release-checksums release-verify-checksums release-sign
.PHONY: release-notes release-upload release-upload-provenance release-export-key release-export-minisign-key release-export-keys
.PHONY: release-verify-key release-verify-minisign-pubkey release-verify-keys release-verify-signatures release-verify
.PHONY: release-clean bootstrap-script build-all gosec gosec-high update-scoop-manifest
.PHONY: package release-preflight release-tag-tests release-guard-tag-version
.PHONY: release-prepare-tag-message release-tag release-push-tag release-verify-tag release-verify-remote-tag
.PHONY: release-create-draft release-publish release-insert-anchors release-export-pin release-validate-pin
.PHONY: version-check version-set version-patch version-minor version-major
.PHONY: print-sfetch-version golangci-lint-install gosec-install test-gosec-pin test-release-verify-checksums test-release-verify-signatures test-release-workflow-draft test-bootstrap-sfetch-verified test-bootstrap-range-release test-install-anchor-select test-install-gpg-mutants test-goneat-key-map test-makefile-release-tag test-upload-release-draft test-version-ldflags require-release-tag

all: build

# Echo SFETCH_VERSION via make (not shell parsing of Makefile). CI install smoke
# and other tools should use this so patch/minor/major pin values always expand
# correctly regardless of assignment form or version shape.
print-sfetch-version: ## Print bootstrap/CI smoke pin (SFETCH_VERSION)
	@echo $(SFETCH_VERSION)

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
# Trust chain: verified bootstrap script -> sfetch (N-1 pin) -> goneat
#
# N-1 pin (SFETCH_VERSION) is always a published release — never this cut.
# N-1 pin is a published release. At/after v0.4.11 the engine takes the
# detached install-sfetch.sh.minisig route when N-1 >= MINISIG_SINCE (v0.4.11).
#
# Do not pipe curl | bash here — that is the anti-pattern this release fixes.

bootstrap: ## Install development tools via verified trust chain
	@echo "Bootstrapping sfetch development environment..."
	@echo ""
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
	@mkdir -p "$(BIN_DIR)"
	@if [ ! -x "$(BIN_DIR)/sfetch" ] && ! command -v sfetch >/dev/null 2>&1; then \
		echo "[..] Installing sfetch $(SFETCH_VERSION) (verified bootstrap, N-1 pin)..."; \
		./scripts/bootstrap-sfetch-verified.sh \
			--version "$(SFETCH_VERSION)" \
			--dir "$(BIN_DIR)" \
			--yes; \
	else \
		echo "[ok] sfetch already installed"; \
	fi
	@SFETCH_BIN=""; \
	if [ -x "$(BIN_DIR)/sfetch" ]; then SFETCH_BIN="$(BIN_DIR)/sfetch"; \
	elif command -v sfetch >/dev/null 2>&1; then SFETCH_BIN="$$(command -v sfetch)"; fi; \
	if [ -z "$$SFETCH_BIN" ]; then echo "[!!] sfetch installation failed"; exit 1; fi; \
	echo "[ok] sfetch: $$SFETCH_BIN"
	@echo ""
	@# Step 2: Verify goneat is installed (dev machines ship with it; CI installs it explicitly before calling make)
	@if ! command -v goneat >/dev/null 2>&1; then \
		echo "[!!] goneat not found on PATH"; \
		echo "    Install it from https://github.com/fulmenhq/goneat/releases (pinned: $(GONEAT_VERSION))"; \
		echo "    Or: ./scripts/bootstrap-sfetch-verified.sh --version $(SFETCH_VERSION) --dir $(BIN_DIR) --goneat-version $(GONEAT_VERSION)"; \
		exit 1; \
	fi
	@echo "[ok] goneat: $$(goneat version 2>&1 | head -n1)"
	@echo ""
	@# Step 3: Install foundation tools via goneat
	@echo "[..] Installing foundation tools via goneat..."
	@goneat doctor tools --scope foundation --install --yes 2>/dev/null || \
		echo "[!!] goneat doctor tools failed, some tools may need manual installation"
	@echo ""
	@echo "[ok] Bootstrap complete"
	@echo ""
	@echo "Run 'make build' to build sfetch"

bootstrap-force: ## Force reinstall repo-local sfetch and re-run bootstrap
	@rm -f "$(BIN_DIR)/sfetch"
	@$(MAKE) bootstrap

tools: ## Verify external tools are available
	@echo "Verifying tools..."
	@if ! command -v goneat >/dev/null 2>&1; then \
		echo "[!!] goneat not found on PATH (install from https://github.com/fulmenhq/goneat/releases)"; \
		exit 1; \
	fi
	@goneat doctor tools --scope foundation 2>&1 || true
	@echo ""

golangci-lint-install: ## Install pinned golangci-lint into bin/ and assert its version
	@mkdir -p $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@ver="$$($(BIN_DIR)/golangci-lint version --short 2>/dev/null)"; \
	if [ "v$$ver" != "$(GOLANGCI_LINT_VERSION)" ] && [ "$$ver" != "$(GOLANGCI_LINT_VERSION)" ]; then \
		echo "[!!] golangci-lint version mismatch (have: $$ver; want: $(GOLANGCI_LINT_VERSION))" >&2; \
		exit 1; \
	fi; \
	echo "[ok] golangci-lint $(GOLANGCI_LINT_VERSION) in $(BIN_DIR)"

# gosec -version prints "dev" for go install builds (no release ldflags).
# Assert the module version recorded in the binary instead.
gosec-install: ## Install pinned gosec into bin/ and assert its version
	@mkdir -p $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	@modver="$$(go version -m "$(BIN_DIR)/gosec" 2>/dev/null | awk '$$1=="mod" && $$2=="github.com/securego/gosec/v2" {print $$3; exit}')"; \
	if [ -z "$$modver" ] || [ "$$modver" != "$(GOSEC_VERSION)" ]; then \
		echo "[!!] gosec version mismatch (have: $$modver; want: $(GOSEC_VERSION))" >&2; \
		exit 1; \
	fi; \
	echo "[ok] gosec $(GOSEC_VERSION) in $(BIN_DIR)"

# -----------------------------------------------------------------------------
# Format, Lint, Assess (via goneat)
# -----------------------------------------------------------------------------

fmt: ## Format code (Go + shell via goneat)
	@command -v goneat >/dev/null 2>&1 || { echo "[!!] goneat not found on PATH"; exit 1; }
	goneat assess --categories format --fix

lint: ## Run linters (via goneat)
	@command -v goneat >/dev/null 2>&1 || { echo "[!!] goneat not found on PATH"; exit 1; }
	goneat assess --categories lint --check

assess: ## Run goneat assess (format, lint, security)
	@command -v goneat >/dev/null 2>&1 || { echo "[!!] goneat not found on PATH"; exit 1; }
	goneat assess --categories format,lint,security --format concise

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
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-darwin-arm64     $(MAIN)
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-linux-amd64      $(MAIN)
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-linux-arm64      $(MAIN)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-windows-amd64.exe $(MAIN)
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-windows-arm64.exe $(MAIN)
	@echo "[ok] Built all platforms to dist/release/"

test: ## Run tests
	go test -v -race ./...

gosec: ## Run gosec security scanner
	gosec ./...

gosec-high: ## Run gosec (high confidence only)
	@export PATH="$(BIN_DIR):$$PATH"; \
	if ! command -v gosec >/dev/null 2>&1; then \
		echo "[!!] gosec not found on PATH; run 'make gosec-install' (pinned $(GOSEC_VERSION))" >&2; \
		exit 1; \
	fi; \
	gosec -confidence high -exclude G301,G302,G107,G304 ./...

# -----------------------------------------------------------------------------
# Pre-commit / Pre-push (via goneat hooks)
# -----------------------------------------------------------------------------

precommit: ## Run pre-commit checks (goneat assess + Go tests + build)
	@command -v goneat >/dev/null 2>&1 || { echo "[!!] goneat not found on PATH"; exit 1; }
	goneat assess --categories format,lint --check --fail-on critical
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	go test -v -race ./...
	$(MAKE) test-gosec-pin
	$(MAKE) gosec-high
	$(MAKE) build-all
	# CI runs make precommit (not prepush); keep fail-closed release-verify regression on this path.
	$(MAKE) test-release-verify-checksums
	$(MAKE) test-release-verify-signatures
	$(MAKE) test-release-workflow-draft
	$(MAKE) test-bootstrap-sfetch-verified
	$(MAKE) test-bootstrap-range-release
	$(MAKE) test-install-anchor-select
	$(MAKE) test-install-gpg-mutants
	$(MAKE) test-goneat-key-map
	$(MAKE) test-makefile-release-tag
	$(MAKE) test-upload-release-draft
	$(MAKE) test-version-ldflags
	$(MAKE) release-tag-tests
	@echo "[ok] Pre-commit checks passed"

prepush: precommit ## Run pre-push checks (same as precommit + security)
	@command -v goneat >/dev/null 2>&1 || { echo "[!!] goneat not found on PATH"; exit 1; }
	goneat assess --categories format,lint,security --check --fail-on high
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

release-download: require-release-tag ## Download CI artifacts for signing (writes dest.anchor)
	@mkdir -p $(DIST_RELEASE)
	./scripts/release-fetch-ci-artifacts.sh $(SFETCH_RELEASE_TAG) $(DIST_RELEASE)

bootstrap-script: ## Copy install script into release directory
	@mkdir -p $(DIST_RELEASE)
	cp scripts/install-sfetch.sh $(DIST_RELEASE)/install-sfetch.sh
	@echo "[ok] Copied install-sfetch.sh to $(DIST_RELEASE)"

release-checksums: bootstrap-script ## Generate SHA256SUMS and SHA512SUMS
	go run ./scripts/cmd/generate-checksums --dir $(DIST_RELEASE)

release-verify-checksums: ## Verify checksums in dist/release (fail-closed; portable /bin/sh)
	@if [ ! -d "$(DIST_RELEASE)" ]; then echo "error: $(DIST_RELEASE) not found (run make release-download first)" >&2; exit 1; fi
	@echo "Verifying checksums in $(DIST_RELEASE)..."
	@set -eu; \
	cd "$(DIST_RELEASE)"; \
	if [ ! -s SHA256SUMS ]; then \
		echo "error: SHA256SUMS missing or empty in $(DIST_RELEASE)" >&2; \
		exit 1; \
	fi; \
	if [ ! -s SHA512SUMS ]; then \
		echo "error: SHA512SUMS missing or empty in $(DIST_RELEASE)" >&2; \
		exit 1; \
	fi; \
	echo "=== SHA256SUMS ==="; \
	shasum -a 256 -c SHA256SUMS; \
	echo "=== SHA512SUMS ==="; \
	shasum -a 512 -c SHA512SUMS; \
	echo "[ok] Checksum verification complete"

# Negative + positive regression for release-verify-checksums (exit status only).
# Wired into precommit because sfetch CI runs make precommit, not prepush.
test-gosec-pin: ## Regression: gosec pin and fail-closed missing-binary guard
	@./scripts/test-gosec-pin.sh

test-release-verify-checksums: ## Regression: fail-closed checksum verify (corrupt/absent/empty)
	@./scripts/test-release-verify-checksums.sh

test-release-verify-signatures: ## Regression: required installer minisig + sign targets
	@./scripts/test-release-verify-signatures.sh

test-release-workflow-draft: ## Regression: every release-writing action preserves draft state
	@python3 ./scripts/test-release-workflow-draft.py

test-bootstrap-sfetch-verified: ## Regression: dual-route bootstrap rejects + fail-closed
	@./scripts/test-bootstrap-sfetch-verified.sh

test-bootstrap-range-release: ## Assert MAX==v(VERSION) and MINISIG_SINCE in range (committed constants)
	@./scripts/assert-bootstrap-range-release.sh

test-install-anchor-select: ## Regression: installer pin-map anchor selection (unit + coherence)
	@./scripts/test-install-anchor-select.sh

test-install-gpg-mutants: ## Mutation tests: all 11 installer GPG-route mutants must die
	@./scripts/test-install-gpg-mutants.sh

test-goneat-key-map: ## Regression: engine goneat pin map (rotation at v0.6.1)
	@./scripts/test-goneat-key-map.sh

test-makefile-release-tag: ## Regression: Makefile refuses bare RELEASE_TAG (not accepted)
	@./scripts/test-makefile-release-tag.sh

test-upload-release-draft: ## Regression: release-upload stays a draft
	@./scripts/test-upload-release-draft.sh

test-version-ldflags: ## Regression: LDFLAGS-injected version outside the repo
	@./scripts/test-version-ldflags.sh

# Tag-consuming recipes refuse a bare RELEASE_TAG (not accepted) and require
# SFETCH_RELEASE_TAG == v$(VERSION). Expanding $(RELEASE_TAG) here is only to
# detect it. require-release-tag is a real prerequisite so the check runs
# before any other prerequisite of a tag-consuming target.
define require_sfetch_release_tag
	@if [ -n "$(RELEASE_TAG)" ]; then echo "error: RELEASE_TAG is not accepted; set SFETCH_RELEASE_TAG only" >&2; exit 1; fi
	@if [ -z "$(SFETCH_RELEASE_TAG)" ]; then echo "error: SFETCH_RELEASE_TAG required" >&2; exit 1; fi
	@printf '%s\n' "$(SFETCH_RELEASE_TAG)" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$$' || { echo "error: SFETCH_RELEASE_TAG must be canonical vX.Y.Z" >&2; exit 1; }
	@if [ "$(SFETCH_RELEASE_TAG)" != "v$(VERSION)" ]; then echo "error: SFETCH_RELEASE_TAG ($(SFETCH_RELEASE_TAG)) must equal v$(VERSION)" >&2; exit 1; fi
endef

require-release-tag:
	$(call require_sfetch_release_tag)

package: ## Cross-compile and package unversioned platform archives
	$(MAKE) build GOOS=linux GOARCH=amd64
	$(MAKE) build GOOS=linux GOARCH=arm64
	$(MAKE) build GOOS=darwin GOARCH=arm64
	$(MAKE) build GOOS=windows GOARCH=amd64
	$(MAKE) build GOOS=windows GOARCH=arm64
	./scripts/package-artifacts.sh

release-tag-tests: ## Signed-tag tooling tests (throwaway keys only; never the default homedir)
	@./scripts/release-ci-artifact-draft.test.sh
	@./scripts/release-workflow-permissions.test.sh
	@./scripts/release-guard-tag-version.test.sh
	@./scripts/release-tag-controls.test.sh
	@./scripts/release-tag-operator.test.sh
	@./scripts/release-prepare-tag-message.test.sh
	@./scripts/release-pin-precursors.test.sh
	@./scripts/release-decernor.test.sh
	@./scripts/release-restore-tag-ref.test.sh
	@./scripts/verify-pinned-tag.test.sh
	@./scripts/release-verify-published-tag.test.sh
	@./scripts/release-publish.test.sh
	@./scripts/release-verify-committed-anchors.test.sh
	@./scripts/release-stage-tagged-pubkeys.test.sh
	@./scripts/ci-install-decernor.test.sh
	@./scripts/test-review-findings.sh
	@echo "[ok] Release tag tooling tests passed"

release-preflight: ## Verify clean-tree pre-tag requirements (does not tag)
	@./scripts/release-verify-committed-anchors.sh
	@./scripts/release-inspect-tag-ruleset.sh "v$(VERSION)"
	@if [ -n "$$(git status --porcelain 2>/dev/null)" ]; then \
		echo "[!!] Working tree not clean - commit or stash changes first"; \
		git status --short; \
		exit 1; \
	fi
	@$(MAKE) test-makefile-release-tag
	@echo "[ok] Release preflight (tooling) passed"

release-guard-tag-version: require-release-tag ## Validate the canonical SFETCH_RELEASE_TAG
	@./scripts/release-guard-tag-version.sh

release-prepare-tag-message: require-release-tag ## Prepare the external per-cut tag message (maintainer)
	@./scripts/release-tag-operator.sh prepare-message

release-tag: require-release-tag ## Maintainer-only: create and verify a local signed version tag (no push)
	@./scripts/release-tag-operator.sh local-tag

release-push-tag: require-release-tag ## Maintainer-only: publish and verify the signed version tag
	@./scripts/release-tag-operator.sh remote-push

release-verify-tag: require-release-tag ## Verify the tag using only the committed public pin
	@./scripts/release-verify-tag.sh

release-verify-remote-tag: require-release-tag ## Compare local and remote tag objects and GitHub verification
	@./scripts/release-verify-remote-tag.sh

release-create-draft: require-release-tag ## Maintainer-only: open a draft GitHub release from staged packages
	@./scripts/release-create-draft.sh "$(SFETCH_RELEASE_TAG)" "$(DIST_RELEASE)"

release-publish: require-release-tag ## Maintainer-only: byte-verify draft assets, then promote
	@./scripts/release-publish.sh "$(SFETCH_RELEASE_TAG)" "$(DIST_RELEASE)"

release-export-pin: ## Maintainer-only: export approved public key when no pin exists
	@./scripts/release-export-pin.sh

release-validate-pin: ## Maintainer-only: read-only validation of existing public pin
	@./scripts/release-validate-pin.sh

release-insert-anchors: release-validate-pin ## Maintainer-only: validate pin, then generate public anchors
	@./scripts/release-insert-anchors.sh

release-notes: require-release-tag ## Copy release notes into dist/release
	@mkdir -p $(DIST_RELEASE)
	@src="docs/releases/$(SFETCH_RELEASE_TAG).md"; \
	if [ ! -f "$$src" ]; then \
		echo "error: release notes file $$src not found (did you set SFETCH_RELEASE_TAG?)" >&2; \
		exit 1; \
	fi; \
	cp "$$src" "$(DIST_RELEASE)/release-notes-$(SFETCH_RELEASE_TAG).md"
	@echo "[ok] Release notes copied to $(DIST_RELEASE)"

release-sign: require-release-tag ## Sign manifests + installer (minisign); PGP manifests-only
	@$(MAKE) release-checksums
	SFETCH_MINISIGN_KEY=$(SFETCH_MINISIGN_KEY) SFETCH_PGP_KEY_ID=$(SFETCH_PGP_KEY_ID) SFETCH_GPG_HOMEDIR=$(SFETCH_GPG_HOMEDIR) ./scripts/sign-release-manifests.sh $(SFETCH_RELEASE_TAG) $(DIST_RELEASE)

release-export-key: require-release-tag ## Stage PGP public key from the tagged commit
	@mkdir -p $(DIST_RELEASE)
	./scripts/release-stage-tagged-pubkeys.sh $(SFETCH_RELEASE_TAG) $(DIST_RELEASE)

release-export-minisign-key: require-release-tag ## Stage minisign public key from the tagged commit
	@mkdir -p $(DIST_RELEASE)
	./scripts/release-stage-tagged-pubkeys.sh $(SFETCH_RELEASE_TAG) $(DIST_RELEASE)

release-export-keys: require-release-tag ## Stage public signing keys from the tagged commit
	@mkdir -p $(DIST_RELEASE)
	./scripts/release-stage-tagged-pubkeys.sh $(SFETCH_RELEASE_TAG) $(DIST_RELEASE)

release-verify-key: ## Verify PGP key is public-only
	./scripts/verify-public-key.sh $(DIST_RELEASE)/$(PUBLIC_KEY_NAME)

release-verify-minisign-pubkey: build ## Verify minisign public key (usage: make release-verify-minisign-pubkey FILE=path/to/key.pub)
	@if [ -z "$(FILE)" ]; then echo "usage: make release-verify-minisign-pubkey FILE=path/to/key.pub" >&2; exit 1; fi
	@if [ ! -f "$(FILE)" ]; then echo "error: file $(FILE) not found" >&2; exit 1; fi
	./$(BUILD_ARTIFACT) --verify-minisign-pubkey "$(FILE)"

release-verify-keys: release-verify-key ## Verify all exported public keys
	@if [ -f "$(DIST_RELEASE)/$(MINISIGN_PUB_NAME)" ]; then \
		$(MAKE) release-verify-minisign-pubkey FILE=$(DIST_RELEASE)/$(MINISIGN_PUB_NAME); \
	else \
		echo "ℹ️  No minisign public key to verify ($(MINISIGN_PUB_NAME) not found)"; \
	fi

release-verify-signatures: ## Verify signatures (installer minisig required; PGP optional)
	./scripts/verify-signatures.sh $(DIST_RELEASE)

release-verify: release-verify-checksums release-verify-signatures release-verify-keys ## Full post-signing release verification

release-upload: require-release-tag ## Upload all assets (requires full verification chain)
	@$(MAKE) release-notes
	@$(MAKE) release-verify
	./scripts/upload-release-assets.sh $(SFETCH_RELEASE_TAG) $(DIST_RELEASE)
	@echo ""
	@echo "📝 Updating Scoop manifest..."
	@$(MAKE) update-scoop-manifest

release-upload-provenance: require-release-tag ## Upload provenance only (requires full verification chain)
	@$(MAKE) release-notes
	@$(MAKE) release-verify
	./scripts/release-upload-provenance.sh $(SFETCH_RELEASE_TAG) $(DIST_RELEASE)

update-scoop-manifest: ## Update Scoop bucket manifest with the current release version (requires sibling ../scoop-bucket)
	@echo "Updating Scoop manifest for $(NAME) $(VERSION)..."
	@echo ""
	@echo "ℹ️  Note: This target expects the scoop-bucket repository as a sibling directory"
	@echo "   Repository: $(SCOOP_BUCKET_REPO)"
	@echo "   Expected path: $(SCOOP_BUCKET_DIR)"
	@echo ""
	@if [ ! -d "$(SCOOP_BUCKET_DIR)" ]; then \
		echo "⚠️  Warning: $(SCOOP_BUCKET_DIR) directory not found"; \
		echo ""; \
		echo "Please clone or initialize the scoop-bucket repository:"; \
		echo "  cd .. && git clone $(SCOOP_BUCKET_REPO)"; \
		echo ""; \
		echo "Directory structure should be:"; \
		echo "  parent/"; \
		echo "    ├── sfetch/           (this repository)"; \
		echo "    └── scoop-bucket/     (sibling repository)"; \
		echo ""; \
		echo "Skipping Scoop manifest update."; \
	elif [ ! -f "$(SCOOP_BUCKET_DIR)/bucket/$(NAME).json" ]; then \
		echo "❌ Error: Manifest file not found: $(SCOOP_BUCKET_DIR)/bucket/$(NAME).json"; \
		exit 1; \
	else \
		echo "✅ Sibling repository found: $(SCOOP_BUCKET_DIR)"; \
		echo "   Calling scoop-bucket update target..."; \
		$(MAKE) -C "$(SCOOP_BUCKET_DIR)" update-sfetch VERSION=$(VERSION); \
		echo ""; \
		echo "✅ Scoop manifest updated successfully!"; \
		echo ""; \
		echo "📋 Next steps:"; \
		echo "   1. Review changes:  cd $(SCOOP_BUCKET_DIR) && git diff bucket/$(NAME).json"; \
		echo "   2. Validate JSON:   python3 -m json.tool $(SCOOP_BUCKET_DIR)/bucket/$(NAME).json >/dev/null"; \
		echo "   3. Commit bucket:   cd $(SCOOP_BUCKET_DIR) && git add bucket/$(NAME).json && git commit"; \
		echo "   4. Push bucket:     cd $(SCOOP_BUCKET_DIR) && git push"; \
	fi

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

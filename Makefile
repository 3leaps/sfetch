-include buildconfig.mk

# Read version from VERSION file, fallback to dev
VERSION ?= $(shell cat VERSION 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
NAME ?= sfetch
MAIN ?= .
YAMLLINT ?= yamllint
JQ ?= jq
ACTIONLINT ?= actionlint

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

.PHONY: all build test clean release-clean install release fmt fmt-check shell-check lint tools prereqs prereqs-advise bootstrap quality gosec gosec-high yamllint-workflows precommit build-all release-download release-checksums release-sign release-notes release-upload verify-release-key release-export-minisign-key bootstrap-script version-check version-set version-patch version-minor version-major corpus corpus-all corpus-dryrun corpus-validate

CORPUS_DEST ?= test-corpus

all: build

tools:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest

prereqs: tools
	@echo "Checking prerequisites..."
	@command -v $(YAMLLINT) >/dev/null 2>&1 || { echo "yamllint not found: brew install yamllint / apt install yamllint / pipx install yamllint" >&2; exit 1; }
	@command -v shfmt >/dev/null 2>&1 || { echo "shfmt not found: brew install shfmt / go install mvdan.cc/sh/v3/cmd/shfmt@latest" >&2; exit 1; }
	@command -v shellcheck >/dev/null 2>&1 || echo "shellcheck not found (optional): brew install shellcheck / apt install shellcheck"
	@command -v $(JQ) >/dev/null 2>&1 || echo "$(JQ) not found (optional): brew install jq / apt install jq"
	@command -v $(ACTIONLINT) >/dev/null 2>&1 || echo "$(ACTIONLINT) not found (optional): go install github.com/rhysd/actionlint/cmd/actionlint@latest"
	@echo "All prerequisites available"

prereqs-advise:
	@echo "Checking prerequisites (advisory; will not fail)..."
	@command -v $(YAMLLINT) >/dev/null 2>&1 || echo "yamllint not found: brew install yamllint / apt install yamllint / pipx install yamllint" >&2
	@command -v shfmt >/dev/null 2>&1 || echo "shfmt not found: brew install shfmt / go install mvdan.cc/sh/v3/cmd/shfmt@latest" >&2
	@command -v shellcheck >/dev/null 2>&1 || echo "shellcheck not found (optional): brew install shellcheck / apt install shellcheck" >&2
	@command -v $(JQ) >/dev/null 2>&1 || echo "$(JQ) not found (optional): brew install jq / apt install jq" >&2
	@command -v $(ACTIONLINT) >/dev/null 2>&1 || echo "$(ACTIONLINT) not found (optional): go install github.com/rhysd/actionlint/cmd/actionlint@latest" >&2
	@echo "Bootstrap checks complete"

bootstrap: tools prereqs-advise

fmt:
	go fmt ./...
	@if command -v shfmt >/dev/null 2>&1; then \
		shfmt -w -i 4 -ci scripts/*.sh; \
	fi

fmt-check:
	@files=$$(git ls-files '*.go'); \
	if [ -n "$$files" ]; then \
		missing=$$(git ls-files -z '*.go' | xargs -0 gofmt -l); \
		if [ -n "$$missing" ]; then \
			echo "gofmt required for:"; \
			echo "$$missing"; \
			exit 1; \
		fi; \
	fi

shell-check:
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not found: brew install shellcheck" >&2; exit 1; }
	@command -v shfmt >/dev/null 2>&1 || { echo "shfmt not found: brew install shfmt" >&2; exit 1; }
	shellcheck scripts/*.sh
	@if ! shfmt -d -i 4 -ci scripts/*.sh >/dev/null 2>&1; then \
		echo "shfmt formatting required for scripts/*.sh - run 'make fmt'"; \
		shfmt -d -i 4 -ci scripts/*.sh; \
		exit 1; \
	fi

lint: tools
	go vet ./...
	go vet ./scripts
	staticcheck ./...
	staticcheck ./scripts
	go run github.com/santhosh-tekuri/jsonschema/cmd/jv@latest testdata/corpus.schema.json testdata/corpus.json
	@$(MAKE) lint-workflows

test:
	go test -v -race ./...

gosec: tools
	gosec ./...

gosec-high: tools
	gosec -confidence high -exclude G301,G302,G107,G304 ./...

yamllint-workflows:
	@command -v $(YAMLLINT) >/dev/null 2>&1 || { echo "$(YAMLLINT) not found (optional): run 'make prereqs' for install guidance" >&2; exit 0; }
	$(YAMLLINT) .github/workflows

actionlint-workflows:
	@command -v $(ACTIONLINT) >/dev/null 2>&1 || { echo "$(ACTIONLINT) not found (optional): go install github.com/rhysd/actionlint/cmd/actionlint@latest" >&2; exit 0; }
	$(ACTIONLINT) .github/workflows/*.yml

lint-workflows: yamllint-workflows actionlint-workflows

# Corpus targets are opt-in (not part of quality/precommit) because they
# require authenticated GitHub API calls. Run manually during release prep:
#   GITHUB_TOKEN=<token> make corpus        # fast repos, dry-run
#   GITHUB_TOKEN=<token> make corpus-all    # all repos including slow
corpus:
	@mkdir -p $(CORPUS_DEST)
	@echo "Note: set GITHUB_TOKEN to avoid API rate limits"
	go run ./scripts/run-corpus.go --manifest testdata/corpus.json --dry-run --dest $(CORPUS_DEST)

corpus-dryrun:
	@mkdir -p $(CORPUS_DEST)
	@echo "Note: set GITHUB_TOKEN to avoid API rate limits"
	go run ./scripts/run-corpus.go --manifest testdata/corpus.json --dry-run --dest $(CORPUS_DEST)

corpus-all:
	@mkdir -p $(CORPUS_DEST)
	@echo "Note: set GITHUB_TOKEN to avoid API rate limits"
	go run ./scripts/run-corpus.go --manifest testdata/corpus.json --dry-run --include-slow --dest $(CORPUS_DEST)

corpus-validate:
	@mkdir -p $(CORPUS_DEST)
	@echo "Note: set GITHUB_TOKEN to avoid API rate limits"
	go run ./scripts/run-corpus.go --manifest testdata/corpus.json --dry-run --include-slow --dest $(CORPUS_DEST)


quality: prereqs fmt-check shell-check lint test gosec-high build-all yamllint-workflows

precommit: quality

build:
	mkdir -p bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-ldflags="$(LDFLAGS)" \
		-trimpath \
		-o $(BUILD_ARTIFACT) $(MAIN)

build-all:
	mkdir -p dist/release
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-darwin-amd64     $(MAIN)
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-darwin-arm64     $(MAIN)
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-linux-amd64      $(MAIN)
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-linux-arm64      $(MAIN)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/release/$(NAME)-windows-amd64.exe $(MAIN)

release: build-all
	# TODO: GitHub release automation
	@echo "Release preparation for $(VERSION)"
	@echo "Build all platforms and prepare assets"

release-download:
	@mkdir -p $(DIST_RELEASE)
	./scripts/download-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

bootstrap-script:
	@mkdir -p $(DIST_RELEASE)
	cp scripts/install-sfetch.sh $(DIST_RELEASE)/install-sfetch.sh
	@echo "✅ Copied install-sfetch.sh to $(DIST_RELEASE)"

release-checksums: bootstrap-script
	go run ./scripts/cmd/generate-checksums --dir $(DIST_RELEASE)

# Backwards compatibility alias
release-sha256: release-checksums

release-notes:
	@mkdir -p $(DIST_RELEASE)
	cp RELEASE_NOTES.md $(DIST_RELEASE)/release-notes-$(RELEASE_TAG).md
	@echo "✅ Release notes copied to $(DIST_RELEASE)"

# Note: SFETCH_GPG_HOMEDIR should be set by user if using custom GPG homedir
# This is not persisted and only affects the signing operation
release-sign: release-checksums
	SFETCH_MINISIGN_KEY=$(SFETCH_MINISIGN_KEY) SFETCH_PGP_KEY_ID=$(SFETCH_PGP_KEY_ID) SFETCH_GPG_HOMEDIR=$(SFETCH_GPG_HOMEDIR) ./scripts/sign-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

release-export-key:
	SFETCH_GPG_HOMEDIR=$(SFETCH_GPG_HOMEDIR) ./scripts/export-release-key.sh $(SFETCH_PGP_KEY_ID) $(DIST_RELEASE)

release-export-minisign-key: build
	@if [ -z "$(SFETCH_MINISIGN_KEY)" ] && [ -z "$(SFETCH_MINISIGN_PUB)" ]; then echo "SFETCH_MINISIGN_KEY or SFETCH_MINISIGN_PUB not set" >&2; exit 1; fi
	@mkdir -p $(DIST_RELEASE)
	@# Use explicit pub path if set, otherwise derive from secret key path
	@if [ -n "$(SFETCH_MINISIGN_PUB)" ]; then \
		pubkey="$(SFETCH_MINISIGN_PUB)"; \
	else \
		pubkey="$$(echo "$(SFETCH_MINISIGN_KEY)" | sed 's/\.key$$/.pub/')"; \
	fi; \
	if [ -f "$$pubkey" ]; then \
		echo "Verifying $$pubkey is a valid minisign public key..."; \
		./$(BUILD_ARTIFACT) --verify-minisign-pubkey "$$pubkey" || exit 1; \
		cp "$$pubkey" "$(DIST_RELEASE)/$(MINISIGN_PUB_NAME)"; \
		echo "✅ Copied minisign public key to $(DIST_RELEASE)/$(MINISIGN_PUB_NAME)"; \
	else \
		echo "error: public key $$pubkey not found" >&2; \
		exit 1; \
	fi

verify-minisign-pubkey: build
	@if [ -z "$(FILE)" ]; then echo "usage: make verify-minisign-pubkey FILE=path/to/key.pub" >&2; exit 1; fi
	./$(BUILD_ARTIFACT) --verify-minisign-pubkey "$(FILE)"

verify-release-key:
	./scripts/verify-public-key.sh $(DIST_RELEASE)/$(PUBLIC_KEY_NAME)

# release-upload: Uploads ALL assets with --clobber for idempotency.
# Re-uploads binaries even though CI built them (same files, ~15MB).
# This ensures fixes can be applied by simply re-running the target.
release-upload: release-notes verify-release-key
	./scripts/upload-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

release-clean:
	rm -rf $(DIST_RELEASE)
	@echo "Cleaned $(DIST_RELEASE)"

clean:
	rm -rf bin/ dist/ coverage.out

install: build
	@mkdir -p "$(INSTALL_BINDIR)"
	cp "$(BUILD_ARTIFACT)" "$(INSTALL_TARGET)"
ifeq ($(GOOS),windows)
	@echo "Installed $(NAME)$(EXT) to $(INSTALL_TARGET). Ensure this directory is on your PATH."
else
	chmod 755 "$(INSTALL_TARGET)"
	@echo "Installed $(NAME)$(EXT) to $(INSTALL_TARGET). Add it to your PATH if needed."
endif

# Version management targets
# Usage: make version-patch  (0.2.0 -> 0.2.1)
#        make version-minor  (0.2.0 -> 0.3.0)
#        make version-major  (0.2.0 -> 1.0.0)
#        make version-set V=1.2.3
#        make version-check  (show current version)

version-check:
	@echo "Current version: $(VERSION)"

version-set:
	@if [ -z "$(V)" ]; then echo "usage: make version-set V=X.Y.Z" >&2; exit 1; fi
	@echo "$(V)" > VERSION
	@echo "Version set to $(V)"

version-patch:
	@current=$(VERSION); \
	major=$$(echo $$current | cut -d. -f1); \
	minor=$$(echo $$current | cut -d. -f2); \
	patch=$$(echo $$current | cut -d. -f3); \
	newpatch=$$((patch + 1)); \
	newver="$$major.$$minor.$$newpatch"; \
	echo "$$newver" > VERSION; \
	echo "Version bumped: $$current -> $$newver"

version-minor:
	@current=$(VERSION); \
	major=$$(echo $$current | cut -d. -f1); \
	minor=$$(echo $$current | cut -d. -f2); \
	newminor=$$((minor + 1)); \
	newver="$$major.$$newminor.0"; \
	echo "$$newver" > VERSION; \
	echo "Version bumped: $$current -> $$newver"

version-major:
	@current=$(VERSION); \
	major=$$(echo $$current | cut -d. -f1); \
	newmajor=$$((major + 1)); \
	newver="$$newmajor.0.0"; \
	echo "$$newver" > VERSION; \
	echo "Version bumped: $$current -> $$newver"

-include buildconfig.mk

# Read version from VERSION file, fallback to dev
VERSION ?= $(shell cat VERSION 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
NAME ?= sfetch
MAIN ?= ./main.go
YAMLLINT ?= yamllint

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
MINISIGN_KEY ?=
MINISIGN_PUB_NAME ?= sfetch-minisign.pub

.PHONY: all build test clean install release fmt fmt-check shell-check lint tools prereqs bootstrap quality gosec gosec-high yamllint-workflows precommit build-all release-download release-sign release-notes release-upload verify-release-key release-export-minisign-key bootstrap-script

all: build

tools:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest

prereqs: tools
	@echo "Checking prerequisites..."
	@command -v $(YAMLLINT) >/dev/null 2>&1 || { echo "yamllint not found: brew install yamllint / apt install yamllint / pipx install yamllint" >&2; exit 1; }
	@command -v shfmt >/dev/null 2>&1 || { echo "shfmt not found: brew install shfmt / go install mvdan.cc/sh/v3/cmd/shfmt@latest" >&2; exit 1; }
	@command -v shellcheck >/dev/null 2>&1 || echo "shellcheck not found (optional): brew install shellcheck / apt install shellcheck"
	@echo "All prerequisites available"

bootstrap: prereqs

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
	@if ! shfmt -d scripts/*.sh >/dev/null 2>&1; then \
		echo "shfmt formatting required for scripts/*.sh - run 'make fmt'"; \
		shfmt -d scripts/*.sh; \
		exit 1; \
	fi

lint: tools
	go vet ./...
	staticcheck ./...

test:
	go test -v -race ./...

gosec: tools
	gosec ./...

gosec-high: tools
	gosec -confidence high -exclude G301,G302,G107,G304 ./...

yamllint-workflows:
	@command -v $(YAMLLINT) >/dev/null 2>&1 || { echo "$(YAMLLINT) not found; run 'make prereqs' for install guidance" >&2; exit 1; }
	$(YAMLLINT) .github/workflows

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

release-sha256: bootstrap-script
	./scripts/generate-sha256sums.sh $(RELEASE_TAG) $(DIST_RELEASE)

release-notes:
	@mkdir -p $(DIST_RELEASE)
	cp RELEASE_NOTES.md $(DIST_RELEASE)/release-notes-$(RELEASE_TAG).md
	@echo "✅ Release notes copied to $(DIST_RELEASE)"

release-sign: release-sha256
	MINISIGN_KEY=$(MINISIGN_KEY) PGP_KEY_ID=$(PGP_KEY_ID) ./scripts/sign-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

release-export-key:
	./scripts/export-release-key.sh $(PGP_KEY_ID) $(DIST_RELEASE)

release-export-minisign-key: build
	@if [ -z "$(MINISIGN_KEY)" ]; then echo "MINISIGN_KEY not set" >&2; exit 1; fi
	@mkdir -p $(DIST_RELEASE)
	@# Extract public key path from secret key (replace .key with .pub)
	@pubkey="$$(echo "$(MINISIGN_KEY)" | sed 's/\.key$$/.pub/')"; \
	if [ -f "$$pubkey" ]; then \
		echo "Verifying $$pubkey is a valid minisign public key..."; \
		./$(BUILD_ARTIFACT) --verify-minisign-pubkey "$$pubkey" || exit 1; \
		cp "$$pubkey" "$(DIST_RELEASE)/$(MINISIGN_PUB_NAME)"; \
		echo "✅ Copied minisign public key to $(DIST_RELEASE)/$(MINISIGN_PUB_NAME)"; \
	else \
		echo "error: public key $$pubkey not found (expected alongside secret key)" >&2; \
		exit 1; \
	fi

verify-minisign-pubkey: build
	@if [ -z "$(FILE)" ]; then echo "usage: make verify-minisign-pubkey FILE=path/to/key.pub" >&2; exit 1; fi
	./$(BUILD_ARTIFACT) --verify-minisign-pubkey "$(FILE)"

verify-release-key:
	./scripts/verify-public-key.sh $(DIST_RELEASE)/$(PUBLIC_KEY_NAME)

release-upload: release-notes verify-release-key
	./scripts/upload-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

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

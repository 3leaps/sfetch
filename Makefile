-include buildconfig.mk

VERSION ?= dev
NAME ?= sfetch
MAIN ?= ./main.go
YAMLLINT ?= yamllint

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

.PHONY: all build test clean install release fmt fmt-check lint tools prereqs bootstrap quality gosec gosec-high yamllint-workflows precommit build-all release-download release-sign release-notes release-upload verify-release-key

all: build

tools:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest

prereqs: tools
	@if command -v $(YAMLLINT) >/dev/null 2>&1; then \
		echo "yamllint available"; \
	else \
		echo "yamllint not found. install via 'brew install yamllint' (macOS), 'sudo apt-get install yamllint' (Debian/Ubuntu), or 'pipx install yamllint'." >&2; \
		exit 1; \
	fi

bootstrap: prereqs

fmt:
	go fmt ./...

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

quality: prereqs fmt-check lint test gosec-high build-all yamllint-workflows

precommit: quality

build:
	mkdir -p bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-trimpath \
		-o $(BUILD_ARTIFACT) $(MAIN)

build-all:
	mkdir -p dist/release
	GOOS=darwin GOARCH=amd64   CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dist/release/$(NAME)-darwin-amd64   $(MAIN)
	GOOS=darwin GOARCH=arm64   CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dist/release/$(NAME)-darwin-arm64   $(MAIN)
	GOOS=linux  GOARCH=amd64   CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dist/release/$(NAME)-linux-amd64     $(MAIN)
	GOOS=linux  GOARCH=arm64   CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dist/release/$(NAME)-linux-arm64     $(MAIN)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dist/release/$(NAME)-windows-amd64.exe $(MAIN)

release: build-all
	# TODO: GitHub release automation
	@echo "Release preparation for $(VERSION)"
	@echo "Build all platforms and prepare assets"

release-download:
	@mkdir -p $(DIST_RELEASE)
	./scripts/download-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

release-notes:
	@mkdir -p $(DIST_RELEASE)
	cp RELEASE_NOTES.md $(DIST_RELEASE)/release-notes-$(RELEASE_TAG).md
	@echo "✅ Release notes copied to $(DIST_RELEASE)"

release-sign:
	./scripts/sign-release-assets.sh $(RELEASE_TAG) $(DIST_RELEASE)

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

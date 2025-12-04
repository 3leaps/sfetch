VERSION ?= dev
NAME ?= sfetch
MAIN ?= ./main.go

# Defaults
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
EXT := 
ifeq ($(GOOS),windows)
EXT := .exe
endif

.PHONY: all build test clean install release fmt lint tools quality gosec gosec-high precommit build-all

all: build

tools:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest

fmt:
	go fmt ./...

lint: tools
	go vet ./...
	staticcheck ./...

test:
	go test -v -race ./...

gosec: tools
	gosec ./...

gosec-high: tools
	gosec -confidence high -exclude G301,G302,G107,G304 ./...

quality: tools fmt lint test gosec-high build-all

precommit: quality

build:
	mkdir -p bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-trimpath \
		-o bin/$(NAME)_$(GOOS)_$(GOARCH)$(EXT) $(MAIN)

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

clean:
	rm -rf bin/ dist/ coverage.out

install: build
	sudo install bin/$(NAME)_$(GOOS)_$(GOARCH)$(EXT) /usr/local/bin/$(NAME)$(EXT)VERSION=2025.12.04

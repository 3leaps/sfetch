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

.PHONY: all build test clean install release fmt lint build-all

all: build

build:
	mkdir -p bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-trimpath \
		-o bin/$(NAME)_$(GOOS)_$(GOARCH)$(EXT) $(MAIN)

test:
	go test -v -race ./...

fmt:
	go fmt ./...

lint:
	go vet ./...

clean:
	rm -rf bin/ dist/

install: build
	sudo install bin/$(NAME)_$(GOOS)_$(GOARCH)$(EXT) /usr/local/bin/$(NAME)$(EXT)

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
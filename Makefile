BINARY := bin/awssync
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= unknown
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: build test race fmt fmt-check vet vuln ci

build:
	mkdir -p $(dir $(BINARY))
	go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/awssync

test:
	go test ./...

race:
	go test -race ./...

fmt:
	gofmt -w ./cmd ./internal

fmt-check:
	test -z "$$(gofmt -l ./cmd ./internal)"

vet:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

ci: fmt-check vet test race vuln build

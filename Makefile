BINARY := bin/awssync

.PHONY: build test fmt vet ci

build:
	go build -o $(BINARY) ./cmd/awssync

test:
	go test ./...

fmt:
	gofmt -w ./cmd ./internal

vet:
	go vet ./...

ci: fmt vet test build

# TRACE — Go binary build
# Cross-compiles a single self-contained binary for macOS, Linux, and Windows.

GO ?= go
BIN_DIR := bin
MODULE := ./cmd/trace
VERSION := 1.0.1

.PHONY: all build darwin linux windows test vet clean

all: darwin linux windows

# Build for the current platform (e.g. `make build` -> bin/trace)
build:
	$(GO) build -o $(BIN_DIR)/trace $(MODULE)

darwin:
	GOOS=darwin GOARCH=arm64 $(GO) build -o $(BIN_DIR)/trace-darwin-arm64 $(MODULE)
	GOOS=darwin GOARCH=amd64 $(GO) build -o $(BIN_DIR)/trace-darwin-amd64 $(MODULE)

linux:
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BIN_DIR)/trace-linux-amd64 $(MODULE)
	GOOS=linux GOARCH=arm64 $(GO) build -o $(BIN_DIR)/trace-linux-arm64 $(MODULE)

windows:
	GOOS=windows GOARCH=amd64 $(GO) build -o $(BIN_DIR)/trace-windows-amd64.exe $(MODULE)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

clean:
	rm -rf $(BIN_DIR)

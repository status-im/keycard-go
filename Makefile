.PHONY: build

GOBIN = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))build/bin
BIN_NAME="status-hardware-wallet"

build:
	go build -i -o $(GOBIN)/$(BIN_NAME) -v ./cmd/status-hardware-wallet
	@echo "Compilation done."
	@echo "Run \"build/bin/$(BIN_NAME) -h\" to view available commands."

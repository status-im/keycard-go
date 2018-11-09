.PHONY: build

GOBIN = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))build/bin
PROJECT_NAME=hardware-wallet-go
GO_PROJECT_PATH=github.com/status-im/$(PROJECT_NAME)
BIN_NAME=status-hardware-wallet
DOCKER_IMAGE_NAME=status-hardware-wallet-build

build:
	go build -i -o $(GOBIN)/$(BIN_NAME) -v ./cmd/status-hardware-wallet
	@echo "Compilation done."
	@echo "Run \"build/bin/$(BIN_NAME) -h\" to view available commands."

build-docker-image:
	docker build -t $(DOCKER_IMAGE_NAME) -f _assets/Dockerfile .

build-platforms:
	xgo -image $(DOCKER_IMAGE_NAME) --dest $(GOBIN) --targets=linux/amd64,windows/amd64 ./cmd/$(BIN_NAME)

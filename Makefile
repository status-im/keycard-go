.PHONY: test

GOBIN=./build

deps:
	go get -t ./...

test:
	go test -v ./...

keycard-lib: ##@cross-compile Build keycard-go as static library for current platform
	mkdir -p $(GOBIN)/libkeycard
	@echo "Building static library..."
	go build -buildmode c-shared -o $(GOBIN)/libkeycard/libkeycard.so ./cmd/lib
	@echo "Static library built:"
	@ls -la $(GOBIN)/libkeycard/*

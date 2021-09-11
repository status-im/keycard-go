.PHONY: test

GOBIN=./build

deps:
	go get -t ./...

test:
	go test -v ./...

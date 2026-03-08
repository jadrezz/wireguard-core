.DEFAULT_GOAL: lint
.PHONY: lint, build

GOOS ?= linux
GOARCH ?= amd64

lint:
	go fmt ./...
	go vet ./...

build :
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build cmd/main.go
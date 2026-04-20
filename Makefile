BINARY     := rud1-agent
BUILD_DIR  := ./dist
CMD        := ./cmd/rud1-agent

VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.Version=$(VERSION) \
	-X main.Commit=$(COMMIT) \
	-X main.BuildDate=$(BUILD_DATE)

.PHONY: all build build-linux build-pi run clean lint test

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) $(CMD)

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-amd64 $(CMD)

build-pi:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-arm64 $(CMD)

run:
	go run $(CMD)

run-dev:
	RUD1_SIMULATE=1 go run $(CMD)

clean:
	rm -rf $(BUILD_DIR)

lint:
	golangci-lint run ./...

test:
	go test ./...

.DEFAULT_GOAL := build

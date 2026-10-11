MODULE := github.com/OWNER/kazeshini
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0-dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -w -s \
	-X 'main.Version=$(VERSION)' \
	-X 'main.Commit=$(COMMIT)' \
	-X 'main.BuildDate=$(BUILD_DATE)'

BINARY := kazeshini
DIST_DIR := dist

.PHONY: all build build-all test race vet fmt fmt-check lint clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/kazeshini

build-all: clean
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-linux-amd64 ./cmd/kazeshini
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-linux-arm64 ./cmd/kazeshini

test:
	go test -race -v ./...

race: test

vet:
	go vet ./...

fmt:
	gofmt -s -w .

fmt-check:
	@diff=$$(gofmt -s -d .); \
	if [ -n "$$diff" ]; then \
		echo "Formatting issues detected:"; \
		echo "$$diff"; \
		exit 1; \
	fi

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed locally, running go vet..."; \
		go vet ./...; \
	fi

clean:
	rm -f $(BINARY)
	rm -rf $(DIST_DIR)


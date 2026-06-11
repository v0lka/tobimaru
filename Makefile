BINARY_NAME := tobimaru
GO := go
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
BUILD_DIR := bin
WEB_DIR := web
WEB_DIST_DIR := internal/api/web/dist

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X github.com/vkochetkov/tobimaru/internal/version.Version=$(VERSION) \
	-X github.com/vkochetkov/tobimaru/internal/version.Commit=$(COMMIT) \
	-X github.com/vkochetkov/tobimaru/internal/version.Date=$(DATE)

.PHONY: build build-all test test-cover lint run clean fmt tidy web web-deps web-clean lint-web check-web-dist all

all: tidy web-deps web build ## Restore all dependencies, build web and then the Go binary

check-web-dist: ## Ensure a minimal dist/index.html exists for go:embed (non-fatal)
	@if [ ! -f $(WEB_DIST_DIR)/index.html ]; then \
		echo "info: $(WEB_DIST_DIR)/index.html is missing — creating placeholder (run 'make web' to build the dashboard)"; \
		mkdir -p $(WEB_DIST_DIR); \
		echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Tobimaru</title></head><body><h1>Tobimaru WiFi Watchdog</h1><p>The web dashboard has not been built yet. Run <code>make web</code> and restart.</p></body></html>' > $(WEB_DIST_DIR)/index.html; \
	fi

build: check-web-dist ## Build binary for the current platform (embeds web/dist)
ifeq ($(shell $(GO) env GOOS),darwin)
	CGO_LDFLAGS='-Wl,-no_warn_duplicate_libraries' $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/tobimaru
else
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/tobimaru
endif

build-all: check-web-dist ## Cross-compile for all target platforms
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/tobimaru
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/tobimaru
	GOOS=darwin GOARCH=arm64 CGO_LDFLAGS='-Wl,-no_warn_duplicate_libraries' $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/tobimaru

test: ## Run all tests with race detector
ifeq ($(shell $(GO) env GOOS),darwin)
	CGO_LDFLAGS='-Wl,-no_warn_duplicate_libraries' $(GO) test -race -cover -coverprofile=coverage.out ./...
else
	$(GO) test -race -cover -coverprofile=coverage.out ./...
endif

test-cover: test ## Run tests and open coverage report
	$(GO) tool cover -html=coverage.out

GOLANGCI_LINT_VERSION := v2.12.2

lint: ## Run golangci-lint
	@actual=$$(golangci-lint --version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1); \
	if [ "$$actual" != "$(GOLANGCI_LINT_VERSION)" ] && [ "v$$actual" != "$(GOLANGCI_LINT_VERSION)" ] && [ "$$actual" != "v$(GOLANGCI_LINT_VERSION)" ]; then \
		echo "ERROR: golangci-lint version mismatch: expected $(GOLANGCI_LINT_VERSION), got $$actual"; \
		echo "Install with: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)"; \
		exit 1; \
	fi
	golangci-lint run ./...

run: ## Build and run
ifeq ($(shell $(GO) env GOOS),darwin)
	CGO_LDFLAGS='-Wl,-no_warn_duplicate_libraries' $(GO) run -ldflags "$(LDFLAGS)" ./cmd/tobimaru
else
	$(GO) run -ldflags "$(LDFLAGS)" ./cmd/tobimaru
endif

clean: ## Remove build artifacts (keeps committed web/dist)
	rm -rf $(BUILD_DIR) coverage.out

web-clean: ## Remove the embedded SPA bundle (forces rebuild on next make web)
	rm -rf $(WEB_DIST_DIR)

fmt: ## Format all Go source files
	$(GO) fmt ./...

tidy: ## Tidy Go modules
	$(GO) mod tidy

web-deps: ## Install SPA build dependencies (requires Node + npm)
	cd $(WEB_DIR) && npm ci

web: ## Build the SPA into $(WEB_DIST_DIR) (requires Node + npm). Re-run before make build to refresh the bundle.
	cp images/logo-128.png $(WEB_DIR)/public/logo-128.png
	cp images/logo-128.png $(WEB_DIR)/src/assets/logo-128.png
	cd $(WEB_DIR) && npm run build

lint-web: ## Lint SPA sources (requires Node + npm)
	cd $(WEB_DIR) && npm run lint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

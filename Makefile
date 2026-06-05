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

.PHONY: build build-all test test-cover lint run clean fmt tidy web web-deps web-clean lint-web check-web-dist

check-web-dist: ## Warn if web/dist is missing (non-fatal)
	@if [ ! -f $(WEB_DIST_DIR)/index.html ]; then \
		echo "warning: $(WEB_DIST_DIR)/index.html is missing; run 'make web' to rebuild the dashboard"; \
	fi

build: check-web-dist ## Build binary for the current platform (embeds web/dist)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/tobimaru

build-all: check-web-dist ## Cross-compile for all target platforms
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/tobimaru
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/tobimaru
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/tobimaru

test: ## Run all tests with race detector
	$(GO) test -race -cover -coverprofile=coverage.out ./...

test-cover: test ## Run tests and open coverage report
	$(GO) tool cover -html=coverage.out

lint: ## Run golangci-lint
	golangci-lint-v2 run ./...

run: ## Build and run
	$(GO) run -ldflags "$(LDFLAGS)" ./cmd/tobimaru

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
	cd $(WEB_DIR) && npm run build

lint-web: ## Lint SPA sources (requires Node + npm)
	cd $(WEB_DIR) && npm run lint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

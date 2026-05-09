.PHONY: all build test cover lint vuln fmt fuzz clean docker run help

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
PKGS          := ./...
BIN_DIR       := ./bin
VERSION       ?= dev
LDFLAGS       := -s -w -X main.version=$(VERSION)

all: lint vet test build ## Lint, vet, test, build

build: ## Build go-socks5 and hashpass binaries
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/go-socks5 ./cmd/go-socks5
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/hashpass ./cmd/hashpass

test: ## Run tests with race detector
	$(GO) test -race -count=1 $(PKGS)

cover: ## Run tests and produce coverage report
	$(GO) test -race -coverprofile=cover.out -covermode=atomic $(PKGS)
	$(GO) tool cover -html=cover.out -o cover.html

vet: ## Run go vet
	$(GO) vet $(PKGS)

lint: ## Run golangci-lint
	$(GOLANGCI_LINT) run $(PKGS)

vuln: ## Run govulncheck
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck $(PKGS)

fmt: ## Format with gofumpt (falls back to gofmt)
	@command -v gofumpt >/dev/null 2>&1 && gofumpt -l -w . || $(GO) fmt $(PKGS)

fuzz: ## Run all fuzz tests for 30s each
	$(GO) test -run=^$$ -fuzz=FuzzReadRequest -fuzztime=30s ./internal/proxy

docker: ## Build Docker image
	docker build --build-arg VERSION=$(VERSION) -t go-socks5:$(VERSION) .

run: build ## Run the proxy with the local config
	$(BIN_DIR)/go-socks5 -c config.toml

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) cover.out cover.html

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*?##/ { printf "  %-12s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: all build clean test fmt vet check install run phase1-smoke help

BINARY_NAME := higgs
MAIN_PACKAGE := ./app/higgs
BUILD_DIR := build
GO := go
# GO_CACHE ?= /tmp/higgs-gocache
# GO_MOD_CACHE ?= /tmp/higgs-gomodcache

# Build flags
LDFLAGS := -s -w
CGO_ENABLED := 0
GO_ENV := CGO_ENABLED=$(CGO_ENABLED)

all: build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO_ENV) $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

clean:
	@rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts"

test:
	$(GO_ENV) $(GO) test -v ./...

fmt:
	$(GO_ENV) $(GO) fmt ./...

vet:
	$(GO_ENV) $(GO) vet ./...

check: fmt vet test build

install:
	$(GO_ENV) $(GO) install $(MAIN_PACKAGE)

run: build
	$(BUILD_DIR)/$(BINARY_NAME)

phase1-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-phase1-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp"; \
	HIGGS_STATE="$$tmp/a.db" $(BUILD_DIR)/$(BINARY_NAME) init a.catofes. >/dev/null; \
	cp "$$tmp/a.db" "$$tmp/b.db"; \
	printf '%s\n' '{"peer_id":"node-a","listen_addr":"127.0.0.1:33434","bootstrap":[{"id":"node-b","addr":"127.0.0.1:33435"}]}' > "$$tmp/a.sync.json"; \
	printf '%s\n' '{"peer_id":"node-b","listen_addr":"127.0.0.1:33435","bootstrap":[{"id":"node-a","addr":"127.0.0.1:33434"}]}' > "$$tmp/b.sync.json"; \
	HIGGS_STATE="$$tmp/b.db" HIGGS_SYNC_CONFIG="$$tmp/b.sync.json" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/b.log" 2>&1 & \
	server_pid="$$!"; \
	trap 'kill "$$server_pid" >/dev/null 2>&1 || true' EXIT; \
	sleep 1; \
	if ! kill -0 "$$server_pid" >/dev/null 2>&1; then cat "$$tmp/b.log"; exit 1; fi; \
	HIGGS_STATE="$$tmp/a.db" $(BUILD_DIR)/$(BINARY_NAME) record put a.catofes. identity node-a >/dev/null; \
	HIGGS_STATE="$$tmp/a.db" HIGGS_SYNC_CONFIG="$$tmp/a.sync.json" $(BUILD_DIR)/$(BINARY_NAME) sync once node-b >/dev/null; \
	HIGGS_STATE="$$tmp/b.db" $(BUILD_DIR)/$(BINARY_NAME) zone show a.catofes. | grep -q '"identity"'; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	echo "Phase1 smoke passed"

help:
	@echo "Available targets:"
	@echo "  build   - Build the higgs binary to $(BUILD_DIR)/"
	@echo "  clean   - Remove build artifacts"
	@echo "  test    - Run all tests"
	@echo "  fmt     - Format Go source code"
	@echo "  vet     - Run go vet"
	@echo "  check   - Run fmt, vet, test, and build"
	@echo "  install - Install higgs to GOPATH/bin"
	@echo "  run     - Build and run higgs"
	@echo "  phase1-smoke - Run a local two-peer gossip smoke test"
	@echo "  help    - Show this help message"

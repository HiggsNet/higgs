.PHONY: all build clean test fmt vet check install run join-smoke phase1-smoke help

BINARY_NAME := higgs
MAIN_PACKAGE := ./app/higgs
BUILD_DIR := build
GO := go
GO_CACHE ?= /tmp/higgs-gocache
GO_MOD_CACHE ?= /tmp/higgs-gomodcache

# Build flags
LDFLAGS := -s -w
CGO_ENABLED := 0
GO_ENV := GOCACHE=$(GO_CACHE) GOMODCACHE=$(GO_MOD_CACHE) CGO_ENABLED=$(CGO_ENABLED)

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

join-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-join-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/node-b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33433' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33434' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/node-b" 'peer_id: node-b' 'listen_addr: 127.0.0.1:33435' > "$$tmp/node-b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. identity node-b >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	echo "Join smoke passed"

phase1-smoke: build
	@set -xeu; \
	tmp="$${TMPDIR:-/tmp}/higgs-phase1-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33433' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33436' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a' 'listen_addr: 127.0.0.1:33434' 'bootstrap:' '  - id: node-b' '    addr: 127.0.0.1:33435' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b' 'listen_addr: 127.0.0.1:33435' 'bootstrap:' '  - id: node-a' '    addr: 127.0.0.1:33434' > "$$tmp/b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-a.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-a.catofes. "$$tmp/node-a.key.json" "$$tmp/node-a.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-a.request.json" "$$tmp/node-a.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-a.bundle.json" "$$tmp/node-a.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/b.log" 2>&1 & \
	server_pid="$$!"; \
	trap 'kill "$$server_pid" >/dev/null 2>&1 || true' EXIT; \
	sleep 1; \
	if ! kill -0 "$$server_pid" >/dev/null 2>&1; then cat "$$tmp/b.log"; exit 1; fi; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. identity node-a >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-b >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. | grep -q '"identity"'; \
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
	@echo "  join-smoke - Run root/delegation/join smoke test"
	@echo "  phase1-smoke - Run a local two-peer gossip smoke test"
	@echo "  help    - Show this help message"

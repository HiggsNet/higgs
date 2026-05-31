.PHONY: all build clean test fmt vet check install run join-smoke phase1-smoke phase2-smoke phase2-run-smoke multi-node-smoke help

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

phase2-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-phase2-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33443' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33446' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a' 'listen_addr: 127.0.0.1:33444' 'bootstrap:' '  - id: node-b' '    addr: 127.0.0.1:33445' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b' 'listen_addr: 127.0.0.1:33445' 'bootstrap:' '  - id: node-a' '    addr: 127.0.0.1:33444' > "$$tmp/b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/a/config.yaml"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/b/config.yaml"; \
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
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. identity node-a >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. identity node-b >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/b.log" 2>&1 & server_pid="$$!"; \
	trap 'kill "$$server_pid" >/dev/null 2>&1 || true' EXIT; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-b >/dev/null; \
	sleep 1; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/a.log" 2>&1 & server_pid="$$!"; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a >/dev/null; \
	sleep 1; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q '"identity"'; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. | grep -q '"identity"'; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status | grep -q 'peer node-b'; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status | grep -q 'peer node-a'; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-a.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-a.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	echo "Phase2 two-node smoke passed"

phase2-run-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-phase2-run-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33463' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33466' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a' 'listen_addr: 127.0.0.1:33464' 'bootstrap:' '  - id: node-b' '    addr: 127.0.0.1:33465' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b' 'listen_addr: 127.0.0.1:33465' 'bootstrap:' '  - id: node-a' '    addr: 127.0.0.1:33464' > "$$tmp/b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/a/config.yaml"; \
	printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/b/config.yaml"; \
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
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. identity node-a >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	b_pid=""; \
	trap 'kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$?" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" 2>/dev/null || true; fi' EXIT; \
	sleep 2; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5; do if HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. | grep -q '"identity"'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. | grep -q '"identity"'; \
	kill "$$b_pid" >/dev/null 2>&1 || true; wait "$$b_pid" >/dev/null 2>&1 || true; b_pid=""; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. identity node-b-restored >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/b-restart.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5; do if HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q 'bm9kZS1iLXJlc3RvcmVk'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q 'bm9kZS1iLXJlc3RvcmVk'; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status | grep -q 'status=online'; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Phase2 sync run smoke passed"

multi-node-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-multi-node-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b" "$$tmp/c"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33453' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33456' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a' 'listen_addr: 127.0.0.1:33454' 'bootstrap:' '  - id: node-b' '    addr: 127.0.0.1:33455' '  - id: node-c' '    addr: 127.0.0.1:33457' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b' 'listen_addr: 127.0.0.1:33455' 'bootstrap:' '  - id: node-a' '    addr: 127.0.0.1:33454' > "$$tmp/b/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/c" 'peer_id: node-c' 'listen_addr: 127.0.0.1:33457' 'bootstrap:' '  - id: node-a' '    addr: 127.0.0.1:33454' > "$$tmp/c/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes a b c; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b c; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-$$node.key.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. identity node-b >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/a.log" 2>&1 & server_pid="$$!"; \
	trap 'kill "$$server_pid" >/dev/null 2>&1 || true' EXIT; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a >/dev/null; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a >/dev/null; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a >/dev/null; \
	sleep 1; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q '"identity"'; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status | grep -q 'peer node-a'; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. identity node-b-restarted >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/a-restart.log" 2>&1 & server_pid="$$!"; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a >/dev/null; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a >/dev/null; \
	sleep 1; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q 'bm9kZS1iLXJlc3RhcnRlZA=='; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q 'bm9kZS1iLXJlc3RhcnRlZA=='; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	echo "Multi-node smoke passed"

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
	@echo "  phase2-smoke - Run bidirectional two-peer sync smoke test"
	@echo "  phase2-run-smoke - Run sync run reconnect/recovery smoke test"
	@echo "  multi-node-smoke - Run three-node transitive sync smoke test"
	@echo "  help    - Show this help message"

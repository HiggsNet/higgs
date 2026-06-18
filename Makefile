.PHONY: all build clean test test-verbose fmt vet check install run smoke smoke-all join-smoke phase1-smoke phase2-smoke phase2-run-smoke phase3-daemon-smoke phase3-daemon-fallback-smoke admin-daemon-smoke multi-node-smoke chain-relay-smoke discovery-smoke reflector-smoke bootstrap-join-smoke nat-observed-smoke nat-daemon-observed-smoke delegation-revoke-smoke object-pull-smoke chunk-fallback-smoke ipsec-policy-smoke ipsec-dry-run-smoke routing-dry-run-smoke firewall-dry-run-smoke ipsec-xfrm-preflight ipsec-xfrm-smoke ipsec-xfrm-container-smoke bird-babel-preflight bird-babel-smoke bird-babel-container-smoke help

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
SMOKE_TARGETS := join-smoke phase1-smoke phase2-smoke phase2-run-smoke phase3-daemon-smoke phase3-daemon-fallback-smoke admin-daemon-smoke multi-node-smoke chain-relay-smoke discovery-smoke reflector-smoke bootstrap-join-smoke nat-observed-smoke nat-daemon-observed-smoke delegation-revoke-smoke object-pull-smoke chunk-fallback-smoke ipsec-policy-smoke ipsec-dry-run-smoke routing-dry-run-smoke firewall-dry-run-smoke

all: build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO_ENV) $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

clean:
	@rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts"

test:
	$(GO_ENV) $(GO) test ./...

test-verbose:
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

smoke: smoke-all

smoke-all: $(SMOKE_TARGETS)
	@echo "All smoke tests passed"

ipsec-xfrm-preflight:
	@docs/scripts/ipsec-xfrm-preflight.sh

ipsec-xfrm-smoke: build
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/ipsec-xfrm-smoke.sh

ipsec-xfrm-container-smoke:
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/ipsec-xfrm-container-smoke.sh

bird-babel-preflight:
	@docs/scripts/bird-babel-preflight.sh

bird-babel-smoke: build
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/bird-babel-smoke.sh

bird-babel-container-smoke:
	@GO="$(GO)" GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MOD_CACHE)" CGO_ENABLED="$(CGO_ENABLED)" docs/scripts/bird-babel-container-smoke.sh

ipsec-dry-run-smoke:
	$(GO_ENV) $(GO) test ./pkg/transport/ipsec
	@echo "IPsec dry-run smoke passed"

routing-dry-run-smoke:
	$(GO_ENV) $(GO) test ./app/higgs -run 'Test(RoutingDryRunSmoke|IPAMRoutingSmoke|AutoAnnounceAssignedIPsRoutingSmoke)' -v
	@echo "Routing dry-run smoke passed"

ipsec-policy-smoke:
	$(GO_ENV) $(GO) test ./pkg/transport/ipsec -run 'Test(ParseMeshPolicy|PlanTransportLinksAppliesMeshPolicyRules)'
	@echo "IPsec policy smoke passed"

firewall-dry-run-smoke:
	$(GO_ENV) $(GO) test ./pkg/firewall
	$(GO_ENV) $(GO) test ./app/higgs -run 'Test(ParseConfigYAMLFirewall|TestFirewallInstancesEnabled|TestFirewallInstanceSpecFromConfig|TestReconcileFirewall|TestDebugFirewall)' -v
	@echo "Firewall dry-run smoke passed"

# Smoke 目标约定：
# - 每个 smoke 都在 $TMPDIR 下创建独立目录，避免重复运行时复用密钥、
#   bbolt 状态、sync peer 元数据或残留 control socket。
# - 信任链必须显式表达：root admin 只管理 "."；catofes. 是被 root 委派
#   的管理 Zone；普通节点再由 catofes. 委派。
# - 现代 gossip peer_id 应默认等于节点管理的 Zone FQDN，例如
#   node-a.catofes.；仍使用短 peer_id 的旧目标只保留兼容性检查语义。
# - 非 root 配置都写入 trusted_root_public_key，使测试能捕获错误 root 或
#   缺失 root 状态，而不是误信任本地 authority。
# - 部分 sync-once smoke 会允许 "pending zones" 后再断言最终状态：
#   sync once 不能在对端还有对象待拉取时宣称完全收敛，但当前单向传输
#   目标本身可能已经成功。

# join-smoke 流程：
# 1. 创建隔离的 root admin、catofes 管理端和 node-b 数据目录。
# 2. root admin 初始化 "."，catofes. 生成 join request 并由 root 签发 delegation。
# 3. catofes. 导入 bundle 成为管理 Zone，再为 node-b.catofes. 签发 leaf delegation。
# 4. node-b 导入 bundle，写入 identity record，并用 verify 检查本地信任链。
# 5. 该目标不启动 UDP，只验证离线准入、密钥、bundle 和本地持久化。
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

# phase1-smoke 流程：
# 1. 创建 root、catofes、node-a、node-b 四个隔离状态目录。
# 2. 建立 "." -> catofes. -> node-a/node-b 的完整 delegation chain。
# 3. join bundle 只携带各节点自己的最小 trust chain；对端状态通过同步获取。
# 4. 启动 node-b 的 sync serve，node-a 写入 identity 后执行一次 sync once。
# 5. sync once 允许 pending zones；最终只断言 B 已收到并可展示 A 的 record。
phase1-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-phase1-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33433' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33436' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33434' 'bootstrap:' '  - id: node-b.catofes.' '    addr: 127.0.0.1:33435' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33435' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33434' > "$$tmp/b/config.yaml"; \
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
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-a.bundle.json" "$$tmp/node-a.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/b.log" 2>&1 & \
	server_pid="$$!"; \
	trap 'status="$$?"; kill "$$server_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	if ! kill -0 "$$server_pid" >/dev/null 2>&1; then cat "$$tmp/b.log"; exit 1; fi; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. identity node-a >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-b.catofes. >"$$tmp/a.log" 2>&1 || grep -q 'pending zones' "$$tmp/a.log"; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. | grep -q '"identity"'; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	echo "Phase1 smoke passed"

# phase2-smoke 流程：
# 1. 创建 root、catofes、node-a、node-b，并写入相同 trusted_root_public_key。
# 2. A/B 用最小 join bundle 加入，后续对端 delegation/record 通过同步获得。
# 3. A/B 分别写入自己的 identity record。
# 4. 先启动 B serve 让 A 拉取 B，再启动 A serve 让 B 拉取 A。
# 5. 最后检查双方 zone show、sync status 和 verify，证明双向收敛。
phase2-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-phase2-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33443' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33446' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33444' 'bootstrap:' '  - id: node-b.catofes.' '    addr: 127.0.0.1:33445' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33445' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33444' > "$$tmp/b/config.yaml"; \
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
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-a.bundle.json" "$$tmp/node-a.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. identity node-a >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. identity node-b >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/b.log" 2>&1 & server_pid="$$!"; \
	trap 'status="$$?"; kill "$$server_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-b.catofes. >"$$tmp/a.log" 2>&1 || grep -q 'pending zones' "$$tmp/a.log"; \
	sleep 1; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/a.log" 2>&1 & server_pid="$$!"; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a.catofes. >"$$tmp/b.log" 2>&1 || grep -q 'pending zones' "$$tmp/b.log"; \
	sleep 1; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q '"identity"'; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. | grep -q '"identity"'; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status | grep -q 'peer node-b.catofes.'; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status | grep -q 'peer node-a.catofes.'; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-a.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-a.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	echo "Phase2 two-node smoke passed"

# phase2-run-smoke 流程：
# 1. 准备两节点 delegation chain，并让 A 先写入 identity。
# 2. 启动 A 的 sync run，再延迟启动 B，验证 B 可自动追上 A。
# 3. 停止 B，模拟 peer 离线。
# 4. B 离线修改本地 record 后重新启动 sync run。
# 5. 断言 A 自动收到 B 的新 record，A/B verified state 的 root 一致。
phase2-run-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-phase2-run-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33463' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33466' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33464' 'advertise_addr: 127.0.0.1:33464' 'publish_endpoints: false' 'bootstrap:' '  - id: node-b.catofes.' '    addr: 127.0.0.1:33465' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33465' 'advertise_addr: 127.0.0.1:33465' 'publish_endpoints: false' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33464' > "$$tmp/b/config.yaml"; \
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
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/b-restart.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 2; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5; do if HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. | grep -q '"identity"'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. | grep -q '"identity"'; \
	kill "$$b_pid" >/dev/null 2>&1 || true; wait "$$b_pid" >/dev/null 2>&1 || true; b_pid=""; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. identity node-b-restored >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/b-restart.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5; do if HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q 'bm9kZS1iLXJlc3RvcmVk'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q 'bm9kZS1iLXJlc3RvcmVk'; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	a_root="$$(HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status | awk '/^local_root:/ {print $$2}')"; \
	b_root="$$(HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status | awk '/^local_root:/ {print $$2}')"; \
	[ "$$a_root" = "$$b_root" ]; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Phase2 sync run smoke passed"

# phase3-daemon-smoke 流程：
# 1. 准备 A/B 两节点和可发布的本地 advertise_addr。
# 2. 分别启动 B 和 A 的 daemon，等待 control socket 就绪。
# 3. 通过 A 的 control socket 执行 record put，确认输出显示 via daemon。
# 4. 等待 B 通过 gossip 收到 A 的 record。
# 5. 在 B 上 verify A，证明 daemon 写入和同步路径都有效。
phase3-daemon-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-phase3-daemon-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33520' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33521' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33522' 'advertise_addr: 127.0.0.1:33522' 'bootstrap:' '  - id: node-b.catofes.' '    addr: 127.0.0.1:33523' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33523' 'advertise_addr: 127.0.0.1:33523' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33522' > "$$tmp/b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-$$node.key.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	HIGGS_CONTROL_SOCKET="$$tmp/b/higgs.sock" HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	sleep 4; \
	HIGGS_CONTROL_SOCKET="$$tmp/a/higgs.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/record-put.out" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/a/higgs.sock" ] && [ -S "$$tmp/b/higgs.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/a/higgs.sock" ]; \
	[ -S "$$tmp/b/higgs.sock" ]; \
	for i in 1 2 3 4 5; do if HIGGS_CONTROL_SOCKET="$$tmp/a/higgs.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status --verbose 2>/dev/null | grep -q 'daemon: online'; then break; fi; sleep 1; done; \
	HIGGS_CONTROL_SOCKET="$$tmp/a/higgs.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status --verbose | grep -q 'daemon: online'; \
	HIGGS_CONTROL_SOCKET="$$tmp/a/higgs.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. identity node-a-daemon >"$$tmp/record-put.out"; \
	grep -q 'via daemon' "$$tmp/record-put.out"; \
	for i in 1 2 3 4 5 6 7 8; do if HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. 2>/dev/null | grep -q '"identity"'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. 2>/dev/null | grep -q '"identity"'; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Phase3 daemon smoke passed"

# phase3-daemon-fallback-smoke 流程：
# 1. 准备 A/B 两节点和 advertise_addr。
# 2. 让 A 的 record put 指向不存在的 control socket，验证会回退到直接写 state。
# 3. 启动 B/A daemon，并确认 control socket 与 daemon 状态可用。
# 4. 等待 B 收到 A 在 daemon 启动前写入的 record。
# 5. verify A，确保 fallback 写入不会在 daemon 接管后丢失。
phase3-daemon-fallback-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-phase3-daemon-fallback-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33530' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33531' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33532' 'advertise_addr: 127.0.0.1:33532' 'bootstrap:' '  - id: node-b.catofes.' '    addr: 127.0.0.1:33533' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33533' 'advertise_addr: 127.0.0.1:33533' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33532' > "$$tmp/b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-$$node.key.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	HIGGS_CONTROL_SOCKET="$$tmp/a/missing.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. identity node-a-fallback 2>"$$tmp/fallback.err" >/dev/null; \
	grep -q 'component=control.*event=fallback.*operation=record_put' "$$tmp/fallback.err"; \
	HIGGS_CONTROL_SOCKET="$$tmp/b/higgs.sock" HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	sleep 4; \
	HIGGS_CONTROL_SOCKET="$$tmp/a/higgs.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/fallback.err" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/a/higgs.sock" ] && [ -S "$$tmp/b/higgs.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/a/higgs.sock" ]; \
	[ -S "$$tmp/b/higgs.sock" ]; \
	HIGGS_CONTROL_SOCKET="$$tmp/a/higgs.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status --verbose | grep -q 'daemon: online'; \
	for i in 1 2 3 4 5 6 7 8; do if HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. 2>/dev/null | grep -q '"identity"'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. 2>/dev/null | grep -q '"identity"'; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Phase3 daemon fallback smoke passed"

# admin-daemon-smoke 流程：
# 1. root admin 离线初始化 "."，随后启动 root admin daemon。
# 2. catofes. 生成 join request，并通过 root admin control socket 签发 bundle。
# 3. catofes. 导入 bundle 后启动自己的 daemon。
# 4. node-b 生成 join request，并通过 catofes. control socket 签发 leaf bundle。
# 5. 通过 catofes. control socket 撤销 node-b，验证 revocation 持久化且 direct delegation 被清理。
admin-daemon-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-admin-daemon-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/node-b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33540' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33541' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/node-b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33542' > "$$tmp/node-b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes node-b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONTROL_SOCKET="$$tmp/admin/higgs.sock" HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/admin.log" 2>&1 & admin_pid="$$!"; \
	trap 'status="$$?"; kill "$$admin_pid" "$${catofes_pid:-}" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/admin.log" "$$tmp/catofes.log" "$$tmp/catofes-issue.out" "$$tmp/node-b-issue.out" "$$tmp/revoke.out" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/admin/higgs.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/admin/higgs.sock" ]; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONTROL_SOCKET="$$tmp/admin/higgs.sock" HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >"$$tmp/catofes-issue.out"; \
	grep -q 'via daemon' "$$tmp/catofes-issue.out"; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONTROL_SOCKET="$$tmp/catofes/higgs.sock" HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/catofes.log" 2>&1 & catofes_pid="$$!"; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/catofes/higgs.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/catofes/higgs.sock" ]; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	HIGGS_CONTROL_SOCKET="$$tmp/catofes/higgs.sock" HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >"$$tmp/node-b-issue.out"; \
	grep -q 'via daemon' "$$tmp/node-b-issue.out"; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	HIGGS_CONTROL_SOCKET="$$tmp/catofes/higgs.sock" HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate revoke node-b.catofes. admin-daemon-smoke >"$$tmp/revoke.out"; \
	grep -q 'via daemon' "$$tmp/revoke.out"; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. | grep -q 'revoked'; \
	if HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null 2>&1; then exit 1; fi; \
	kill "$$admin_pid" "$$catofes_pid" >/dev/null 2>&1 || true; \
	echo "Admin daemon smoke passed"

# multi-node-smoke 流程：
# 1. 准备 A/B/C 三节点，A 作为 hub，B/C 只通过 A 同步。
# 2. 所有 leaf 用最小 join bundle 加入；hub 从同步 snapshot 学到其他 leaf。
# 3. B 写入 identity，A serve 后 B 先把状态推给 A。
# 4. C 对 A 执行 sync once，通过 A 学到 B 的 record。
# 5. 停止并重启 A 的 serve 路径，B 写入更高版本 record。
# 6. 断言 A 和 C 都看到 B 的新版本，验证重启恢复和 latest-record 收敛。
multi-node-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-multi-node-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b" "$$tmp/c"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33453' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33456' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33454' 'bootstrap:' '  - id: node-b.catofes.' '    addr: 127.0.0.1:33455' '  - id: node-c.catofes.' '    addr: 127.0.0.1:33457' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33455' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33454' > "$$tmp/b/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/c" 'peer_id: node-c.catofes.' 'listen_addr: 127.0.0.1:33457' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33454' > "$$tmp/c/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes a b c; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b c; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-$$node.key.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; done; \
	for node in a b c; do HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; done; \
	for node in a b c; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. identity node-b >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/a.log" 2>&1 & server_pid="$$!"; \
	trap 'status="$$?"; kill "$$server_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/a-restart.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a.catofes. >"$$tmp/b-to-a.log" 2>&1 || grep -q 'pending zones' "$$tmp/b-to-a.log"; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a.catofes. >"$$tmp/c-to-a.log" 2>&1 || grep -q 'pending zones' "$$tmp/c-to-a.log"; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a.catofes. >"$$tmp/c-to-a-2.log" 2>&1 || grep -q 'pending zones' "$$tmp/c-to-a-2.log"; \
	sleep 1; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q '"identity"'; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status | grep -q 'peer node-a.catofes.'; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. identity node-b-restarted >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/a-restart.log" 2>&1 & server_pid="$$!"; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a.catofes. >"$$tmp/b-to-a-restart.log" 2>&1 || grep -q 'pending zones' "$$tmp/b-to-a-restart.log"; \
	sleep 1; \
	for i in 1 2 3 4 5 6 7 8; do \
		HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a.catofes. >"$$tmp/c-to-a-restart-$$i.log" 2>&1 || grep -q 'pending zones' "$$tmp/c-to-a-restart-$$i.log"; \
		if HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. 2>/dev/null | grep -q 'bm9kZS1iLXJlc3RhcnRlZA=='; then break; fi; \
		sleep 1; \
	done; \
	kill "$$server_pid" >/dev/null 2>&1 || true; \
	wait "$$server_pid" >/dev/null 2>&1 || true; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q 'bm9kZS1iLXJlc3RhcnRlZA=='; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. | grep -q 'bm9kZS1iLXJlc3RhcnRlZA=='; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	echo "Multi-node smoke passed"

# chain-relay-smoke 流程：
# 1. 准备 A-B-C-D 链式拓扑，每个节点只配置相邻 bootstrap。
# 2. 所有 leaf 用最小 join bundle 加入，后续 trust proof 随 snapshot 中继。
# 3. 不预装完整 leaf delegation table，验证 relay 真的能传播必要信任材料。
# 4. A 写入 identity，B/C/D 先启动 sync run，再启动 A。
# 5. 等待 D 收到并 verify A，验证 relay fanout 与周期 digest 收敛。
chain-relay-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-chain-relay-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b" "$$tmp/c" "$$tmp/d"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33473' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33478' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33474' 'bootstrap:' '  - id: node-b.catofes.' '    addr: 127.0.0.1:33475' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33475' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33474' '  - id: node-c.catofes.' '    addr: 127.0.0.1:33476' > "$$tmp/b/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/c" 'peer_id: node-c.catofes.' 'listen_addr: 127.0.0.1:33476' 'bootstrap:' '  - id: node-b.catofes.' '    addr: 127.0.0.1:33475' '  - id: node-d.catofes.' '    addr: 127.0.0.1:33477' > "$$tmp/c/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/d" 'peer_id: node-d.catofes.' 'listen_addr: 127.0.0.1:33477' 'bootstrap:' '  - id: node-c.catofes.' '    addr: 127.0.0.1:33476' > "$$tmp/d/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes a b c d; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b c d; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-$$node.key.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; done; \
	for node in a b c d; do HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; done; \
	for node in a b c d; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. identity node-a-relay >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/c.log" 2>&1 & c_pid="$$!"; \
	HIGGS_CONFIG="$$tmp/d/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/d.log" 2>&1 & d_pid="$$!"; \
	a_pid=""; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" "$$c_pid" "$$d_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/c.log" "$$tmp/d.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do if HIGGS_CONFIG="$$tmp/d/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. | grep -q 'bm9kZS1hLXJlbGF5'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/d/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. | grep -q 'bm9kZS1hLXJlbGF5'; \
	HIGGS_CONFIG="$$tmp/d/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" "$$c_pid" "$$d_pid" >/dev/null 2>&1 || true; \
	echo "Chain relay smoke passed"

# discovery-smoke 流程：
# 1. 准备 A/B/C 三节点，其中 B 不直接静态 bootstrap 到 C。
# 2. C 写入 identity 和 signed endpoint record。
# 3. 启动 A/B/C 的 sync run，让 endpoint record 经 gossip 传播。
# 4. B 通过 verified active state 发现 C，而不是依赖静态配置。
# 5. 用 debug peer 和 sync status --verbose 断言 discovery 对操作者可见。
discovery-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-discovery-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b" "$$tmp/c"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33493' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33498' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a' 'listen_addr: 127.0.0.1:33494' 'bootstrap:' '  - id: node-b' '    addr: 127.0.0.1:33495' '  - id: node-c' '    addr: 127.0.0.1:33497' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b' 'listen_addr: 127.0.0.1:33495' 'bootstrap:' '  - id: node-a' '    addr: 127.0.0.1:33494' > "$$tmp/b/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/c" 'peer_id: node-c' 'listen_addr: 127.0.0.1:33497' 'bootstrap:' '  - id: node-a' '    addr: 127.0.0.1:33494' > "$$tmp/c/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes a b c; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b c; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-$$node.key.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-c.catofes. identity node-c >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 2 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	sleep 2; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 2 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 2 >"$$tmp/c.log" 2>&1 & c_pid="$$!"; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" "$$c_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/c.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
		if HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-c.catofes. 2>/dev/null | grep -q '"identity"'; then break; fi; \
		sleep 1; \
	done; \
	sleep 2; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-c.catofes. 2>/dev/null | grep -q '"identity"'; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-c.catofes. | grep -q 'resolved_addr:'; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status --verbose | grep -q 'discovered peer=node-c.catofes.'; \
	kill "$$a_pid" "$$b_pid" "$$c_pid" >/dev/null 2>&1 || true; \
	echo "Discovery smoke passed"

# reflector-smoke 流程：
# 1. 不启动 shell 拓扑，直接运行相关 Go 测试。
# 2. 验证 public IP reflector 查询和响应解析。
# 3. 验证 reflector 结果进入本地 endpoint candidate 收集。
# 4. 验证 reflector-derived endpoint 可被签名发布。
reflector-smoke:
	$(GO_ENV) $(GO) test -v ./pkg/core/gossip ./app/higgs -run 'Test(QueryPublicIP|CollectLocalEndpointsWithReflectors|ReflectorEndpointPublishSmoke)'

# bootstrap-join-smoke 流程：
# 1. 准备 catofes、node-a、node-b，其中 B 只知道 bootstrap A。
# 2. catofes 以 sync run 启动，提供 UDP gossip 和同端口 TCP object pull。
# 3. A 先从 catofes 同步到 B 的 delegated identity，但还没有 B 的 endpoint。
# 4. A 写入 identity 并启动 sync run，作为 B 的首次接入入口。
# 5. B accept bundle 后启动 sync run，依靠已验证身份入站白名单和 observed reply address。
# 6. 断言 A 看到 B 的 endpoint，B 也看到 A 的既有 record，覆盖首次接入死锁。
bootstrap-join-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-bootstrap-join-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/node-a" "$$tmp/node-b"; \
	catofes_pid=""; a_pid=""; b_pid=""; \
	trap 'status="$$?"; kill "$${catofes_pid:-}" "$${a_pid:-}" "$${b_pid:-}" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/catofes.log" "$$tmp/node-a-bootstrap.log" "$$tmp/node-a.log" "$$tmp/node-b.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33500' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33501' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/node-a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33502' 'bootstrap:' '  - id: zone-catofes-admin' '    addr: 127.0.0.1:33501' > "$$tmp/node-a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/node-b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33503' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33502' > "$$tmp/node-b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes node-a node-b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-a.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-a.catofes. "$$tmp/node-a.key.json" "$$tmp/node-a.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-a.request.json" "$$tmp/node-a.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-a.bundle.json" "$$tmp/node-a.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-b.catofes. "$$tmp/node-b.key.json" "$$tmp/node-b.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-b.request.json" "$$tmp/node-b.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/catofes.log" 2>&1 & catofes_pid="$$!"; \
	sleep 2; \
	if ! kill -0 "$$catofes_pid" >/dev/null 2>&1; then cat "$$tmp/catofes.log"; exit 1; fi; \
	HIGGS_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once zone-catofes-admin >"$$tmp/node-a-bootstrap.log" 2>&1; \
	HIGGS_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. identity node-a >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/node-a.log" 2>&1 & a_pid="$$!"; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-b.bundle.json" "$$tmp/node-b.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/node-b.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5 6 7 8; do \
		if HIGGS_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. 2>/dev/null | grep -q 'sync/endpoint/udp'; then break; fi; \
		sleep 1; \
	done; \
	HIGGS_CONFIG="$$tmp/node-a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. 2>/dev/null | grep -q 'sync/endpoint/udp'; \
	HIGGS_CONFIG="$$tmp/node-b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. 2>/dev/null | grep -q '"identity"'; \
	kill "$$catofes_pid" "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Bootstrap join smoke passed"

# nat-observed-smoke 流程：
# 1. 准备 A/B，其中 B 设置 publish_endpoints: false 模拟 NAT 后节点。
# 2. catofes 以 sync run 启动，提供 UDP gossip 和同端口 TCP object pull。
# 3. A 先从 catofes 同步必要 delegation，再作为 serve 端等待 B。
# 4. B 主动连 A，A 只能记录 observed UDP path，不能生成 durable discovered_addr。
# 5. A 停止 serve 后写入 record，再通过 observed path 对 B 执行 sync once。
# 6. 断言 B 收到 A 的 record，证明无 signed endpoint 时仍可用 verified observed path 返回同步。
nat-observed-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-nat-observed-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33540' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33541' 'publish_endpoints: false' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33542' 'bootstrap:' '  - id: zone-catofes-admin' '    addr: 127.0.0.1:33541' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33543' 'publish_endpoints: false' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33542' > "$$tmp/b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-$$node.key.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/catofes.log" 2>&1 & catofes_pid="$$!"; \
	a_pid=""; b_pid=""; \
	trap 'status="$$?"; kill "$$catofes_pid" "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/catofes.log" "$$tmp/a.log" "$$tmp/b.log" "$$tmp/put.out" "$$tmp/a-to-b.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once zone-catofes-admin >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	kill "$$catofes_pid" >/dev/null 2>&1 || true; wait "$$catofes_pid" >/dev/null 2>&1 || true; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync serve >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	sleep 1; \
	if ! kill -0 "$$a_pid" >/dev/null 2>&1; then cat "$$tmp/a.log"; exit 1; fi; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 60 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5 6 7 8; do if HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. 2>/dev/null | grep -q 'observed_status: active'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'observed_addr: 127.0.0.1:33543'; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'observed_status: active'; \
	if HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'discovered_addr: 127.0.0.1:33543'; then exit 1; fi; \
	kill "$$a_pid" >/dev/null 2>&1 || true; wait "$$a_pid" >/dev/null 2>&1 || true; a_pid=""; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. identity node-a-observed >"$$tmp/put.out"; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-b.catofes. >"$$tmp/a-to-b.log" 2>&1 || grep -q 'pending zones' "$$tmp/a-to-b.log"; \
	for i in 1 2 3 4 5 6 7 8; do if HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. 2>/dev/null | grep -q 'bm9kZS1hLW9ic2VydmVk'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. 2>/dev/null | grep -q 'bm9kZS1hLW9ic2VydmVk'; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "NAT observed path smoke passed"

# nat-daemon-observed-smoke 流程：
# 1. 准备 A/B，其中 B 禁用 endpoint 发布，A 使用 advertise_addr。
# 2. catofes 以 sync run 启动，提供 UDP gossip 和同端口 TCP object pull。
# 3. A 先从 catofes 同步 delegation，再启动 A/B daemon。
# 4. 断言 A 对 B 只记录 observed_addr/observed_status，不产生 discovered_addr。
# 5. 通过 A 的 control socket 写入 record。
# 6. 等待 B 收到并 verify A，确保 daemon 路径与 direct CLI 的 NAT observed 行为一致。
nat-daemon-observed-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-nat-daemon-observed-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33560' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33561' 'publish_endpoints: false' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33562' 'advertise_addr: 127.0.0.1:33562' 'bootstrap:' '  - id: zone-catofes-admin' '    addr: 127.0.0.1:33561' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33563' 'publish_endpoints: false' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33562' > "$$tmp/b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-$$node.key.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 1 >"$$tmp/catofes.log" 2>&1 & catofes_pid="$$!"; \
	a_pid=""; b_pid=""; \
	trap 'status="$$?"; kill "$$catofes_pid" "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/catofes.log" "$$tmp/a.log" "$$tmp/b.log" "$$tmp/record-put.out" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once zone-catofes-admin >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	kill "$$catofes_pid" >/dev/null 2>&1 || true; wait "$$catofes_pid" >/dev/null 2>&1 || true; catofes_pid=""; \
	HIGGS_CONTROL_SOCKET="$$tmp/a/higgs.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	sleep 2; \
	HIGGS_CONTROL_SOCKET="$$tmp/b/higgs.sock" HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 60 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/a/higgs.sock" ] && [ -S "$$tmp/b/higgs.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/a/higgs.sock" ]; \
	[ -S "$$tmp/b/higgs.sock" ]; \
	for i in 1 2 3 4 5 6 7 8; do if HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. 2>/dev/null | grep -q 'observed_status: active'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'observed_addr: 127.0.0.1:33563'; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'observed_status: active'; \
	if HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'discovered_addr: 127.0.0.1:33563'; then echo "FAIL: B should not have discovered_addr" >&2; exit 1; fi; \
	HIGGS_CONTROL_SOCKET="$$tmp/a/higgs.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. identity node-a-nat-daemon >"$$tmp/record-put.out"; \
	grep -q 'via daemon' "$$tmp/record-put.out"; \
	for i in 1 2 3 4 5 6 7 8 9 10; do if HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. 2>/dev/null | grep -q 'bm9kZS1hLW5hdC1kYWVtb24='; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. 2>/dev/null | grep -q 'bm9kZS1hLW5hdC1kYWVtb24='; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "NAT daemon observed path smoke passed"

# delegation-revoke-smoke 流程：
# 1. 准备 A/B/C 和 catofes，其中 B 先发布 identity 与 endpoint record。
# 2. 所有 leaf 用最小 join bundle 加入，后续对端状态和撤销通过同步传播。
# 3. 让 A/C 通过同步信任 B，并确认 B endpoint 进入 discovered peers。
# 4. catofes. 对 node-b.catofes. 写入 parent-authoritative revocation。
# 5. A/C 从 catofes 同步 revocation 后，verify B 必须失败且 debug zone 显示 revoked。
# 6. 断言 A 的 discovered peers 不再包含 B，防止撤销节点通过旧 endpoint 复活。
delegation-revoke-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-delegation-revoke-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b" "$$tmp/c"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33510' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33511' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33512' 'bootstrap:' '  - id: zone-catofes-admin' '    addr: 127.0.0.1:33511' '  - id: node-b.catofes.' '    addr: 127.0.0.1:33513' '  - id: node-c.catofes.' '    addr: 127.0.0.1:33514' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33513' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33512' > "$$tmp/b/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/c" 'peer_id: node-c.catofes.' 'listen_addr: 127.0.0.1:33514' 'bootstrap:' '  - id: zone-catofes-admin' '    addr: 127.0.0.1:33511' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33512' > "$$tmp/c/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes a b c; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b c; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-$$node.key.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; done; \
	for node in b c a; do HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; done; \
	for node in a b c; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. identity node-b >/dev/null; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. sync/endpoint/udp '{"endpoints":[{"address":"127.0.0.1","port":33513,"protocol":"udp"}]}' sync.endpoint >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 60 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	catofes_pid=""; \
	trap 'status="$$?"; kill "$$a_pid" "$$catofes_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/catofes.log" "$$tmp/b-to-a.log" "$$tmp/c-to-a.log" "$$tmp/a-from-catofes.log" "$$tmp/c-from-catofes.log" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	sleep 1; \
	for i in 1 2 3 4 5; do \
		HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a.catofes. >"$$tmp/b-to-a.log" 2>&1 || grep -Eq 'pending zones|sync receive timed out' "$$tmp/b-to-a.log"; \
		if HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. >/dev/null 2>&1; then break; fi; \
		sleep 1; \
	done; \
	for i in 1 2 3 4 5; do \
		HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once node-a.catofes. >"$$tmp/c-to-a.log" 2>&1 || grep -Eq 'pending zones|sync receive timed out' "$$tmp/c-to-a.log"; \
		if HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. >/dev/null 2>&1; then break; fi; \
		sleep 1; \
	done; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status --verbose | grep -q 'discovered peer=node-b.catofes.'; \
	kill "$$a_pid" >/dev/null 2>&1 || true; \
	wait "$$a_pid" >/dev/null 2>&1 || true; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate revoke node-b.catofes. retired >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync run --interval 60 >"$$tmp/catofes.log" 2>&1 & catofes_pid="$$!"; \
	sleep 1; \
	for node in a c; do \
		for i in 1 2 3; do \
			HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync once zone-catofes-admin >"$$tmp/$$node-from-catofes.log" 2>&1 || grep -Eq 'pending zones|gossip peer quota exceeded|sync receive timed out' "$$tmp/$$node-from-catofes.log"; \
			if HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. 2>/dev/null | grep -q 'revoked: true'; then break; fi; \
			sleep 1; \
		done; \
	done; \
	if HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null 2>&1; then exit 1; fi; \
	if HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null 2>&1; then exit 1; fi; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. | grep -q 'revoked: true'; \
	HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug zone node-b.catofes. | grep -q 'revoked: true'; \
	if HIGGS_CONFIG="$$tmp/c/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) sync status --verbose | grep -q 'discovered peer=node-b.catofes.'; then exit 1; fi; \
	kill "$$a_pid" "$$catofes_pid" >/dev/null 2>&1 || true; \
	echo "Delegation revoke smoke passed"

# object-pull-smoke 流程：
# 1. 准备 A/B 两节点并启动双方 daemon。
# 2. A 通过 control socket 写入 3000-byte bigdata record。
# 3. 该 record 超过默认 1200-byte UDP datagram budget，不应通过超大 UDP 发送。
# 4. B 必须通过 digest/metadata gossip 触发 TCP object pull 拉取完整对象。
# 5. 断言 B 能看到 bigdata 并 verify A，证明不依赖 IP fragmentation。
object-pull-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-object-pull-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33540' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: zone-catofes-admin' 'listen_addr: 127.0.0.1:33541' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33542' 'advertise_addr: 127.0.0.1:33542' 'bootstrap:' '  - id: node-b.catofes.' '    addr: 127.0.0.1:33543' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33543' 'advertise_addr: 127.0.0.1:33543' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33542' > "$$tmp/b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-$$node.key.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	HIGGS_CONTROL_SOCKET="$$tmp/b/higgs.sock" HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 30 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	sleep 4; \
	HIGGS_CONTROL_SOCKET="$$tmp/a/higgs.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 30 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/record-put.out" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/a/higgs.sock" ] && [ -S "$$tmp/b/higgs.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/a/higgs.sock" ]; \
	[ -S "$$tmp/b/higgs.sock" ]; \
	large_value="$$(perl -e 'print "x" x 3000')"; \
	HIGGS_CONTROL_SOCKET="$$tmp/a/higgs.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-a.catofes. bigdata "$$large_value" test.data >"$$tmp/record-put.out"; \
	grep -q 'via daemon' "$$tmp/record-put.out"; \
	sleep 3; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. | grep -q 'bigdata'; \
	for i in $$(seq 1 30); do if HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. 2>/dev/null | grep -q 'bigdata'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes. 2>/dev/null | grep -q 'bigdata' || { HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-a.catofes.; exit 1; }; \
	HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-a.catofes. >/dev/null; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Object pull smoke passed"

# chunk-fallback-smoke 流程：
# 1. 准备 A/B（拓扑同 object-pull-smoke，互相 bootstrap）。
# 2. B 的 TCP object pull 端口被临时抢占，导致 B 的 daemon 启动时
#    object pull server 绑定失败（daemon 继续运行，只剩 UDP）。
# 3. A 正常启动 daemon（UDP+TCP）。
# 4. B 通过 control socket 写入 3000-byte bigdata record。
# 5. B 的 UDP gossip 向 A 发出 announce/digest；A 尝试 TCP object pull B
#    失败（connection refused），触发 chunk fallback 路径。
# 6. A 发送 fetch_zone 带 ChunkFallback=true；B 将 zone snapshot 拆成
#    多个 UDP object_chunk 发给 A。
# 7. 断言 A 收到 bigdata，且 A 的 debug peer 显示 chunk_fallbacks > 0。
chunk-fallback-smoke: build
	@set -eu; \
	tmp="$${TMPDIR:-/tmp}/higgs-chunk-fallback-smoke"; \
	rm -rf "$$tmp"; \
	mkdir -p "$$tmp/admin" "$$tmp/catofes" "$$tmp/a" "$$tmp/b"; \
	printf '%s\n' 'data_dir: '"$$tmp/admin" 'peer_id: node-admin' 'listen_addr: 127.0.0.1:33590' > "$$tmp/admin/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/catofes" 'peer_id: catofes.' 'listen_addr: 127.0.0.1:33591' > "$$tmp/catofes/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/a" 'peer_id: node-a.catofes.' 'listen_addr: 127.0.0.1:33592' 'advertise_addr: 127.0.0.1:33592' 'bootstrap:' '  - id: node-b.catofes.' '    addr: 127.0.0.1:33593' > "$$tmp/a/config.yaml"; \
	printf '%s\n' 'data_dir: '"$$tmp/b" 'peer_id: node-b.catofes.' 'listen_addr: 127.0.0.1:33593' 'advertise_addr: 127.0.0.1:33593' 'bootstrap:' '  - id: node-a.catofes.' '    addr: 127.0.0.1:33592' > "$$tmp/b/config.yaml"; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root init >/dev/null; \
	root_key="$$(HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) root pubkey)"; \
	for node in catofes a b; do printf '%s\n' 'trusted_root_public_key: '"$$root_key" >> "$$tmp/$$node/config.yaml"; done; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/catofes.key.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request catofes. "$$tmp/catofes.key.json" "$$tmp/catofes.request.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/admin/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/catofes.request.json" "$$tmp/catofes.bundle.json" >/dev/null; \
	HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/catofes.bundle.json" "$$tmp/catofes.key.json" >/dev/null; \
	for node in a b; do HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) keygen "$$tmp/node-$$node.key.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join request node-$$node.catofes. "$$tmp/node-$$node.key.json" "$$tmp/node-$$node.request.json" >/dev/null; HIGGS_CONFIG="$$tmp/catofes/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) delegate issue "$$tmp/node-$$node.request.json" "$$tmp/node-$$node.bundle.json" >/dev/null; HIGGS_CONFIG="$$tmp/$$node/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) join accept "$$tmp/node-$$node.bundle.json" "$$tmp/node-$$node.key.json" >/dev/null; done; \
	perl -e 'use IO::Socket::INET; my $$s = IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => 33593, Proto => "tcp", Listen => 1, Reuse => 1) or die $$!; sleep 3600' & tcp_blocker_pid="$$!"; \
	sleep 0.5; \
	HIGGS_CONTROL_SOCKET="$$tmp/b/higgs.sock" HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 30 >"$$tmp/b.log" 2>&1 & b_pid="$$!"; \
	sleep 2; \
	kill "$$tcp_blocker_pid" >/dev/null 2>&1 || true; wait "$$tcp_blocker_pid" >/dev/null 2>&1 || true; \
	HIGGS_CONTROL_SOCKET="$$tmp/a/higgs.sock" HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) daemon --interval 30 >"$$tmp/a.log" 2>&1 & a_pid="$$!"; \
	trap 'status="$$?"; kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; if [ "$$status" != 0 ]; then cat "$$tmp/a.log" "$$tmp/b.log" "$$tmp/record-put.out" 2>/dev/null || true; fi; exit "$$status"' EXIT; \
	for i in 1 2 3 4 5; do if [ -S "$$tmp/a/higgs.sock" ] && [ -S "$$tmp/b/higgs.sock" ]; then break; fi; sleep 1; done; \
	[ -S "$$tmp/a/higgs.sock" ]; \
	[ -S "$$tmp/b/higgs.sock" ]; \
	large_value="$$(perl -e 'print "x" x 3000')"; \
	HIGGS_CONTROL_SOCKET="$$tmp/b/higgs.sock" HIGGS_CONFIG="$$tmp/b/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) record put node-b.catofes. bigdata "$$large_value" test.data >"$$tmp/record-put.out"; \
	grep -q 'via daemon' "$$tmp/record-put.out"; \
	for i in 1 2 3 4 5 6 7 8 9 10; do if HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. 2>/dev/null | grep -q 'bigdata'; then break; fi; sleep 1; done; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes. 2>/dev/null | grep -q 'bigdata' || { HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) zone show node-b.catofes.; exit 1; }; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) verify node-b.catofes. >/dev/null; \
	HIGGS_CONFIG="$$tmp/a/config.yaml" $(BUILD_DIR)/$(BINARY_NAME) debug peer node-b.catofes. | grep -q 'datagram_chunk_fallbacks: [1-9]'; \
	kill "$$a_pid" "$$b_pid" >/dev/null 2>&1 || true; \
	echo "Chunk fallback smoke passed"

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
	@echo "  smoke   - Run all smoke tests"
	@echo "  smoke-all - Run all smoke tests"
	@echo "  join-smoke - Run root/delegation/join smoke test"
	@echo "  phase1-smoke - Run a local two-peer gossip smoke test"
	@echo "  phase2-smoke - Run bidirectional two-peer sync smoke test"
	@echo "  phase2-run-smoke - Run sync run reconnect/recovery smoke test"
	@echo "  phase3-daemon-smoke - Run daemon control write and sync smoke test"
	@echo "  phase3-daemon-fallback-smoke - Run daemon-off direct write recovery smoke test"
	@echo "  multi-node-smoke - Run three-node transitive sync smoke test"
	@echo "  chain-relay-smoke - Run four-node chain relay fanout smoke test"
	@echo "  discovery-smoke - Run endpoint discovery smoke test"
	@echo "  reflector-smoke - Run public IP reflector endpoint smoke test"
	@echo "  bootstrap-join-smoke - Run new-node bootstrap admission smoke test"
	@echo "  nat-observed-smoke - Run NAT-style verified observed UDP path smoke test"
	@echo "  nat-daemon-observed-smoke - Run daemon-based NAT observed path smoke test"
	@echo "  admin-daemon-smoke - Run admin daemon delegation issue/revoke smoke test"
	@echo "  delegation-revoke-smoke - Run delegation revocation convergence smoke test"
	@echo "  object-pull-smoke - Run large-record object-pull over TCP smoke test"
	@echo "  chunk-fallback-smoke - Run large-record UDP chunk fallback when TCP object pull is unreachable"
	@echo "  ipsec-policy-smoke - Run IPsec mesh policy URI rule planner smoke test"
	@echo "  ipsec-dry-run-smoke - Run IPsec planner + fake driver reconcile smoke test"
	@echo "  routing-dry-run-smoke - Run Phase 5 routing dry-run smoke test"
	@echo "  firewall-dry-run-smoke - Run Phase 6.3 firewall planner + config dry-run smoke test"
	@echo "  ipsec-xfrm-preflight - Check root/netns/XFRM/StrongSwan prerequisites"
	@echo "  ipsec-xfrm-smoke - Run real StrongSwan/XFRM smoke (requires root, NOT in smoke-all)"
	@echo "  ipsec-xfrm-container-smoke - Run StrongSwan/XFRM smoke in privileged container"
	@echo "  bird-babel-preflight - Check root/netns/BIRD prerequisites"
	@echo "  bird-babel-smoke - Run real BIRD/Babel smoke (requires root, NOT in smoke-all)"
	@echo "  bird-babel-container-smoke - Run BIRD/Babel smoke in privileged container"
	@echo "  help    - Show this help message"

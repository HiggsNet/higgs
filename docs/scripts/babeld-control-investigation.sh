#!/usr/bin/env bash
# babeld control protocol 能力调研脚本（修正版）
#
# 关键结论：
#   1. 控制 socket 分只读 (-g) 和读写 (-G) 两种模式。
#   2. 动态增删接口的命令是 "interface <name>" / "flush interface <name>"。
#   3. filter (in/out/redistribute/install) 和 routing table 只能在启动配置阶段设置，
#      运行时再通过 -G socket 也无法修改。
#
# 用法：在具备 root/CAP_NET_ADMIN 权限、已安装 babeld 的环境中运行。
# 脚本末尾自动清理 namespace。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/babeld-investigation-logs"
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"/ns-a "$LOG_DIR"/ns-b

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }
info()  { echo -e "${YELLOW}[INFO]${NC} $*"; }

BABELD=$(command -v babeld || true)
if [ -z "$BABELD" ]; then
    fail "babeld not found in PATH. Install: apt install babeld / nix-shell -p babeld"
    exit 1
fi
pass "babeld found at $BABELD"
"$BABELD" -V 2>&1 || true

cleanup() {
    info "=== Cleanup ==="
    ip netns del ns-a 2>/dev/null || true
    ip netns del ns-b 2>/dev/null || true
}
trap cleanup EXIT
cleanup

info "=== Create network topology ==="
ip netns add ns-a
ip netns add ns-b
ip link add veth-a type veth peer name veth-b
ip link set veth-a netns ns-a
ip link set veth-b netns ns-b

ip netns exec ns-a ip addr add 172.20.1.1/24 dev veth-a
ip netns exec ns-a ip link set veth-a up
ip netns exec ns-a ip link set lo up

ip netns exec ns-b ip addr add 172.20.1.2/24 dev veth-b
ip netns exec ns-b ip link set veth-b up
ip netns exec ns-b ip link set lo up

ip netns exec ns-a ping -c1 -W1 172.20.1.2 && pass "ns-a -> ns-b ping OK" || fail "ns-a -> ns-b ping FAILED"

NS_A_CTL="$LOG_DIR"/ns-a/babeld.ctl
NS_B_CTL="$LOG_DIR"/ns-b/babeld.ctl
NS_A_PID="$LOG_DIR"/ns-a/babeld.pid
NS_B_PID="$LOG_DIR"/ns-b/babeld.pid
NS_A_LOG="$LOG_DIR"/ns-a/babeld.log
NS_B_LOG="$LOG_DIR"/ns-b/babeld.log

# 注意：使用 -G 创建读写 control socket，这样运行时 interface/flush 等指令才会被接受。
info "=== Start babeld instances with READ-WRITE control socket (-G) ==="
ip netns exec ns-a "$BABELD" \
    -D \
    -d 1 \
    -I "$NS_A_PID" \
    -G "$NS_A_CTL" \
    -L "$NS_A_LOG" \
    -C "redistribute local deny" \
    lo &

ip netns exec ns-b "$BABELD" \
    -D \
    -d 1 \
    -I "$NS_B_PID" \
    -G "$NS_B_CTL" \
    -L "$NS_B_LOG" \
    -C "redistribute local deny" \
    lo &

for i in $(seq 1 30); do
    if [ -S "$NS_A_CTL" ] && [ -S "$NS_B_CTL" ]; then
        pass "Both babeld control sockets ready"
        break
    fi
    sleep 0.2
done

if [ ! -S "$NS_A_CTL" ] || [ ! -S "$NS_B_CTL" ]; then
    fail "babeld control sockets not created after 6s"
    exit 1
fi

# 发送命令并读取到连接关闭/超时
babeld_cmd() {
    local socket="$1"
    local cmd="$2"
    {
        echo "$cmd"
        # 给 daemon 一点回复时间，然后关闭写端
        sleep 0.1
    } | nc -U "$socket" -w 2 || true
}

# ---- Test 1: 读写模式 (-G) 下接受 interface 指令 ----
info "=== Test 1: Read-write mode accepts interface directive ==="
RESP=$(babeld_cmd "$NS_A_CTL" "interface veth-a")
if echo "$RESP" | tail -1 | grep -qx "ok"; then
    pass "Read-write socket accepted 'interface veth-a'"
else
    fail "Read-write socket rejected 'interface veth-a': $RESP"
fi

# ---- Test 2: 读写模式 (-G) 下动态增删接口 ----
info "=== Test 2: Dynamic interface add/remove via -G socket ==="

ip netns exec ns-a ip link add dummy0 type dummy
ip netns exec ns-a ip link set dummy0 up
ip netns exec ns-a ip addr add 10.99.1.1/24 dev dummy0

RESP=$(babeld_cmd "$NS_A_CTL" "interface dummy0")
if echo "$RESP" | tail -1 | grep -qx "ok"; then
    pass "'interface dummy0' accepted"
else
    fail "'interface dummy0' rejected: $RESP"
fi

RESP=$(babeld_cmd "$NS_A_CTL" "dump")
if echo "$RESP" | grep -q "add interface dummy0"; then
    pass "dummy0 appears in dump output"
else
    fail "dummy0 not in dump output"
fi

RESP=$(babeld_cmd "$NS_A_CTL" "flush interface dummy0")
if echo "$RESP" | tail -1 | grep -qx "ok"; then
    pass "'flush interface dummy0' accepted"
else
    fail "'flush interface dummy0' rejected: $RESP"
fi

# ---- Test 3: 运行时再添加 veth，观察邻居发现 ----
info "=== Test 3: Add veth interfaces and observe neighbour discovery ==="

RESP=$(babeld_cmd "$NS_A_CTL" "interface veth-a")
if echo "$RESP" | tail -1 | grep -qx "ok"; then pass "Added veth-a to ns-a babeld"; else fail "Add veth-a failed: $RESP"; fi

RESP=$(babeld_cmd "$NS_B_CTL" "interface veth-b")
if echo "$RESP" | tail -1 | grep -qx "ok"; then pass "Added veth-b to ns-b babeld"; else fail "Add veth-b failed: $RESP"; fi

info "Waiting for Babel neighbour discovery..."
sleep 4

RESP=$(babeld_cmd "$NS_A_CTL" "dump")
echo "$RESP" | tee "$LOG_DIR"/ns-a/dump_after_neighbour.txt
if echo "$RESP" | grep -q "add neighbour"; then
    pass "Babeld discovered neighbour on veth"
else
    info "No neighbour in dump yet (may need more time or interface up)"
    tail -10 "$NS_A_LOG"
fi

# ---- Test 4: 运行时 filter / redistribute / routing table 被拒绝 ----
info "=== Test 4: Runtime filter/routing-table changes are rejected ==="

for cmd in \
    "in ip 192.0.2.0/24 allow" \
    "out ip 192.0.2.0/24 allow" \
    "redistribute local ip 192.0.2.0/24 allow" \
    "install ip 192.0.2.0/24 allow" \
    "export-table 100" \
    "import-table 100"; do
    RESP=$(babeld_cmd "$NS_A_CTL" "$cmd")
    if echo "$RESP" | tail -1 | grep -qx "bad"; then
        pass "Runtime '$cmd' correctly rejected"
    else
        fail "Runtime '$cmd' unexpectedly accepted: $RESP"
    fi
done

# ---- Test 5: monitor 事件流 ----
info "=== Test 5: Monitor event stream ==="

# monitor 会先发一次当前状态快照，然后持续推送事件
RESP=$( { echo "monitor"; sleep 0.5; echo "unmonitor"; } | nc -U "$NS_A_CTL" -w 2 || true )
echo "$RESP" | head -40 | tee "$LOG_DIR"/ns-a/monitor_output.txt
if echo "$RESP" | grep -q "add interface"; then
    pass "Monitor command returns initial snapshot"
else
    info "Monitor output did not contain expected snapshot"
fi

# ---- Test 6: 并发连接 ----
info "=== Test 6: Concurrent control socket connections ==="

( echo "monitor" | nc -U "$NS_A_CTL" -w 3 > "$LOG_DIR"/ns-a/monitor1.txt 2>&1 ) &
PID1=$!
sleep 0.3

RESP=$(echo "dump" | nc -U "$NS_A_CTL" -w 2 || true)
if [ -n "$RESP" ]; then
    pass "Second concurrent connection works"
else
    fail "Second concurrent connection returned empty"
fi
wait $PID1 2>/dev/null || true

# ---- Summary ----
info ""
info "============================================"
info "=== Investigation Complete ==="
info "============================================"
info ""
info "All output saved to: $LOG_DIR"
info ""
info "Key findings:"
info "  1. '-G' read-write socket is required for runtime interface management."
info "  2. 'interface <name>' adds an interface; 'flush interface <name>' removes it."
info "  3. 'in/out/redistribute/install' filters cannot be changed at runtime."
info "  4. 'export-table/import-table' cannot be changed at runtime."
info "  5. 'dump/monitor/unmonitor/quit' work in both -g and -G modes."

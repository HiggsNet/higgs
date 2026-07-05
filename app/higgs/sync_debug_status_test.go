package main

import (
	"bytes"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
	"strings"
	"testing"
	"time"
)

func TestSyncStatusVerboseOutput(t *testing.T) {
	prepareDiagnosticsState(t)

	output := runCLIAndCaptureStdout(t, "higgs", "sync", "status", "--verbose")

	assertOutputContains(t, output,
		"peer_id: node-a.catofes.",
		"listen_addr: 127.0.0.1:0",
		"known_peers: 1",
		"known_zones: 3",
		"limits: max_datagram_bytes=4096 max_sync_zones=8 max_sync_records=64 wire_version=1 wire_codec=msgpack",
		"allowlist_source: bootstrap+discovery",
		"bootstrap_peers: 1",
		"bootstrap peer=node-b.catofes. configured_addr=127.0.0.1:9999 resolved_addr=127.0.0.1:9999",
		"sync_flow peer=node-b.catofes. active_pull=object_pulling active_event=catalog_page active_updated=2023-11-14T22:13:20Z hint_accepted=2 hint_suppressed=1 last_hint=2023-11-14T22:13:20Z hint_reason=announce_hint hint_suppression=session_active read_only_responder=3 responder_kind=chunk_fallback responder_zone=node-b.catofes. responder_last=2023-11-14T22:13:20Z",
		"datagram peer=node-b.catofes. too_large_dropped=2 digest_only_announces=1 chunk_fallbacks=0",
		"object_pull peer=node-b.catofes. attempts=3 successes=2 failures=1 large_object_unreachable=1",
		"zone node-b.catofes.",
	)
}

func TestDebugPeerOutput(t *testing.T) {
	prepareDiagnosticsState(t)

	output := runCLIAndCaptureStdout(t, "higgs", "debug", "peer", "node-b.catofes.")

	assertOutputContains(t, output,
		"peer_id: node-b.catofes.",
		"source: bootstrap",
		"configured_addr: 127.0.0.1:9999",
		"resolved_addr: 127.0.0.1:2000",
		"last_success: 2023-11-14T22:13:20Z",
		"last_error: -",
		"discovered_addr: 127.0.0.1:2000",
		"observed_addr: 127.0.0.1:3000",
		"observed_status: active",
		"last_update_source: node-c.catofes.",
		"active_pull_state: object_pulling",
		"active_pull_last_event: catalog_page",
		"hint_last: 2023-11-14T22:13:20Z reason=announce_hint suppression=session_active",
		"read_only_responder_last: 2023-11-14T22:13:20Z kind=chunk_fallback zone=node-b.catofes.",
		"datagram_too_large_dropped: 2",
		"datagram_last_too_large: 2023-11-14T22:13:20Z direction=send object=record zone=node-b.catofes. key=bigdata bytes=1800 limit=1200",
		"object_pull_attempts: 3",
		"object_pull_last: 2023-11-14T22:13:20Z object=record zone=node-b.catofes. key=bigdata bytes=4096 source_peer=node-b.catofes. unreachable=true error=no TCP address",
	)
}

func TestDebugZoneOutput(t *testing.T) {
	prepareDiagnosticsState(t)

	output := runCLIAndCaptureStdout(t, "higgs", "debug", "zone", "node-b.catofes.")

	assertOutputContains(t, output,
		"zone: node-b.catofes.",
		"records: 1",
		"history: 0",
		"delegations: 0",
		"parent_proof: 0",
		"verify: ok",
		"record key=sync/endpoint/udp version=1 type=sync.endpoint",
	)
}

func TestDebugRecordsOutputFiltersByPrefixAndPrintsValues(t *testing.T) {
	now := time.Unix(1700000000, 0)
	state, _ := buildTestNetworkState(t)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	var out bytes.Buffer
	if err := writeDebugRecords(&out, state, "node-b.catofes.", "ipsec/", true); err != nil {
		t.Fatalf("writeDebugRecords: %v", err)
	}
	output := out.String()
	assertOutputContains(t, output,
		"zones: 1",
		"records: 5",
		"prefix: ipsec/",
		"zone node-b.catofes.",
		"record key=ipsec/overlays/main version=1 type=ipsec.overlay_intent.v1",
		"record key=ipsec/profile version=1 type=ipsec.profile.v1",
		"record key=ipsec/transport-key version=1 type=ipsec.transport_key.v1",
		"value: {",
	)
	if strings.Contains(output, "sync/endpoint/udp") {
		t.Fatalf("debug records prefix leaked endpoint record:\n%s", output)
	}
}

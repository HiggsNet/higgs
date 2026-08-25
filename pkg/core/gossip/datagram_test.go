package gossip

import (
	"bytes"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestPlanSnapshotDatagramsSortsDigestHints(t *testing.T) {
	network := zone.NewNetworkState()
	for _, path := range []zone.ZonePath{"z.catofes.", "a.catofes."} {
		network.Zones[path] = zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
	}
	input := []zone.ZonePath{"z.catofes.", "missing.catofes.", "a.catofes."}
	plan := PlanSnapshotDatagrams(network, input, DefaultDatagramBudget, time.Unix(100, 0))
	if len(plan.Oversized) != 0 || len(plan.Announces) != 1 {
		t.Fatalf("plan = %#v", plan)
	}
	zones := plan.Announces[0].Zones
	if len(zones) != 2 || zones[0].Zone != "a.catofes." || zones[1].Zone != "z.catofes." {
		t.Fatalf("zones = %#v, want sorted digest hints", zones)
	}
	if input[0] != "z.catofes." {
		t.Fatal("PlanSnapshotDatagrams mutated caller zone order")
	}
}

func TestPlanSnapshotDatagramsClassifiesOversizedDigest(t *testing.T) {
	network := zone.NewNetworkState()
	path := zone.ZonePath("node-a.catofes.")
	network.Zones[path] = zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
	plan := PlanSnapshotDatagrams(network, []zone.ZonePath{path}, 1, time.Unix(100, 0))
	if len(plan.Announces) != 0 || len(plan.Oversized) != 1 || plan.Oversized[0].Zone != path {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanSnapshotDatagramsIgnoresRecordPayloadSize(t *testing.T) {
	network := zone.NewNetworkState()
	path := zone.ZonePath("node-a.catofes.")
	state := zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
	state.Records["bigdata"] = &zone.Record{
		Zone: path, Key: "bigdata", Type: "test.data", Value: bytes.Repeat([]byte("x"), 3000), Version: 1,
	}
	network.Zones[path] = state

	plan := PlanSnapshotDatagrams(network, []zone.ZonePath{path}, DefaultDatagramBudget, time.Unix(100, 0))
	if len(plan.Oversized) != 0 || len(plan.Announces) != 1 || len(plan.Announces[0].Zones) != 1 {
		t.Fatalf("plan = %#v, want one digest-only announce", plan)
	}
	if size := AnnounceWireSize(plan.Announces[0]); size > DefaultDatagramBudget {
		t.Fatalf("announce wire size = %d, want <= %d", size, DefaultDatagramBudget)
	}
}

func TestPackDigestAnnouncesRespectsBudget(t *testing.T) {
	var digests []corestate.ZoneDigest
	for i := range 20 {
		digests = append(digests, corestate.ZoneDigest{Zone: zone.ZonePath(string(rune('a'+i)) + ".catofes."), RootHash: bytes.Repeat([]byte{byte(i)}, 32)})
	}
	announces := PackDigestAnnounces(digests, 300)
	if len(announces) < 2 {
		t.Fatalf("announces = %d, want multiple batches", len(announces))
	}
	var count int
	for _, announce := range announces {
		if size := AnnounceWireSize(announce); size > 300 {
			t.Fatalf("announce wire size = %d, want <= 300", size)
		}
		count += len(announce.Zones)
	}
	if count != len(digests) {
		t.Fatalf("packed digests = %d, want %d", count, len(digests))
	}
}

func TestBuildZoneSnapshotChunksFitsWireBudgetAndRoundTrips(t *testing.T) {
	snapshot := &corestate.ZoneSnapshot{
		Zone:      "node-a.catofes.",
		Authority: &zone.ZoneAuthority{Zone: "node-a.catofes.", Epoch: 1, Threshold: 1},
		Records: map[string]*zone.Record{
			"large": {Zone: "node-a.catofes.", Key: "large", Value: bytes.Repeat([]byte("x"), 3000)},
		},
	}
	id := []byte("0123456789abcdef")
	chunks, err := BuildZoneSnapshotChunks(snapshot, DefaultDatagramBudget, "sender.catofes.", id)
	if err != nil {
		t.Fatalf("BuildZoneSnapshotChunks: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("chunks = %d, want chunked object", len(chunks))
	}
	var encoded []byte
	for i, chunk := range chunks {
		if chunk.Index != uint16(i) || int(chunk.Total) != len(chunks) || !bytes.Equal(chunk.TransferID, id) {
			t.Fatalf("chunk[%d] metadata = %#v", i, chunk)
		}
		message := &Message{Type: MessageObjectChunk, PeerID: "sender.catofes.", Nonce: ^uint64(0), Timestamp: int64(^uint64(0) >> 1), ObjectChunk: chunk}
		if size := MessageWireSize(message); size > DefaultDatagramBudget {
			t.Fatalf("chunk[%d] wire size = %d, want <= %d", i, size, DefaultDatagramBudget)
		}
		encoded = append(encoded, chunk.Data...)
	}
	decoded, err := DecodeZoneSnapshotObject(encoded)
	if err != nil {
		t.Fatalf("DecodeZoneSnapshotObject: %v", err)
	}
	if decoded.Zone != snapshot.Zone || len(decoded.Records["large"].Value) != 3000 {
		t.Fatalf("decoded snapshot = %#v", decoded)
	}
}

func TestBuildZoneSnapshotChunksRejectsTransferIDAndTinyBudget(t *testing.T) {
	snapshot := &corestate.ZoneSnapshot{Zone: "node-a.catofes.", Authority: &zone.ZoneAuthority{Zone: "node-a.catofes."}}
	if _, err := BuildZoneSnapshotChunks(snapshot, DefaultDatagramBudget, "sender", []byte("short")); err == nil {
		t.Fatal("short transfer ID accepted")
	}
	if _, err := BuildZoneSnapshotChunks(snapshot, 1, "sender", []byte("0123456789abcdef")); err == nil {
		t.Fatal("tiny datagram budget accepted")
	}
}

package gossip

import (
	"errors"
	"testing"
	"time"
)

func TestEngineOwnsSessionsAndPlansInbound(t *testing.T) {
	engine := NewEngine()
	session := engine.NewSession("peer-a")
	if engine.Session("peer-a") != session || !engine.HasActiveSession("peer-a") {
		t.Fatal("engine did not retain active session")
	}
	actions := engine.PlanInbound(&Packet{Message: &Message{Type: MessagePong, PeerID: "peer-a", Pong: &Pong{}}})
	if len(actions) != 1 || actions[0].Kind != InboundPostSessionEvent {
		t.Fatalf("actions = %#v, want active PONG session event", actions)
	}
	engine.RemoveSession("peer-a")
	if engine.Session("peer-a") != nil {
		t.Fatal("session remains after RemoveSession")
	}
}

func TestEngineHandleEventAndProtocolFailure(t *testing.T) {
	engine := NewEngine()
	session := engine.NewSession("peer-a")
	now := time.Unix(100, 0)
	result := engine.HandleEvent(&SyncTimerEvent{PeerID: "peer-a", LocalSummary: &CatalogSummary{}}, now)
	if !result.Accepted || result.Session != session || result.OldState != SyncSessionIdle || session.State != SyncSessionSummarySent {
		t.Fatalf("result = %#v session=%#v", result, session)
	}
	unknown := engine.HandleEvent(&PacketEvent{}, now)
	if unknown.Accepted || unknown.PeerID != "" {
		t.Fatalf("unknown result = %#v, want rejected", unknown)
	}

	bad := &CatalogPageReceivedEvent{PeerID: "peer-a", Page: &CatalogPage{CatalogRoot: []byte("wrong")}}
	result = engine.HandleEvent(bad, now)
	if !result.Accepted || result.Err != nil {
		// This event is ignored in summary-sent without a prior remote root;
		// explicit Fail below locks the engine's retained-session behavior.
		t.Fatalf("catalog result = %#v", result)
	}
	session.Fail(errors.New("failed"))
	if engine.HasActiveSession("peer-a") {
		t.Fatal("failed session reported active")
	}
}

func TestEnginePendingHints(t *testing.T) {
	engine := NewEngine()
	engine.DeferHint("peer-a")
	if !engine.PendingHint("peer-a") || !engine.TakePendingHint("peer-a") || engine.PendingHint("peer-a") {
		t.Fatal("pending hint lifecycle failed")
	}
}

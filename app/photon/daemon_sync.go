package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// EnableEventLoopSync configures the event-loop gossip.SyncSession clock. The
const syncIngressRouteTTL = time.Minute

type syncIngressRoute struct {
	addr  *net.UDPAddr
	until time.Time
}

// objectPullTCPAddr derives the TCP object-pull address from a gossip UDP
// endpoint. TCP and UDP intentionally share the numeric port.
func objectPullTCPAddr(udpAddr string) string {
	udp, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return ""
	}
	return (&net.TCPAddr{IP: udp.IP, Port: udp.Port}).String()
}

func (d *DaemonService) objectPullResponse(req *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
	if d == nil || d.StateStore == nil {
		return &gossip.ObjectPullResponse{Error: "invalid request"}
	}
	view := d.StateStore.common.ReadView()
	var network *zone.NetworkState
	if view.State != nil {
		network = view.State.Network
	}
	response := gossip.BuildObjectPullResponse(network, req, time.Now())
	if req != nil && response != nil && response.OK && response.Snapshot != nil {
		encoded, _ := gossip.EncodeZoneSnapshotObject(response.Snapshot)
		d.logDebug("object_pull", "lookup_snapshot", map[string]any{
			"zone": req.Zone.String(), "records": len(response.Snapshot.Records), "bytes": len(encoded),
		})
	}
	return response
}

func newDaemonObjectPullExecutor(d *DaemonService) *corehost.GossipObjectPullExecutor {
	return corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{
		Client:    photonlinux.GossipObjectPullClient{},
		Discovery: d.currentGossipDiscoveryInput,
		Now:       d.Sync.now,
		ObserveAttempt: func(peerID string, path zone.ZonePath, now time.Time) {
			d.observeObjectPullAttempt(peerID, path, now)
			d.logDebug("object_pull", "worker_start", map[string]any{"peer_id": peerID, "zone": path.String()})
		},
		ObserveResult: func(result corehost.GossipObjectPullDiagnostics) {
			d.observeObjectPullResult(result)
			errorText := ""
			if result.Err != nil {
				errorText = result.Err.Error()
			}
			d.logDebug("object_pull", "worker_done", map[string]any{
				"peer_id": result.PeerID, "zone": result.Zone.String(), "ok": result.Err == nil,
				"bytes": result.Bytes, "error": errorText,
			})
		},
	})
}

// startObjectPullServer binds the platform listener and gives its lifecycle to
// HostRuntime.
func startObjectPullServer(ctx context.Context, d *DaemonService) error {
	if d == nil || d.Sync == nil || d.Sync.Transport == nil || d.hostRuntime == nil {
		return errors.New("object-pull server runtime is not configured")
	}
	addr := objectPullTCPAddr(d.Sync.Transport.LocalAddr().String())
	if addr == "" {
		return nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if err := d.hostRuntime.StartGossipObjectPullServer(ctx, listener, d.objectPullResponse, 0, 0); err != nil {
		_ = listener.Close()
		return err
	}
	d.logInfo("object_pull", "serve_started", map[string]any{"addr": listener.Addr()})
	return nil
}

// event-loop sync path is the only daemon sync path; this helper remains for
// tests that need a fake clock.
func (d *DaemonService) EnableEventLoopSync(clock corehost.Clock) {
	if clock == nil {
		if d.Sync != nil && d.Sync.App != nil && d.Sync.App.Clock != nil {
			clock = corehost.NewClock(d.Sync.App.Clock)
		} else {
			clock = corehost.NewClock(nil)
		}
	}
	if d.hostRuntime == nil {
		d.hostRuntime = corehost.NewRuntime(clock, corehost.DefaultEventBuffer)
		return
	}
	d.hostRuntime.ResetScheduler(clock)
}

func (d *DaemonService) handleSyncTimerEvent(ctx context.Context, force bool) error {
	if d == nil || d.Sync == nil {
		return nil
	}
	now := d.Sync.now()
	input := d.currentGossipDiscoveryInput()
	peers := corehost.GossipOutboundPeers(input, now)
	if len(peers) == 0 {
		return nil
	}
	summary := corestate.CatalogSummaryFor(input.Network)
	d.logDebug("sync", "event_loop_timer", map[string]any{
		"peer_count": len(peers),
		"force":      force,
	})
	for _, peerID := range peers {
		if !force && corehost.GossipBackoffRemaining(input.Peers[peerID], now) > 0 {
			d.logDebug("sync", "event_loop_skipped", map[string]any{
				"peer_id": peerID,
				"reason":  "backoff",
			})
			continue
		}
		if d.hostRuntime.Gossip.HasActiveSession(peerID) {
			d.logDebug("sync", "event_loop_skipped", map[string]any{
				"peer_id": peerID,
				"reason":  "session_active",
			})
			continue
		}
		d.hostRuntime.Gossip.NewSession(peerID)
		event := &gossip.SyncTimerEvent{
			PeerID:       peerID,
			LocalSummary: summary,
		}
		// This function already runs on the daemon event-loop goroutine. Execute
		// the initial event directly so a saturated internal event queue cannot
		// leave an idle session behind forever. Such a zombie session suppresses
		// every later periodic/bootstrap retry as "session_active".
		d.handleSyncEvent(ctx, event)
	}
	return nil
}

func (d *DaemonService) handlePacketEventSyncSession(packet *gossip.Packet, ctx context.Context) error {
	if packet != nil && packet.Message != nil && d != nil && d.Sync != nil {
		msg := packet.Message
		now := d.Sync.now()
		d.rememberSyncIngressRoute(msg.PeerID, packet.Addr, now)
		if d.recordVerifiedObservedCheckpoint(msg.PeerID, packet.Addr, now) {
			recordObservedSource(d.PeerObservability, msg.PeerID, msg.Type, now)
		}
		d.seedObservedPeerPath(msg.PeerID)
	}
	controller := &daemonGossipActionController{
		daemon:    d,
		now:       d.Sync.now(),
		limits:    syncLimits(d.Sync.Config),
		replyAddr: packet.Addr,
	}
	return d.hostRuntime.ExecuteGossipInbound(ctx, d.hostRuntime.Gossip.PlanInbound(packet), controller)
}

func (d *DaemonService) recordVerifiedObservedCheckpoint(peerID string, addr *net.UDPAddr, now time.Time) bool {
	if d == nil || d.StateStore == nil || addr == nil || peerID == "" {
		return false
	}
	patch, ok := corehost.PlanVerifiedObservedCheckpoint(d.currentGossipDiscoveryInput(), peerID, addr.String(), now)
	if !ok {
		return false
	}
	_, err := d.StateStore.UpdatePeerCheckpoint(context.Background(), peerID, patch)
	if err != nil {
		d.logWarn("sync", "observed_checkpoint_commit_failed", map[string]any{"peer_id": peerID, "error": err})
		return false
	}
	return true
}

func (d *DaemonService) handleAnnounceHint(peerID string) error {
	if d == nil || d.Sync == nil || peerID == "" {
		return nil
	}
	now := d.Sync.now()
	if d.hostRuntime.Gossip.HasActiveSession(peerID) {
		d.hostRuntime.Gossip.DeferHint(peerID)
		recordSyncHint(d.PeerObservability, peerID, "announce_hint", "session_active", false, now)
		d.logDebug("sync", "announce_hint_suppressed", map[string]any{
			"peer_id": peerID,
			"reason":  "session_active",
		})
		return nil
	}
	return d.startHintedSyncSession(peerID, "announce_hint")
}

func (d *DaemonService) startHintedSyncSession(peerID, reason string) error {
	if d == nil || d.Sync == nil || peerID == "" {
		return nil
	}
	now := d.Sync.now()
	view := d.StateStore.common.ReadView()
	if view.State == nil || view.State.Network == nil {
		return nil
	}
	summary := corestate.CatalogSummaryFor(view.State.Network)
	session := d.hostRuntime.Gossip.NewSession(peerID)
	if err := d.hostRuntime.PostGossip(&gossip.SyncTimerEvent{
		PeerID:       peerID,
		LocalSummary: summary,
	}); err != nil {
		d.logWarn("sync", "event_dropped", map[string]any{"reason": "sync_events_full"})
		d.hostRuntime.Gossip.RemoveSession(peerID)
		return err
	}
	recordSyncHint(d.PeerObservability, peerID, reason, "", true, now)
	recordSyncActivePull(d.PeerObservability, peerID, "hint_queued", session, now)
	d.logDebug("sync", "hinted_sync_started", map[string]any{
		"peer_id": peerID,
		"reason":  reason,
	})
	return nil
}
func (d *DaemonService) postSyncEvent(event gossip.SyncEvent) error {
	return d.hostRuntime.PostGossip(event)
}

func (d *DaemonService) respondFetchZoneTo(peerID string, path zone.ZonePath, replyAddr *net.UDPAddr) error {
	if d == nil || d.Sync == nil {
		return nil
	}
	budget := d.syncDatagramBudget()
	view := d.StateStore.common.ReadView()
	if view.State == nil || view.State.Network == nil || view.State.Network.Zones[path] == nil {
		d.logDebug("sync", "fetch_zone_snapshot_missing", map[string]any{
			"peer_id": peerID,
			"zone":    path,
			"error":   zone.ErrZoneNotFound,
			"via":     "responder",
		})
		return nil
	}
	plan := gossip.PlanSnapshotDatagrams(view.State.Network, []zone.ZonePath{path}, budget, d.Sync.now())
	return d.respondAnnouncePlanTo(peerID, plan, budget, replyAddr)
}

func (d *DaemonService) respondFetchZoneChunksTo(peerID string, path zone.ZonePath, replyAddr *net.UDPAddr) error {
	if d == nil || d.Sync == nil || d.Sync.Transport == nil {
		return nil
	}
	now := d.Sync.now()
	view := d.StateStore.common.ReadView()
	if view.State == nil || view.State.Network == nil || view.State.Network.Zones[path] == nil {
		return nil
	}
	network := view.State.Network
	plan := gossip.PlanSnapshotDatagrams(network, []zone.ZonePath{path}, d.syncDatagramBudget(), now)
	if network.IsZoneRevoked(path, now) {
		return nil
	}
	snapshot, err := corestate.Snapshot(network, path)
	if err != nil {
		return nil
	}
	diag, err := sendDetachedSnapshotWithDiagnosticsTo(snapshot, plan, d.Sync.Transport, peerID, replyAddr, now, d.Sync.logger())
	recordDatagramSendDiagnostics(d.PeerObservability, peerID, diag, d.syncDatagramBudget(), now)
	return err
}

func (d *DaemonService) respondAnnouncePlanTo(peerID string, plan gossip.DatagramPlan, budget int, replyAddr *net.UDPAddr) error {
	if d == nil || d.Sync == nil {
		return nil
	}
	for _, oversized := range plan.Oversized {
		recordDatagramTooLarge(d.PeerObservability, peerID, "send", oversized.Object, oversized.Zone, oversized.Key, oversized.Size, budget, d.Sync.now())
		d.logDebug("transport", "datagram_too_large", map[string]any{
			"peer_id": peerID,
			"object":  oversized.Object,
			"zone":    oversized.Zone,
			"key":     oversized.Key,
			"bytes":   oversized.Size,
			"limit":   budget,
			"via":     "responder",
		})
	}
	for _, announce := range plan.Announces {
		if announce == nil {
			continue
		}
		d.logInfo("sync", "sending_announce", map[string]any{
			"peer_id": peerID,
			"digests": len(announce.Zones),
			"via":     "responder",
		})
		d.sendSyncMessageTo(peerID, replyAddr, &gossip.Message{
			Type:     gossip.MessageAnnounce,
			Announce: announce,
		})
	}
	return nil
}

func (d *DaemonService) handleSyncEvent(ctx context.Context, event gossip.SyncEvent) bool {
	peerID := gossip.SyncEventPeerID(event)
	eventNow := d.Sync.now()
	mutations := newSyncPeerStateMutationBatch(peerID)
	controller := &daemonGossipActionController{
		daemon: d, mutations: mutations, now: eventNow, limits: syncLimits(d.Sync.Config),
	}
	result, err := d.hostRuntime.HandleGossipEvent(ctx, event, eventNow, controller)
	if err != nil {
		d.logDebug("sync", "event_dropped", map[string]any{"peer_id": peerID, "error": err})
		return false
	}
	session := d.hostRuntime.Gossip.Session(peerID)
	if result.ProtocolErr != nil {
		d.logWarn("sync", "session_event_error", map[string]any{
			"peer_id": peerID,
			"error":   result.ProtocolErr,
		})
	}
	eventName := gossip.SyncEventName(event)
	activeSession := &gossip.SyncSession{State: session.State}
	recordSyncActivePull(d.PeerObservability, peerID, eventName, activeSession, eventNow)
	if result.NewState != result.OldState {
		d.logDebug("sync", "session_state_changed", map[string]any{
			"peer_id":   peerID,
			"event":     fmt.Sprintf("%T", event),
			"old_state": result.OldState,
			"new_state": result.NewState,
			"pending":   result.Pending,
			"inflight":  result.Inflight,
		})
	}
	if result.Done {
		mutations.addCompletion(session, eventNow)
	}
	mutations.commit(d)
	if result.Done {
		d.completeSyncSessionAfterPeerState(session, session.NetworkChanged())
	}
	return result.NetworkChanged
}

func filterRemoteCatalogPage(state *stateFile, peerID string, page *corestate.CatalogPage, now time.Time) *corestate.CatalogPage {
	if page == nil || state == nil || len(page.Entries) == 0 {
		return page
	}
	filtered := *page
	filtered.Entries = make([]corestate.ZoneDigest, 0, len(page.Entries))
	for _, entry := range page.Entries {
		if shouldSkipRemoteZone(state, peerID, entry.Zone, entry.RootHash, now) {
			continue
		}
		filtered.Entries = append(filtered.Entries, entry)
	}
	return &filtered
}

func (d *DaemonService) recordSyncPeerState(peerID, label string, fn func(*corestate.PeerCheckpoint)) bool {
	return d.recordSyncPeerStateBatch(peerID, label, fn)
}

func (d *DaemonService) recordSyncPeerStateBatch(peerID, label string, fns ...func(*corestate.PeerCheckpoint)) bool {
	if d == nil || d.Sync == nil || d.StateStore == nil || len(fns) == 0 {
		return false
	}
	view := d.StateStore.common.ReadView()
	peer := view.Gossip.Peers[peerID]
	for _, fn := range fns {
		if fn != nil {
			fn(&peer)
		}
	}
	if _, err := d.StateStore.UpdatePeerCheckpoint(context.Background(), peerID, fullPeerCheckpointPatch(peer)); err != nil {
		d.logWarn("sync", "sync_peer_state_commit_failed", map[string]any{
			"peer_id": peerID,
			"label":   label,
			"error":   err,
		})
		return false
	}
	return true
}

func fullPeerCheckpointPatch(peer corestate.PeerCheckpoint) corestate.PeerCheckpointPatch {
	reject := make(map[zone.ZonePath]corestate.RejectedObject, len(peer.RejectedObjects))
	for path, item := range peer.RejectedObjects {
		reject[path] = item
	}
	return corestate.PeerCheckpointPatch{
		LastSyncUnix: corestate.PatchField[int64]{Set: true, Value: peer.LastSyncUnix}, LastAttemptUnix: corestate.PatchField[int64]{Set: true, Value: peer.LastAttemptUnix},
		BackoffUntilUnix: corestate.PatchField[int64]{Set: true, Value: peer.BackoffUntilUnix}, FailureCount: corestate.PatchField[int]{Set: true, Value: peer.FailureCount},
		LastRelayUnix: corestate.PatchField[int64]{Set: true, Value: peer.LastRelayUnix}, LastRelayRootHex: corestate.PatchField[string]{Set: true, Value: peer.LastRelayCatalogRootHex},
		DiscoveredEndpoint: corestate.PatchField[string]{Set: true, Value: peer.DiscoveredEndpoint}, DiscoveredAtUnix: corestate.PatchField[int64]{Set: true, Value: peer.DiscoveredAtUnix},
		ObservedEndpoint: corestate.PatchField[string]{Set: true, Value: peer.ObservedEndpoint}, ObservedFirstUnix: corestate.PatchField[int64]{Set: true, Value: peer.ObservedFirstSeenUnix},
		ObservedLastUnix: corestate.PatchField[int64]{Set: true, Value: peer.ObservedLastSeenUnix}, ObservedSyncUnix: corestate.PatchField[int64]{Set: true, Value: peer.ObservedLastSyncUnix},
		ObservedUntilUnix: corestate.PatchField[int64]{Set: true, Value: peer.ObservedUntilUnix}, ObservedFailures: corestate.PatchField[int]{Set: true, Value: peer.ObservedFailureCount},
		ObservedGrace: corestate.PatchField[[]corestate.ObservedGraceEndpoint]{Set: true, Value: peer.ObservedGraceEndpoints}, LastFailure: corestate.PatchField[*corestate.PeerFailure]{Set: true, Value: peer.LastFailure}, Reject: reject,
	}
}

func recordPeerSyncCheckpoint(peer *corestate.PeerCheckpoint, syncErr error, now time.Time) {
	if peer == nil {
		return
	}
	peer.LastAttemptUnix = now.Unix()
	if syncErr != nil {
		peer.FailureCount++
		backoff := time.Duration(1<<minInt(peer.FailureCount, 6)) * time.Second
		peer.BackoffUntilUnix = now.Add(backoff).Unix()
		peer.LastFailure = &corestate.PeerFailure{Code: corestate.PeerFailureUnknown, Message: syncErr.Error(), AtUnix: now.Unix()}
		return
	}
	peer.LastSyncUnix = now.Unix()
	peer.BackoffUntilUnix = 0
	peer.FailureCount = 0
	peer.LastFailure = nil
	if peer.ObservedEndpoint != "" && peer.ObservedUntilUnix != 0 && now.Before(time.Unix(peer.ObservedUntilUnix, 0)) {
		peer.ObservedLastSyncUnix = now.Unix()
		peer.ObservedFailureCount = 0
	}
}

type syncPeerStateMutation struct {
	label string
	apply func(*corestate.PeerCheckpoint)
}

// syncPeerStateMutationBatch collects the control-state changes caused by one
// sync event. It preserves mutation order and flushes before persistence, while
// avoiding a complete state-store transaction for every individual field
// family.
type syncPeerStateMutationBatch struct {
	peerID             string
	pending            []syncPeerStateMutation
	completionRecorded bool
}

func newSyncPeerStateMutationBatch(peerID string) *syncPeerStateMutationBatch {
	return &syncPeerStateMutationBatch{peerID: peerID}
}

func (b *syncPeerStateMutationBatch) add(label string, fn func(*corestate.PeerCheckpoint)) {
	if b == nil || fn == nil {
		return
	}
	b.pending = append(b.pending, syncPeerStateMutation{label: label, apply: fn})
}

func (b *syncPeerStateMutationBatch) addCompletion(session *gossip.SyncSession, now time.Time) {
	if b == nil || session == nil || b.completionRecorded {
		return
	}
	lastError := session.LastError()
	b.add("peer_sync", func(peer *corestate.PeerCheckpoint) {
		recordPeerSyncCheckpoint(peer, lastError, now)
	})
	b.completionRecorded = true
}

func (b *syncPeerStateMutationBatch) commit(d *DaemonService) {
	if b == nil || len(b.pending) == 0 || d == nil {
		return
	}
	pending := b.pending
	b.pending = nil
	labels := make([]string, 0, len(pending))
	fns := make([]func(*corestate.PeerCheckpoint), 0, len(pending))
	for _, mutation := range pending {
		labels = append(labels, mutation.label)
		fns = append(fns, mutation.apply)
	}
	d.recordSyncPeerStateBatch(b.peerID, strings.Join(labels, ","), fns...)
}

type syncSnapshotApply struct {
	action gossip.ApplySnapshotAction
	limits corestate.SyncLimits
}

func snapshotApplyVia(action gossip.ApplySnapshotAction) string {
	if action.Via != "" {
		return action.Via
	}
	return "event_loop"
}

type syncSnapshotOutcome struct {
	result         *corestate.ApplyResult
	applyErr       error
	networkChanged bool
	adopted        bool
	adoptionErr    error
	refreshed      bool
	refreshErr     error
	managedZone    zone.ZonePath
}

// syncSnapshotCommit separates publication of the detached state workspace
// from a real Network transition. A successful snapshot may still commit
// peer/admission metadata while leaving every relevant Zone root unchanged.
type syncSnapshotCommit struct {
	StateCommitted bool
	NetworkChanged bool
}

func (d *DaemonService) applySyncSnapshotBatch(peerID string, applies []syncSnapshotApply, now time.Time) ([]syncSnapshotOutcome, syncSnapshotCommit, error) {
	if d == nil || d.Sync == nil || d.StateStore == nil {
		return nil, syncSnapshotCommit{}, errors.New("daemon service is not initialized")
	}
	managedZone := zone.ZonePath("")
	view := d.StateStore.common.ReadView()
	if view.State != nil {
		managedZone = view.State.ManagedZone
	}
	batch := make([]corestate.RemoteSnapshot, 0, len(applies))
	for _, apply := range applies {
		batch = append(batch, corestate.RemoteSnapshot{
			Snapshot: apply.action.Snapshot, ExpectedRoot: append([]byte(nil), apply.action.ExpectedRoot...), Limits: apply.limits,
		})
	}
	result, err := d.StateStore.ApplyCommonRemoteBatch(context.Background(), peerID, batch, now)
	if err != nil {
		return nil, syncSnapshotCommit{}, err
	}
	outcomes := make([]syncSnapshotOutcome, len(result.Outcomes))
	for i, item := range result.Outcomes {
		outcomes[i] = syncSnapshotOutcome{
			result: item.Result, applyErr: item.Err, networkChanged: item.Result != nil && item.Result.NetworkChanged || item.ManagedZoneAdopted || item.AuthorityRefreshed,
			adopted: item.ManagedZoneAdopted, refreshed: item.AuthorityRefreshed, managedZone: managedZone,
		}
	}
	return outcomes, syncSnapshotCommit{StateCommitted: result.Committed, NetworkChanged: result.Changes.NetworkChanged}, nil
}

func (d *DaemonService) logSnapshotAdoption(peerID string, outcome syncSnapshotOutcome) {
	if outcome.adoptionErr != nil {
		d.logWarn("auto_join", "adopt_failed", map[string]any{
			"peer_id": peerID,
			"zone":    outcome.managedZone,
			"via":     "event_loop",
			"error":   outcome.adoptionErr,
		})
	} else if outcome.adopted {
		d.logInfo("auto_join", "adopted", map[string]any{
			"peer_id": peerID,
			"zone":    outcome.managedZone,
			"via":     "event_loop",
		})
	}
	if outcome.refreshErr != nil {
		d.logWarn("authority", "managed_zone_refresh_failed", map[string]any{
			"peer_id": peerID,
			"zone":    outcome.managedZone,
			"error":   outcome.refreshErr,
		})
	} else if outcome.refreshed {
		d.logInfo("authority", "managed_zone_refreshed", map[string]any{
			"peer_id": peerID,
			"zone":    outcome.managedZone,
		})
	}
}

func (d *DaemonService) applySyncSnapshotAction(peerID string, action gossip.ApplySnapshotAction, limits corestate.SyncLimits, now time.Time) (*corestate.ApplyResult, syncSnapshotCommit, error) {
	if action.Snapshot == nil {
		return nil, syncSnapshotCommit{}, nil
	}
	outcomes, commit, err := d.applySyncSnapshotBatch(peerID, []syncSnapshotApply{{action: action, limits: limits}}, now)
	if err != nil {
		return nil, syncSnapshotCommit{}, err
	}
	if !commit.StateCommitted || len(outcomes) == 0 {
		return nil, commit, nil
	}
	outcome := outcomes[0]
	if outcome.applyErr != nil {
		return nil, commit, outcome.applyErr
	}
	d.logSnapshotAdoption(peerID, outcome)
	return outcome.result, commit, nil
}

type daemonGossipActionController struct {
	daemon    *DaemonService
	mutations *syncPeerStateMutationBatch
	now       time.Time
	limits    corestate.SyncLimits
	replyAddr *net.UDPAddr
}

func (controller *daemonGossipActionController) GossipStateView(context.Context) corehost.GossipStateView {
	view := controller.daemon.StateStore.common.ReadView()
	if view.State == nil || view.State.Network == nil {
		return corehost.GossipStateView{}
	}
	return corehost.GossipStateView{
		Loaded:       true,
		Digests:      corestate.ZoneDigests(view.State.Network),
		SenderPeerID: controller.daemon.Sync.Config.PeerID,
	}
}

func (controller *daemonGossipActionController) GossipDatagramBudget() int {
	return controller.daemon.syncDatagramBudget()
}

func (controller *daemonGossipActionController) ObserveGossipCatalogSummary(peerID string, summary *corestate.CatalogSummary) {
	recordCatalogSummary(controller.daemon.PeerObservability, peerID, summary, controller.now)
}

func (controller *daemonGossipActionController) ObserveGossipCatalogPage(peerID string, page *corestate.CatalogPage) {
	recordCatalogPage(controller.daemon.PeerObservability, peerID, page, controller.now)
	recordReadOnlyResponder(controller.daemon.PeerObservability, peerID, "catalog_page", "", controller.now)
}

func (controller *daemonGossipActionController) FilterGossipCatalogPage(_ context.Context, peerID string, page *corestate.CatalogPage, now time.Time) ([]corestate.ZoneDigest, *corestate.CatalogPage) {
	return corehost.FilterGossipCatalogPage(controller.daemon.currentGossipDiscoveryInput(), peerID, page, now)
}

func (controller *daemonGossipActionController) ObserveGossipChunkRepair(peerID string) {
	recordDatagramRepairNACK(controller.daemon.PeerObservability, peerID, false, controller.now)
}

func (controller *daemonGossipActionController) ObserveGossipCatalogReject(peerID, cursor string, err error) {
	budget := controller.GossipDatagramBudget()
	recordDatagramTooLarge(controller.daemon.PeerObservability, peerID, "send", "catalog_page", "", "", 0, budget, controller.now)
	recordCatalogReject(controller.daemon.PeerObservability, peerID, cursor, gossip.RejectReason(err), controller.now)
	controller.daemon.logWarn("sync", "catalog_page_failed", map[string]any{
		"peer_id": peerID,
		"cursor":  cursor,
		"error":   err,
		"via":     "responder",
	})
}

func (controller *daemonGossipActionController) RecordGossipSummaryMatch(_ context.Context, peerID string) error {
	recordSyncHint(controller.daemon.PeerObservability, peerID, "ping_summary_match", "", true, controller.now)
	controller.daemon.recordSyncPeerStateBatch(peerID, "peer_sync",
		func(peer *corestate.PeerCheckpoint) {
			recordPeerSyncCheckpoint(peer, nil, controller.now)
		},
	)
	controller.daemon.logDebug("sync", "ping_summary_shortcut", map[string]any{
		"peer_id": peerID,
		"reason":  "catalog_root_match",
	})
	return nil
}

func (controller *daemonGossipActionController) HandleGossipAnnounceHint(_ context.Context, peerID string) error {
	return controller.daemon.handleAnnounceHint(peerID)
}

func (controller *daemonGossipActionController) RespondGossipFetchZone(_ context.Context, peerID string, request *gossip.FetchZone) error {
	if request == nil {
		return nil
	}
	if request.ChunkFallback {
		recordReadOnlyResponder(controller.daemon.PeerObservability, peerID, "chunk_fallback", request.Zone, controller.now)
		return controller.daemon.respondFetchZoneChunksTo(peerID, request.Zone, controller.replyAddr)
	}
	recordReadOnlyResponder(controller.daemon.PeerObservability, peerID, "fetch_zone", request.Zone, controller.now)
	return controller.daemon.respondFetchZoneTo(peerID, request.Zone, controller.replyAddr)
}

func (controller *daemonGossipActionController) HandleGossipObjectChunk(_ context.Context, message *gossip.Message) error {
	return controller.daemon.handleObjectChunkFrom(message, controller.replyAddr, controller.limits)
}

func (controller *daemonGossipActionController) HandleGossipObjectChunkNACK(_ context.Context, message *gossip.Message) error {
	return controller.daemon.Sync.handleObjectChunkNACKFrom(message, controller.replyAddr)
}

func (controller *daemonGossipActionController) ApplyGossipSnapshots(_ context.Context, peerID string, actions []gossip.ApplySnapshotAction) (corehost.GossipSnapshotApplyResult, error) {
	view := controller.daemon.StateStore.common.ReadView()
	managedZone := zone.ZonePath("")
	if view.State != nil {
		managedZone = view.State.ManagedZone
	}
	var applies []syncSnapshotApply
	for _, action := range actions {
		if action.Snapshot == nil {
			continue
		}
		if action.Snapshot.Zone == managedZone {
			controller.daemon.logDebug("sync", "skipping_own_zone_snapshot", map[string]any{
				"peer_id": peerID,
				"zone":    action.Snapshot.Zone,
			})
			continue
		}
		limits := controller.limits
		if action.RelaxedLimits {
			limits.MaxBytes = 8 << 20
		}
		applies = append(applies, syncSnapshotApply{action: action, limits: limits})
	}
	if len(applies) == 0 {
		return corehost.GossipSnapshotApplyResult{}, nil
	}
	outcomes, committed, err := controller.daemon.applySyncSnapshotBatch(peerID, applies, controller.now)
	if err != nil {
		return corehost.GossipSnapshotApplyResult{}, err
	}
	for i, outcome := range outcomes {
		apply := applies[i]
		if outcome.applyErr != nil {
			controller.daemon.logWarn("sync", "zone_apply_failed", map[string]any{
				"peer_id": peerID,
				"zone":    apply.action.Snapshot.Zone,
				"reason":  gossip.RejectReason(outcome.applyErr),
				"error":   outcome.applyErr,
			})
			continue
		}
		if outcome.result == nil {
			continue
		}
		controller.daemon.logSnapshotAdoption(peerID, outcome)
		if !committed.NetworkChanged || !outcome.networkChanged {
			continue
		}
		controller.daemon.logInfo("sync", "zone_applied", map[string]any{
			"peer_id":     peerID,
			"zone":        apply.action.Snapshot.Zone,
			"records":     outcome.result.Records,
			"delegations": outcome.result.Delegation,
			"via":         snapshotApplyVia(apply.action),
		})
	}
	for i, apply := range applies {
		if !apply.action.ReportResult || apply.action.Snapshot == nil {
			continue
		}
		event := &gossip.SnapshotAppliedEvent{PeerID: peerID, Zone: apply.action.Snapshot.Zone}
		if i >= len(outcomes) {
			event.Err = errors.New("snapshot apply produced no outcome")
		} else {
			event.Err = outcomes[i].applyErr
		}
		_ = controller.daemon.postSyncEvent(event)
	}
	return corehost.GossipSnapshotApplyResult{StateCommitted: committed.StateCommitted, NetworkChanged: committed.NetworkChanged}, nil
}

func (controller *daemonGossipActionController) SendGossip(_ context.Context, outbound gossip.OutboundMessage) error {
	if controller.replyAddr != nil {
		return controller.daemon.sendSyncMessageTo(outbound.PeerID, controller.replyAddr, outbound.Message)
	}
	return controller.daemon.sendSyncSessionMessage(outbound.PeerID, outbound.Message)
}

func (controller *daemonGossipActionController) RecordGossipBackoffs(_ context.Context, backoffs []gossip.RecordBackoffAction) error {
	for _, backoff := range backoffs {
		if controller.mutations == nil {
			controller.daemon.recordSyncPeerState(backoff.PeerID, "peer_backoff", func(peer *corestate.PeerCheckpoint) {
				recordPeerBackoffCheckpoint(peer, backoff.Err, controller.now)
			})
			continue
		}
		actionErr := backoff.Err
		controller.mutations.add("peer_backoff", func(peer *corestate.PeerCheckpoint) {
			recordPeerBackoffCheckpoint(peer, actionErr, controller.now)
		})
	}
	return nil
}

func (controller *daemonGossipActionController) PersistGossip(_ context.Context, intent corehost.GossipPersistenceIntent, completion *corehost.GossipCompletionIntent) error {
	if controller.mutations != nil {
		if completion != nil && !controller.mutations.completionRecorded {
			completionErr := completion.Err
			controller.mutations.add("peer_sync", func(peer *corestate.PeerCheckpoint) {
				recordPeerSyncCheckpoint(peer, completionErr, controller.now)
			})
			controller.mutations.completionRecorded = true
		}
		controller.mutations.commit(controller.daemon)
	}
	return nil
}

func (controller *daemonGossipActionController) ReportGossipIssue(issue corehost.GossipExecutionIssue) {
	event := "gossip_effect_failed"
	switch issue.Phase {
	case corehost.GossipPhaseApply:
		event = "snapshot_batch_commit_failed"
	case corehost.GossipPhaseInbound:
		event = "event_dropped"
	case corehost.GossipPhaseTimer:
		event = "timer_action_failed"
	case corehost.GossipPhasePersistence:
		event = "save_failed"
	}
	controller.daemon.logWarn("sync", event, map[string]any{
		"peer_id": issue.PeerID,
		"phase":   issue.Phase,
		"error":   issue.Err,
	})
}

func (d *DaemonService) syncDatagramBudget() int {
	budget := gossip.DefaultMaxMessage
	if d != nil && d.Sync != nil && d.Sync.Transport != nil {
		if m := d.Sync.Transport.MaxMessageBytes(); m > 0 {
			budget = m
		}
	}
	return budget
}

// rememberSyncIngressRoute keeps the source of a recently accepted inbound
// packet as an ephemeral route for the active pull it triggered. The route is
// never persisted or promoted to a verified observed path here.
func (d *DaemonService) rememberSyncIngressRoute(peerID string, addr *net.UDPAddr, now time.Time) {
	if d == nil || peerID == "" || addr == nil {
		return
	}
	if d.syncIngressRoutes == nil {
		d.syncIngressRoutes = make(map[string]syncIngressRoute)
	}
	copied := *addr
	d.syncIngressRoutes[peerID] = syncIngressRoute{addr: &copied, until: now.Add(syncIngressRouteTTL)}
}

func (d *DaemonService) syncIngressRouteAddr(peerID string, now time.Time) *net.UDPAddr {
	if d == nil || peerID == "" || d.syncIngressRoutes == nil {
		return nil
	}
	route, ok := d.syncIngressRoutes[peerID]
	if !ok || route.addr == nil || !now.Before(route.until) {
		delete(d.syncIngressRoutes, peerID)
		return nil
	}
	copied := *route.addr
	return &copied
}

func (d *DaemonService) clearSyncIngressRoute(peerID string) {
	if d == nil || d.syncIngressRoutes == nil {
		return
	}
	delete(d.syncIngressRoutes, peerID)
}

func (d *DaemonService) sendSyncSessionMessage(peerID string, msg *gossip.Message) error {
	var replyAddr *net.UDPAddr
	if d != nil && d.Sync != nil {
		replyAddr = d.syncIngressRouteAddr(peerID, d.Sync.now())
	}
	return d.sendSyncMessageTo(peerID, replyAddr, msg)
}

func (d *DaemonService) sendSyncMessageTo(peerID string, replyAddr *net.UDPAddr, msg *gossip.Message) error {
	if d.Sync == nil || d.Sync.Transport == nil {
		return nil
	}
	budget := d.syncDatagramBudget()
	size, sizeErr := gossip.WireEncodeSizeForPeer(msg, d.Sync.Transport.PeerID())
	if sizeErr != nil {
		return sizeErr
	}
	if size > budget {
		object := string(msg.Type)
		recordDatagramTooLarge(d.PeerObservability, peerID, "send", object, "", "", size, budget, d.Sync.now())
		d.logWarn("transport", "datagram_too_large", map[string]any{
			"peer_id": peerID,
			"type":    msg.Type,
			"bytes":   size,
			"limit":   budget,
			"action":  "drop",
		})
		return gossip.ErrMessageTooLarge
	}
	var err error
	if replyAddr != nil {
		err = d.Sync.Transport.SendTo(peerID, replyAddr, msg)
	} else {
		err = d.Sync.Transport.Send(peerID, msg)
	}
	if err != nil {
		replyAddrText := ""
		if replyAddr != nil {
			replyAddrText = replyAddr.String()
		}
		d.logDebug("sync", "send_failed", map[string]any{
			"peer_id":    peerID,
			"type":       msg.Type,
			"reply_addr": replyAddrText,
			"error":      err,
		})
	}
	return err
}

func (d *DaemonService) completeSyncSessionAfterPeerState(session *gossip.SyncSession, changed bool) {
	if session == nil {
		return
	}
	peerID := session.PeerID
	d.hostRuntime.CancelGossipTimers(peerID)
	// Only mark the last-used address as failing for timeout-like errors; do
	// not penalize the address for internal/event handling failures.
	if session.LastError() != nil && d.Sync.Transport != nil && strings.Contains(session.LastError().Error(), "timeout") {
		if lastAddr := d.Sync.Transport.LastSendAddr(peerID); lastAddr != nil {
			d.Sync.Transport.RecordAddrFailure(peerID, lastAddr)
		}
	}
	if session.State == gossip.SyncSessionCompleted && changed {
		if d.Sync.Transport != nil {
			d.updateDiscoveredPeers()
		}
		d.notifyStateChanged()
		d.relaySyncToPeers(peerID)
	}
	d.hostRuntime.Gossip.RemoveSession(peerID)
	if d.hostRuntime.Gossip.TakePendingHint(peerID) {
		_ = d.startHintedSyncSession(peerID, "announce_hint_followup")
		return
	}
	d.clearSyncIngressRoute(peerID)
}

func (d *DaemonService) relaySyncToPeers(sourcePeerID string) {
	if d == nil || d.Sync == nil {
		return
	}
	now := d.Sync.now()
	relayed := 0
	input := d.currentGossipDiscoveryInput()
	summary := corestate.CatalogSummaryFor(input.Network)
	if summary == nil {
		return
	}
	peers := corehost.GossipOutboundPeers(input, now)
	catalogRoot := hex.EncodeToString(summary.CatalogRoot)
	for _, peerID := range peers {
		if peerID == sourcePeerID {
			continue
		}
		if relayed >= maxRelayFanoutPerUpdate {
			recordRelaySuppression(d.PeerObservability, peerID, "relay_fanout_limited", now)
			continue
		}
		allowed, reason := corehost.ShouldRelayGossipUpdate(input.Peers[peerID], peerID, sourcePeerID, catalogRoot, now)
		if !allowed {
			recordRelaySuppression(d.PeerObservability, peerID, reason, now)
			continue
		}
		relayed++
		if d.hostRuntime.Gossip.HasActiveSession(peerID) {
			continue
		}
		d.hostRuntime.Gossip.NewSession(peerID)
		if err := d.hostRuntime.PostGossip(&gossip.SyncTimerEvent{
			PeerID:       peerID,
			LocalSummary: summary,
		}); err != nil {
			d.logWarn("sync", "relay_event_full", map[string]any{"peer_id": peerID, "source_peer": sourcePeerID})
			d.hostRuntime.Gossip.RemoveSession(peerID)
			continue
		}
		if d.recordSyncPeerState(peerID, "relay_success", func(peer *corestate.PeerCheckpoint) {
			peer.LastRelayUnix = now.Unix()
			peer.LastRelayCatalogRootHex = catalogRoot
		}) {
			recordRelaySuccessDiagnostics(d.PeerObservability, peerID, sourcePeerID, now)
		}
	}
}

func digestForSnapshot(snapshot *corestate.ZoneSnapshot) corestate.ZoneDigest {
	if snapshot == nil {
		return corestate.ZoneDigest{}
	}
	return corestate.ZoneDigest{
		Zone:     snapshot.Zone,
		RootHash: corestate.ZoneRoot(zoneStateFromSnapshot(snapshot)),
	}
}

func zoneStateFromSnapshot(snapshot *corestate.ZoneSnapshot) *zone.ZoneState {
	if snapshot == nil {
		return nil
	}
	zs := zone.NewZoneState(snapshot.Zone, snapshot.Authority)
	zs.Delegations = snapshot.Delegations
	zs.Revocations = snapshot.Revocations
	zs.Records = snapshot.Records
	zs.RecordHistory = snapshot.RecordHistory
	return zs
}

func recordPeerBackoffCheckpoint(peer *corestate.PeerCheckpoint, err error, now time.Time) {
	if peer == nil {
		return
	}
	peer.LastAttemptUnix = now.Unix()
	if err != nil {
		peer.LastFailure = &corestate.PeerFailure{Code: corestate.PeerFailureUnknown, Message: err.Error(), AtUnix: now.Unix()}
	}
	backoff := time.Duration(1<<minInt(peer.FailureCount, 6)) * time.Second
	peer.BackoffUntilUnix = now.Add(backoff).Unix()
}

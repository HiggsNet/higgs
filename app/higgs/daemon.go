package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

type DaemonService struct {
	Sync              *SyncRuntime
	Interval          time.Duration
	ControlSocketPath string
	Events            chan daemonEvent
	Hooks             DaemonHooks
}

type DaemonHooks struct {
	OnStateChanged func(*stateFile)
}

type daemonEventType string

const (
	controlConnDeadline                       = 10 * time.Second
	daemonEventRecordPut      daemonEventType = "record_put"
	daemonEventDelegateIssue  daemonEventType = "delegate_issue"
	daemonEventDelegateRevoke daemonEventType = "delegate_revoke"
	daemonEventJoinAccept     daemonEventType = "join_accept"
	daemonEventRootInit       daemonEventType = "root_init"
	daemonEventPacket         daemonEventType = "packet"
	daemonEventSyncTimer      daemonEventType = "timer_sync"
	daemonEventEndpointTimer  daemonEventType = "timer_endpoint_publish"
	daemonEventRemoteApplied  daemonEventType = "remote_announce_applied"
	daemonEventSyncTrigger    daemonEventType = "sync_trigger"
	daemonEventShutdown       daemonEventType = "shutdown"
)

type daemonEvent struct {
	Type         daemonEventType
	RecordPut    *daemonRecordPut
	JoinRequest  *joinRequest
	JoinBundle   *joinBundle
	PrivateKey   *privateKeyFile
	Zone         zone.ZonePath
	Reason       string
	Packet       *gossip.Packet
	SourcePeerID string
	ForceSync    bool
	Context      context.Context
	Reply        chan daemonEventResult
}

type daemonRecordPut struct {
	Zone  zone.ZonePath
	Key   string
	Value []byte
	Type  string
}

type daemonEventResult struct {
	Version       uint64
	Zone          zone.ZonePath
	RootPublicKey []byte
	JoinBundle    *joinBundle
	Error         error
}

func newDaemonService(rt *Runtime, state *stateFile, config *syncConfigFile, interval time.Duration) *DaemonService {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	var socketPath string
	if rt != nil {
		socketPath = controlSocketPath(rt.Config)
	}
	return &DaemonService{
		Sync:              newSyncRuntime(state, config, nil, rt),
		Interval:          interval,
		ControlSocketPath: socketPath,
		Events:            make(chan daemonEvent, 64),
	}
}

func (d *DaemonService) Run(ctx context.Context) error {
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.Config == nil {
		return errors.New("daemon service is not initialized")
	}
	transport, err := d.Sync.openTransport()
	if err != nil {
		return err
	}
	defer transport.Close()
	objectPullListener, err := startObjectPullServer(d)
	if err != nil {
		fmt.Fprintf(os.Stderr, "object pull server error: %v\n", err)
	}
	if objectPullListener != nil {
		defer objectPullListener.Close()
	}
	stopControl, err := d.startControlServer(ctx)
	if err != nil {
		return err
	}
	defer stopControl()
	fmt.Printf("daemon running as %s on %s interval=%s\n", d.Sync.Config.PeerID, transport.LocalAddr(), d.Interval)

	nextSync := d.Sync.now()
	nextEndpointPublish := d.Sync.now()
	lastObservedDigests := gossip.ZoneDigests(d.Sync.State.Network)
	d.Sync.updateDiscoveredPeers()
	var forceSync bool
	for {
		if ctx.Err() != nil {
			return nil
		}
		now := d.Sync.now()
		if syncNow, shutdown := d.processEvents(ctx); shutdown {
			return nil
		} else if syncNow {
			nextSync = now
			forceSync = true
		}
		if latest, changed, err := d.Sync.reloadStateIfChanged(lastObservedDigests); err != nil {
			fmt.Fprintf(os.Stderr, "daemon reload error: %v\n", err)
		} else if changed {
			d.setState(latest)
			lastObservedDigests = gossip.ZoneDigests(latest.Network)
			nextSync = now
			forceSync = true
			d.Sync.updateDiscoveredPeers()
			d.notifyStateChanged()
		}
		if !now.Before(nextEndpointPublish) {
			result, triggerSync, _ := d.handleEvent(daemonEvent{Type: daemonEventEndpointTimer, Context: ctx})
			if result.Error != nil {
				fmt.Fprintf(os.Stderr, "endpoint publish error: %v\n", result.Error)
			}
			if triggerSync {
				nextSync = now
				forceSync = true
				lastObservedDigests = gossip.ZoneDigests(d.Sync.State.Network)
			}
			interval := d.Sync.Config.ReflectorInterval
			if interval <= 0 {
				interval = 5 * time.Minute
			}
			nextEndpointPublish = now.Add(interval)
		}
		if !now.Before(nextSync) {
			result, _, _ := d.handleEvent(daemonEvent{Type: daemonEventSyncTimer, ForceSync: forceSync, Context: ctx})
			if result.Error != nil {
				fmt.Fprintf(os.Stderr, "sync timer error: %v\n", result.Error)
			}
			if !sameZoneDigests(lastObservedDigests, gossip.ZoneDigests(d.Sync.State.Network)) {
				lastObservedDigests = gossip.ZoneDigests(d.Sync.State.Network)
			}
			nextSync = now.Add(d.Interval)
			forceSync = false
		}
		packet, err := receiveWithContext(ctx, transport, d.Sync.now().Add(250*time.Millisecond))
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isReceiveTimeout(err) || errors.Is(err, gossip.ErrUnknownPeer) || errors.Is(err, gossip.ErrAddrMismatch) || errors.Is(err, gossip.ErrMessageTooLarge) {
				continue
			}
			fmt.Fprintf(os.Stderr, "daemon receive error: %v\n", err)
			continue
		}
		result, _, _ := d.handleEvent(daemonEvent{Type: daemonEventPacket, Packet: packet, Context: ctx})
		if result.Error != nil {
			fmt.Fprintf(os.Stderr, "daemon packet error from %s: %v\n", packet.Message.PeerID, result.Error)
		}
		if !sameZoneDigests(lastObservedDigests, gossip.ZoneDigests(d.Sync.State.Network)) {
			lastObservedDigests = gossip.ZoneDigests(d.Sync.State.Network)
		}
	}
}

func (d *DaemonService) startControlServer(ctx context.Context) (func(), error) {
	if d.ControlSocketPath == "" {
		return func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(d.ControlSocketPath), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(d.ControlSocketPath)
	listener, err := net.Listen("unix", d.ControlSocketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(d.ControlSocketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(d.ControlSocketPath)
		return nil, err
	}
	done := make(chan struct{})
	go d.serveControl(controlContext(ctx), listener, done)
	return func() {
		_ = listener.Close()
		<-done
		_ = os.Remove(d.ControlSocketPath)
	}, nil
}

func (d *DaemonService) serveControl(ctx context.Context, listener net.Listener, done chan<- struct{}) {
	defer close(done)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "daemon control accept error: %v\n", err)
			continue
		}
		go d.handleControlConn(ctx, conn)
	}
}

func (d *DaemonService) handleControlConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	var request controlRequest
	_ = conn.SetReadDeadline(time.Now().Add(controlConnDeadline))
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		writeControlResponse(conn, controlError(err))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	switch request.Method {
	case "status":
		writeControlResponse(conn, controlResponse{
			OK:      true,
			PeerID:  d.Sync.Config.PeerID,
			Message: "daemon online",
		})
	case "record_put":
		if err := validateControlRecordPut(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type: daemonEventRecordPut,
			RecordPut: &daemonRecordPut{
				Zone:  zone.ZonePath(request.Zone),
				Key:   request.Key,
				Value: parseControlRecordValue(request),
				Type:  request.Type,
			},
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Version: result.Version})
	case "delegate_issue":
		if err := validateControlDelegateIssue(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:        daemonEventDelegateIssue,
			JoinRequest: request.JoinRequest,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Zone: result.Zone, JoinBundle: result.JoinBundle})
	case "delegate_revoke":
		if err := validateControlDelegateRevoke(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:   daemonEventDelegateRevoke,
			Zone:   zone.ZonePath(request.Zone),
			Reason: request.Reason,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Zone: result.Zone})
	case "join_accept":
		if err := validateControlJoinAccept(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:       daemonEventJoinAccept,
			JoinBundle: request.JoinBundle,
			PrivateKey: request.PrivateKey,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Zone: result.Zone, RootPublicKey: result.RootPublicKey})
	case "root_init":
		writeControlResponse(conn, controlError(errors.New("root init via daemon is only valid before a daemon has loaded state; stop the daemon and run root init as recovery/direct initialization")))
	case "sync_trigger":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventSyncTrigger})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Message: "sync scheduled"})
	case "shutdown":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventShutdown})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Message: "shutdown scheduled"})
	case "reload":
		writeControlResponse(conn, controlError(errors.New("reload is reserved for a later Phase 3 step")))
	default:
		writeControlResponse(conn, controlError(fmt.Errorf("unknown control method: %s", request.Method)))
	}
}

func (d *DaemonService) enqueueEvent(ctx context.Context, event daemonEvent) daemonEventResult {
	if ctx == nil {
		ctx = context.Background()
	}
	event.Reply = make(chan daemonEventResult, 1)
	select {
	case d.Events <- event:
	case <-ctx.Done():
		return daemonEventResult{Error: ctx.Err()}
	}
	select {
	case result := <-event.Reply:
		return result
	case <-ctx.Done():
		return daemonEventResult{Error: ctx.Err()}
	}
}

func (d *DaemonService) processEvents(ctx context.Context) (syncNow bool, shutdown bool) {
	for {
		select {
		case event := <-d.Events:
			result, triggerSync, stop := d.handleEvent(event)
			if event.Reply != nil {
				event.Reply <- result
			}
			syncNow = syncNow || triggerSync
			shutdown = shutdown || stop
			if shutdown {
				return syncNow, shutdown
			}
		default:
			return syncNow, shutdown
		}
	}
}

func (d *DaemonService) handleEvent(event daemonEvent) (daemonEventResult, bool, bool) {
	switch event.Type {
	case daemonEventRecordPut:
		version, err := d.handleRecordPutEvent(event.RecordPut)
		return daemonEventResult{Version: version, Error: err}, err == nil, false
	case daemonEventDelegateIssue:
		result, err := d.handleDelegateIssueEvent(event.JoinRequest)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		return daemonEventResult{Zone: result.Zone, JoinBundle: result.Bundle}, true, false
	case daemonEventDelegateRevoke:
		err := d.handleDelegateRevokeEvent(event.Zone, event.Reason)
		return daemonEventResult{Zone: event.Zone, Error: err}, err == nil, false
	case daemonEventJoinAccept:
		result, err := d.handleJoinAcceptEvent(event.JoinBundle, event.PrivateKey)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		return daemonEventResult{Zone: result.Zone, RootPublicKey: result.RootPublicKey}, true, false
	case daemonEventRootInit:
		rootKey, err := d.handleRootInitEvent()
		return daemonEventResult{Zone: zone.RootZone, RootPublicKey: rootKey, Error: err}, false, false
	case daemonEventPacket:
		return daemonEventResult{Error: d.handlePacketEvent(event.Packet, controlContext(event.Context))}, false, false
	case daemonEventSyncTimer:
		return daemonEventResult{Error: d.handleSyncTimerEvent(controlContext(event.Context), event.ForceSync)}, false, false
	case daemonEventEndpointTimer:
		err := d.handleEndpointTimerEvent()
		return daemonEventResult{Error: err}, err == nil, false
	case daemonEventRemoteApplied:
		return daemonEventResult{Error: d.handleRemoteAppliedEvent(controlContext(event.Context), event.SourcePeerID)}, false, false
	case daemonEventSyncTrigger:
		return daemonEventResult{}, true, false
	case daemonEventShutdown:
		return daemonEventResult{}, false, true
	default:
		return daemonEventResult{Error: fmt.Errorf("unknown daemon event: %s", event.Type)}, false, false
	}
}

func (d *DaemonService) handleDelegateIssueEvent(request *joinRequest) (*delegationIssueResult, error) {
	latest, err := d.Sync.loadState()
	if err != nil {
		return nil, err
	}
	d.setState(latest)
	result, err := issueDelegationInState(d.Sync.App, d.Sync.State, request)
	if err != nil {
		return nil, err
	}
	if err := d.Sync.saveState(); err != nil {
		return nil, err
	}
	if d.Sync.Transport != nil {
		d.Sync.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return result, nil
}

func (d *DaemonService) handleDelegateRevokeEvent(path zone.ZonePath, reason string) error {
	latest, err := d.Sync.loadState()
	if err != nil {
		return err
	}
	d.setState(latest)
	if err := revokeDelegationInState(d.Sync.App, d.Sync.State, path, reason); err != nil {
		return err
	}
	if err := d.Sync.saveState(); err != nil {
		return err
	}
	if d.Sync.Transport != nil {
		d.Sync.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return nil
}

func (d *DaemonService) handleJoinAcceptEvent(bundle *joinBundle, key *privateKeyFile) (*joinAcceptResult, error) {
	result, err := acceptJoinBundleInState(d.Sync.App, bundle, key)
	if err != nil {
		return nil, err
	}
	latest, err := d.Sync.loadState()
	if err != nil {
		return nil, err
	}
	d.setState(latest)
	if d.Sync.Transport != nil {
		d.Sync.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return result, nil
}

func (d *DaemonService) handleRootInitEvent() ([]byte, error) {
	return nil, errors.New("root init via daemon is only valid before a daemon has loaded state; stop the daemon and run root init as recovery/direct initialization")
}

func (d *DaemonService) handlePacketEvent(packet *gossip.Packet, ctx context.Context) error {
	if packet == nil || packet.Message == nil {
		return errors.New("packet event is nil")
	}
	digestsBefore := gossip.ZoneDigests(d.Sync.State.Network)
	if err := d.Sync.handlePacket(packet); err != nil {
		return err
	}
	if packet.Message.Announce != nil && syncStateChanged(d.Sync.State, digestsBefore) {
		return d.handleRemoteAppliedEvent(ctx, packet.Message.PeerID)
	}
	return nil
}

func (d *DaemonService) handleRemoteAppliedEvent(ctx context.Context, sourcePeerID string) error {
	recordUpdateSource(d.Sync.State, sourcePeerID)
	if d.Sync.Transport != nil {
		d.Sync.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	if err := d.Sync.relay(ctx, sourcePeerID); err != nil {
		return fmt.Errorf("sync relay source=%s: %w", sourcePeerID, err)
	}
	return d.Sync.saveState()
}

func (d *DaemonService) handleSyncTimerEvent(ctx context.Context, force bool) error {
	latest, err := d.Sync.loadState()
	if err != nil {
		return fmt.Errorf("daemon reload: %w", err)
	}
	d.setState(latest)
	d.Sync.updateDiscoveredPeers()
	digestsBeforeRound := gossip.ZoneDigests(d.Sync.State.Network)
	var syncErr error
	for _, peerID := range outboundSyncPeersAt(d.Sync.State, d.Sync.Config, d.Sync.now()) {
		if !force && backoffRemaining(d.Sync.State.SyncPeers[peerID], d.Sync.now()) > 0 {
			continue
		}
		if err := d.Sync.syncRound(ctx, peerID, 3*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "sync round error peer=%s: %v\n", peerID, err)
			if syncErr == nil {
				syncErr = err
			}
		}
	}
	if syncStateChanged(d.Sync.State, digestsBeforeRound) {
		d.Sync.updateDiscoveredPeers()
		d.notifyStateChanged()
	}
	return syncErr
}

func (d *DaemonService) handleEndpointTimerEvent() error {
	latest, err := d.Sync.loadState()
	if err != nil {
		return fmt.Errorf("daemon reload: %w", err)
	}
	d.setState(latest)
	if err := d.Sync.publishEndpointRecord(); err != nil {
		return err
	}
	d.notifyStateChanged()
	return nil
}

func (d *DaemonService) handleRecordPutEvent(event *daemonRecordPut) (uint64, error) {
	if event == nil {
		return 0, errors.New("record_put event is nil")
	}
	latest, err := d.Sync.loadState()
	if err != nil {
		return 0, err
	}
	d.setState(latest)
	record, err := buildSignedRecordAt(d.Sync.State, event.Zone, event.Key, event.Value, event.Type, d.Sync.now())
	if err != nil {
		return 0, err
	}
	if err := d.Sync.State.Network.Put(record); err != nil {
		return 0, err
	}
	if err := d.Sync.saveState(); err != nil {
		return 0, err
	}
	if d.Sync.Transport != nil {
		d.Sync.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return record.Version, nil
}

func (d *DaemonService) setState(state *stateFile) {
	d.Sync.State = state
}

func (d *DaemonService) notifyStateChanged() {
	if d.Hooks.OnStateChanged != nil {
		d.Hooks.OnStateChanged(d.Sync.State)
	}
}

func daemonRun(ctx context.Context, interval time.Duration) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	config, err := rt.SyncConfig(state)
	if err != nil {
		return err
	}
	return newDaemonService(rt, state, config, interval).Run(ctx)
}

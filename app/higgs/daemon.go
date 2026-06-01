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
	daemonEventRecordPut   daemonEventType = "record_put"
	daemonEventSyncTrigger daemonEventType = "sync_trigger"
	daemonEventShutdown    daemonEventType = "shutdown"
)

type daemonEvent struct {
	Type      daemonEventType
	RecordPut *daemonRecordPut
	Reply     chan daemonEventResult
}

type daemonRecordPut struct {
	Zone  zone.ZonePath
	Key   string
	Value []byte
	Type  string
}

type daemonEventResult struct {
	Version uint64
	Error   error
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
	for {
		if ctx.Err() != nil {
			return nil
		}
		now := d.Sync.now()
		if syncNow, shutdown := d.processEvents(ctx); shutdown {
			return nil
		} else if syncNow {
			nextSync = now
		}
		if latest, changed, err := d.Sync.reloadStateIfChanged(lastObservedDigests); err != nil {
			fmt.Fprintf(os.Stderr, "daemon reload error: %v\n", err)
		} else if changed {
			d.setState(latest)
			lastObservedDigests = gossip.ZoneDigests(latest.Network)
			nextSync = now
			d.Sync.updateDiscoveredPeers()
			d.notifyStateChanged()
		}
		if !now.Before(nextEndpointPublish) {
			if latest, err := d.Sync.loadState(); err == nil {
				d.setState(latest)
				if err := d.Sync.publishEndpointRecord(); err != nil {
					fmt.Fprintf(os.Stderr, "endpoint publish error: %v\n", err)
				} else {
					lastObservedDigests = gossip.ZoneDigests(d.Sync.State.Network)
					nextSync = now
					d.notifyStateChanged()
				}
			} else {
				fmt.Fprintf(os.Stderr, "daemon reload error: %v\n", err)
			}
			interval := d.Sync.Config.ReflectorInterval
			if interval <= 0 {
				interval = 5 * time.Minute
			}
			nextEndpointPublish = now.Add(interval)
		}
		if !now.Before(nextSync) {
			if latest, err := d.Sync.loadState(); err == nil {
				d.setState(latest)
				lastObservedDigests = gossip.ZoneDigests(d.Sync.State.Network)
			} else {
				fmt.Fprintf(os.Stderr, "daemon reload error: %v\n", err)
			}
			d.Sync.updateDiscoveredPeers()
			digestsBeforeRound := gossip.ZoneDigests(d.Sync.State.Network)
			for _, peerID := range outboundSyncPeers(d.Sync.State, d.Sync.Config) {
				if backoffRemaining(d.Sync.State.SyncPeers[peerID], now) > 0 {
					continue
				}
				err := d.Sync.syncRound(ctx, peerID, 3*time.Second)
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync round error peer=%s: %v\n", peerID, err)
				}
			}
			if syncStateChanged(d.Sync.State, digestsBeforeRound) {
				d.Sync.updateDiscoveredPeers()
				lastObservedDigests = gossip.ZoneDigests(d.Sync.State.Network)
				d.notifyStateChanged()
			}
			nextSync = now.Add(d.Interval)
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
		digestsBefore := gossip.ZoneDigests(d.Sync.State.Network)
		if err := d.Sync.handlePacket(packet); err != nil {
			fmt.Fprintf(os.Stderr, "daemon packet error from %s: %v\n", packet.Message.PeerID, err)
			continue
		}
		if packet.Message.Announce != nil && syncStateChanged(d.Sync.State, digestsBefore) {
			recordUpdateSource(d.Sync.State, packet.Message.PeerID)
			lastObservedDigests = gossip.ZoneDigests(d.Sync.State.Network)
			d.Sync.updateDiscoveredPeers()
			d.notifyStateChanged()
			if err := d.Sync.relay(ctx, packet.Message.PeerID); err != nil {
				fmt.Fprintf(os.Stderr, "sync relay error source=%s: %v\n", packet.Message.PeerID, err)
			}
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
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		writeControlResponse(conn, controlError(err))
		return
	}
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
	case daemonEventSyncTrigger:
		return daemonEventResult{}, true, false
	case daemonEventShutdown:
		return daemonEventResult{}, false, true
	default:
		return daemonEventResult{Error: fmt.Errorf("unknown daemon event: %s", event.Type)}, false, false
	}
}

func (d *DaemonService) handleRecordPutEvent(event *daemonRecordPut) (uint64, error) {
	if event == nil {
		return 0, errors.New("record_put event is nil")
	}
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

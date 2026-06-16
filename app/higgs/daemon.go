package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

type DaemonService struct {
	Sync              *SyncRuntime
	Interval          time.Duration
	ControlSocketPath string
	Events            chan daemonEvent
	Hooks             DaemonHooks
	IPsecDriver       ipsec.IPsecDriver
	XFRMDriver        ipsec.XFRMDriver
	closeIPsecDriver  func() error
	Log               *appLogger
	LogLimiter        *repeatedLogLimiter
	drainingEvents    bool
	ipsecDirty        bool
	routingDirty      bool

	eventLoopSync     bool
	syncSessions      map[string]*SyncSession
	syncEvents        chan SyncEvent
	objectPullResults chan ObjectPullResult
	objectPullPool    *objectPullPool
	timerManager      *TimerManager

	// stateUnlock tracks the unlock function for the stateFile currently locked
	// by the event loop. It is updated by lockState and setState so that deferred
	// unlocks always release the correct stateFile pointer after setState swaps it.
	// stateMu protects stateUnlock and must be held when reading or writing it.
	stateMu     sync.Mutex
	stateUnlock func()

	// Test overrides for BIRD routing reconcile.
	birdProcessManager birdProcessManager
	birdClientFactory  func(socketPath string, timeout time.Duration) birdClient
	vethManager        vethManager
}

type DaemonHooks struct {
	OnStateChanged func(*stateFile)
}

type daemonEventType string

const (
	controlConnDeadline                           = 10 * time.Second
	defaultIPsecReconcileInterval                 = 30 * time.Second
	daemonEventRecordPut          daemonEventType = "record_put"
	daemonEventDelegateIssue      daemonEventType = "delegate_issue"
	daemonEventDelegateRevoke     daemonEventType = "delegate_revoke"
	daemonEventJoinAccept         daemonEventType = "join_accept"
	daemonEventRootInit           daemonEventType = "root_init"
	daemonEventPacket             daemonEventType = "packet"
	daemonEventSyncTimer          daemonEventType = "timer_sync"
	daemonEventEndpointTimer      daemonEventType = "timer_endpoint_publish"
	daemonEventRemoteApplied      daemonEventType = "remote_announce_applied"
	daemonEventSyncTrigger        daemonEventType = "sync_trigger"
	daemonEventReloadConfig       daemonEventType = "reload_config"
	daemonEventShutdown           daemonEventType = "shutdown"
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
	if state != nil && state.Network != nil && state.Network.RecordVerifier == nil {
		configureValidation(state.Network)
	}
	d := &DaemonService{
		Sync:              newSyncRuntime(state, config, nil, rt),
		Interval:          interval,
		ControlSocketPath: socketPath,
		Events:            make(chan daemonEvent, 64),
		Log:               newAppLogger(config),
		LogLimiter:        newRepeatedLogLimiter(30 * time.Second),
	}
	d.eventLoopSync = true
	d.syncSessions = make(map[string]*SyncSession)
	d.syncEvents = make(chan SyncEvent, 64)
	d.objectPullResults = make(chan ObjectPullResult, 64)
	d.objectPullPool = newObjectPullPool(func() *stateFile { return d.Sync.State }, d.Sync.Config, d.objectPullResults, 0)
	d.timerManager = NewTimerManager(NewRealClock(), d.syncEvents)
	return d
}

func (d *DaemonService) Run(ctx context.Context) error {
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.Config == nil {
		return errors.New("daemon service is not initialized")
	}
	if d.IPsecDriver == nil && d.XFRMDriver == nil {
		if err := d.configureIPsecDriversFromConfig(); err != nil {
			return err
		}
	}
	defer d.closeConfiguredIPsecDriver()
	transport, err := d.Sync.openTransport()
	if err != nil {
		return err
	}
	packetCh, stopRecv := startGossipPacketReceiver(ctx, transport, func(c, e string, f map[string]any) { d.logWarn(c, e, f) })
	defer stopRecv()
	objectPullListener, err := startObjectPullServer(d)
	if err != nil {
		d.logError("object_pull", "server_start_failed", map[string]any{"error": err})
	}
	if objectPullListener != nil {
		defer objectPullListener.Close()
	}
	if d.eventLoopSync {
		d.objectPullPool.Start(ctx)
	}
	stopControl, err := d.startControlServer(ctx)
	if err != nil {
		return err
	}
	defer stopControl()
	startFields := map[string]any{
		"peer_id":  d.Sync.Config.PeerID,
		"addr":     transport.LocalAddr(),
		"interval": d.Interval,
	}
	if d.Sync.App != nil {
		startFields["config_path"] = configPath()
		startFields["state_path"] = d.Sync.App.StatePath
	}
	d.logInfo("daemon", "started", startFields)
	logAutoJoinPending(d.Log, d.Sync.State)

	nextSync := d.Sync.now()
	nextEndpointPublish := d.Sync.now()
	ipsecReconcileInterval := d.ipsecReconcileInterval()
	nextIPsecReconcile := nextIPsecReconcileTime(d.Sync.now(), ipsecReconcileInterval)
	routingReconcileInterval := d.routingReconcileInterval()
	nextRoutingReconcile := nextRoutingReconcileTime(d.Sync.now(), routingReconcileInterval)
	lastObservedDigests := d.zoneDigests()
	d.Sync.State.Lock()
	d.Sync.updateDiscoveredPeers()
	d.recoverIPsecLinksOnStart(ctx)
	d.recoverRoutingOnStart(ctx)
	d.Sync.State.Unlock()
	var forceSync bool
	for {
		if ctx.Err() != nil {
			return nil
		}
		now := d.Sync.now()
		syncNow, shutdown, ipsecFlushed, routingFlushed := d.processEvents(ctx)
		if shutdown {
			return nil
		}
		if syncNow {
			nextSync = now
			forceSync = true
		}
		if ipsecFlushed {
			nextIPsecReconcile = nextIPsecReconcileTime(now, ipsecReconcileInterval)
		}
		if interval := d.ipsecReconcileInterval(); interval != ipsecReconcileInterval {
			ipsecReconcileInterval = interval
			nextIPsecReconcile = nextIPsecReconcileTime(now, ipsecReconcileInterval)
		}
		if routingFlushed {
			nextRoutingReconcile = nextRoutingReconcileTime(now, routingReconcileInterval)
		}
		if interval := d.routingReconcileInterval(); interval != routingReconcileInterval {
			routingReconcileInterval = interval
			nextRoutingReconcile = nextRoutingReconcileTime(now, routingReconcileInterval)
		}
		if latest, changed, err := d.Sync.reloadStateIfChanged(lastObservedDigests); err != nil {
			d.logWarn("daemon", "reload_failed", map[string]any{"error": err})
		} else if changed {
			d.setState(latest)
			lastObservedDigests = gossip.ZoneDigests(latest.Network)
			nextSync = now
			forceSync = true
			d.Sync.updateDiscoveredPeers()
			d.notifyStateChanged()
			// setState acquired the lock on the new state; release it before the
			// next iteration so handleEvent can lock the current state.
			d.releaseStateLock()
		}
		if !now.Before(nextEndpointPublish) {
			result, triggerSync, _ := d.handleEvent(daemonEvent{Type: daemonEventEndpointTimer, Context: ctx})
			if result.Error != nil {
				d.logWarn("endpoint", "publish_failed", map[string]any{"error": result.Error})
			}
			if triggerSync {
				nextSync = now
				forceSync = true
				lastObservedDigests = d.zoneDigests()
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
				d.logDebug("sync", "timer_completed_with_error", map[string]any{"error": result.Error})
			}
			d.ipsecDirty = true
			d.routingDirty = true
			if d.flushIPsecReconcile(ctx) {
				nextIPsecReconcile = nextIPsecReconcileTime(now, ipsecReconcileInterval)
			}
			if d.flushRoutingReconcile(ctx) {
				nextRoutingReconcile = nextRoutingReconcileTime(now, routingReconcileInterval)
			}
			if !sameZoneDigests(lastObservedDigests, d.zoneDigests()) {
				lastObservedDigests = d.zoneDigests()
			}
			nextSync = now.Add(d.Interval)
			forceSync = false
		}
		if !nextIPsecReconcile.IsZero() && !now.Before(nextIPsecReconcile) {
			d.ipsecDirty = true
			if d.flushIPsecReconcile(ctx) {
				nextIPsecReconcile = nextIPsecReconcileTime(now, ipsecReconcileInterval)
			}
		}
		if !nextRoutingReconcile.IsZero() && !now.Before(nextRoutingReconcile) {
			d.routingDirty = true
			if d.flushRoutingReconcile(ctx) {
				nextRoutingReconcile = nextRoutingReconcileTime(now, routingReconcileInterval)
			}
		}
		// Wait for the next event. Use a dedicated receiver goroutine so UDP
		// reads block until a packet arrives instead of polling every 250 ms.
		wait := d.nextTimerWait(nextSync, nextEndpointPublish, nextIPsecReconcile, nextRoutingReconcile)
		if wait <= 0 {
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case event := <-d.Events:
			timer.Stop()
			result, triggerSync, stop := d.handleEvent(event)
			if event.Reply != nil {
				event.Reply <- result
			}
			if stop {
				return nil
			}
			if triggerSync {
				nextSync = d.Sync.now()
				forceSync = true
				lastObservedDigests = d.zoneDigests()
			}
		case packet := <-packetCh:
			timer.Stop()
			result, _, _ := d.handleEvent(daemonEvent{Type: daemonEventPacket, Packet: packet, Context: ctx})
			if result.Error != nil {
				d.logWarn("gossip", "packet_failed", map[string]any{
					"peer_id": packet.Message.PeerID,
					"type":    packet.Message.Type,
					"error":   result.Error,
					"reason":  gossip.RejectReason(result.Error),
				})
			}
			if !sameZoneDigests(lastObservedDigests, d.zoneDigests()) {
				lastObservedDigests = d.zoneDigests()
			}
		case event := <-d.syncEvents:
			timer.Stop()
			d.handleSyncEvent(ctx, event)
			if !sameZoneDigests(lastObservedDigests, d.zoneDigests()) {
				lastObservedDigests = d.zoneDigests()
			}
		case result := <-d.objectPullResults:
			timer.Stop()
			select {
			case d.syncEvents <- objectPullResultToEvent(result):
			default:
				d.logWarn("sync", "object_pull_result_dropped", map[string]any{
					"peer_id": result.PeerID,
					"zone":    result.Zone,
				})
			}
		case <-timer.C:
			// Continue the loop; timers will be checked and fired at the top.
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
			d.logWarn("daemon", "control_accept_failed", map[string]any{"error": err})
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
		var linkInstances int
		var desiredLinks int
		var lastLinkError string
		if d.Sync.State != nil {
			d.Sync.State.RLock()
			linkInstances = len(d.Sync.State.LinkInstances)
			desiredLinks = desiredIPsecLinks(d.Sync.State)
			lastLinkError = lastIPsecReconcileError(d.Sync.State)
			d.Sync.State.RUnlock()
		}
		writeControlResponse(conn, controlResponse{
			OK:            true,
			PeerID:        d.Sync.Config.PeerID,
			LinkInstances: linkInstances,
			DesiredLinks:  desiredLinks,
			LastLinkError: lastLinkError,
			Message:       "daemon online",
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
	case "reload":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventReloadConfig})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Message: "config reloaded"})
	case "shutdown":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventShutdown})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Message: "shutdown scheduled"})
	case "bird_status":
		var instances map[string]*BirdInstanceState
		var lastRoutingError string
		if d.Sync.State != nil {
			d.Sync.State.RLock()
			instances = d.Sync.State.BirdInstances
			if d.Sync.State.RoutingReconcile != nil {
				lastRoutingError = d.Sync.State.RoutingReconcile.LastError
			}
			d.Sync.State.RUnlock()
		}
		writeControlResponse(conn, controlResponse{
			OK:               true,
			BirdInstances:    instances,
			LastRoutingError: lastRoutingError,
			Message:          "bird status",
		})
	case "routes_dump":
		if d.Sync.State == nil || d.Sync.State.Network == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		d.Sync.State.RLock()
		ars, err := routing.BuildAuthorizedRouteSet(d.Sync.State.Network, d.Sync.now())
		if err != nil {
			d.Sync.State.RUnlock()
			writeControlResponse(conn, controlError(err))
			return
		}
		routesDump := buildRoutesDumpResponse(d.Sync.State.ManagedZone, ars)
		d.Sync.State.RUnlock()
		writeControlResponse(conn, controlResponse{
			OK:         true,
			RoutesDump: routesDump,
			Message:    "routes dump",
		})
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

func (d *DaemonService) processEvents(ctx context.Context) (syncNow bool, shutdown bool, ipsecFlushed bool, routingFlushed bool) {
	d.drainingEvents = true
	defer func() {
		d.drainingEvents = false
		ipsecFlushed = d.flushIPsecReconcile(ctx)
		routingFlushed = d.flushRoutingReconcile(ctx)
	}()
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
				return syncNow, shutdown, ipsecFlushed, routingFlushed
			}
		default:
			return syncNow, shutdown, ipsecFlushed, routingFlushed
		}
	}
}

func (d *DaemonService) handleEvent(event daemonEvent) (daemonEventResult, bool, bool) {
	unlock := d.lockState()
	defer unlock()
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
	case daemonEventReloadConfig:
		err := d.handleReloadConfigEvent()
		return daemonEventResult{Error: err}, err == nil, false
	case daemonEventShutdown:
		return daemonEventResult{}, false, true
	default:
		return daemonEventResult{Error: fmt.Errorf("unknown daemon event: %s", event.Type)}, false, false
	}
}

func (d *DaemonService) handleReloadConfigEvent() error {
	if d == nil || d.Sync == nil || d.Sync.App == nil {
		return errors.New("daemon service is not initialized")
	}
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	statePath := config.StatePath
	if override := statePathOverride(); override != "" {
		statePath = override
	}
	if d.Sync.App.StatePath != "" && statePath != d.Sync.App.StatePath {
		return fmt.Errorf("reload would change state path from %s to %s; restart daemon to switch state", d.Sync.App.StatePath, statePath)
	}
	socketPath := controlSocketPath(config)
	if d.ControlSocketPath != "" && socketPath != d.ControlSocketPath {
		return fmt.Errorf("reload would change control socket path from %s to %s; restart daemon to switch control socket", d.ControlSocketPath, socketPath)
	}
	latest, err := loadStateAtWithConfig(statePath, config)
	if err != nil {
		return err
	}
	if d.Sync.State != nil && d.Sync.State.IdentityKeyPath != "" && latest.IdentityKeyPath != "" && latest.IdentityKeyPath != d.Sync.State.IdentityKeyPath {
		return fmt.Errorf("reload would change identity.key_path from %s to %s; identity is immutable, use a new data_dir/state_path to create a different node", d.Sync.State.IdentityKeyPath, latest.IdentityKeyPath)
	}
	syncConfig := syncConfigFromAppConfig(config, latest)
	var ipsecDrivers configuredIPsecDrivers
	refreshIPsecDrivers := (d.IPsecDriver == nil && d.XFRMDriver == nil) || d.closeIPsecDriver != nil
	if refreshIPsecDrivers {
		var err error
		ipsecDrivers, err = newConfiguredIPsecDrivers(config.IPsec)
		if err != nil {
			return err
		}
	}
	d.Sync.App.Config = config
	d.Sync.App.StatePath = statePath
	d.Sync.Config = syncConfig
	if refreshIPsecDrivers {
		if err := d.installConfiguredIPsecDrivers(ipsecDrivers); err != nil {
			return err
		}
	}
	d.Log = newAppLogger(syncConfig)
	d.ControlSocketPath = socketPath
	d.setState(latest)
	if d.Sync.Transport != nil {
		d.Sync.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	d.recoverRoutingOnStart(context.Background())
	return nil
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

// processPacketEvent locks the current state and then dispatches to
// handlePacketEvent. It is used by tests and other callers that bypass the
// main Events channel.
func (d *DaemonService) processPacketEvent(packet *gossip.Packet, ctx context.Context) error {
	unlock := d.lockState()
	defer unlock()
	return d.handlePacketEvent(packet, ctx)
}

func (d *DaemonService) handlePacketEvent(packet *gossip.Packet, ctx context.Context) error {
	if packet == nil || packet.Message == nil {
		return errors.New("packet event is nil")
	}
	if d.eventLoopSync {
		return d.handlePacketEventSyncSession(packet, ctx)
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
	if d.eventLoopSync {
		return d.handleSyncTimerEventLoop(ctx, force)
	}
	digestsBeforeRound := gossip.ZoneDigests(d.Sync.State.Network)
	var syncErr error
	peers := outboundSyncPeersAt(d.Sync.State, d.Sync.Config, d.Sync.now())
	peerBackoffs := make(map[string]time.Duration, len(peers))
	for _, peerID := range peers {
		peerBackoffs[peerID] = backoffRemaining(d.Sync.State.SyncPeers[peerID], d.Sync.now())
	}
	d.logDebug("sync", "timer_started", map[string]any{
		"peer_count": len(peers),
		"force":      force,
	})
	// Release the event-loop lock before the synchronous round; syncRound
	// acquires and releases its own lock around state mutations and may block
	// on network I/O.
	d.releaseStateLock()
	for _, peerID := range peers {
		if !force && peerBackoffs[peerID] > 0 {
			d.logDebug("sync", "round_skipped", map[string]any{
				"peer_id": peerID,
				"reason":  "backoff",
				"backoff": peerBackoffs[peerID],
			})
			continue
		}
		start := d.Sync.now()
		if err := d.Sync.syncRound(ctx, peerID, defaultSyncRoundTimeout); err != nil {
			d.logSyncRoundError(peerID, err, d.Sync.now().Sub(start))
			if syncErr == nil {
				syncErr = err
			}
		} else {
			d.logDebug("sync", "round_completed", map[string]any{
				"peer_id":     peerID,
				"duration_ms": d.Sync.now().Sub(start).Milliseconds(),
			})
		}
	}
	// Reacquire the event-loop lock for post-round state mutations. The pointer
	// is still the one set above because no other goroutine replaces it.
	unlock := d.lockState()
	defer unlock()
	if syncStateChanged(d.Sync.State, digestsBeforeRound) {
		d.Sync.updateDiscoveredPeers()
		d.notifyStateChanged()
	}
	return syncErr
}

func (d *DaemonService) zoneDigests() []gossip.ZoneDigest {
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.State.Network == nil {
		return nil
	}
	d.Sync.State.RLock()
	defer d.Sync.State.RUnlock()
	return gossip.ZoneDigests(d.Sync.State.Network)
}

func (d *DaemonService) logSyncRoundError(peerID string, err error, duration time.Duration) {
	if err == nil {
		return
	}
	now := d.Sync.now()
	reason := syncErrorReason(err)
	fields := map[string]any{
		"peer_id":     peerID,
		"reason":      reason,
		"error":       err,
		"duration_ms": duration.Milliseconds(),
	}
	if d.Sync.State != nil {
		d.Sync.State.RLock()
		addPeerLogFields(fields, d.Sync.State, peerID, now)
		d.Sync.State.RUnlock()
	}
	key := "sync_round|" + peerID + "|" + reason + "|" + err.Error()
	if suppressed, ok := d.LogLimiter.Allow(key, now); ok {
		if suppressed > 0 {
			fields["suppressed"] = suppressed
		}
		d.logWarn("sync", "round_failed", fields)
	}
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
	if err := d.Sync.publishIPsecRecords(); err != nil {
		return err
	}
	if err := d.publishRoutingNetnsRecord(); err != nil {
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
	if zs := d.Sync.State.Network.Zones[event.Zone]; zs != nil {
		d.logInfo("daemon", "record_put_persist", map[string]any{
			"zone":         event.Zone,
			"key":          event.Key,
			"record_count": len(zs.Records),
		})
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

// lockState acquires the write lock on the current Sync.State and stores the
// matching unlock function in d.stateUnlock. The returned function must be
// called once to release the lock. It is safe to call when Sync.State is nil.
func (d *DaemonService) lockState() func() {
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		return func() {}
	}
	d.Sync.State.Lock()
	if d.Sync.State.Network != nil && d.Sync.State.Network.RecordVerifier == nil {
		configureValidation(d.Sync.State.Network)
	}
	fn := d.Sync.State.Unlock
	d.stateMu.Lock()
	d.stateUnlock = fn
	d.stateMu.Unlock()
	return func() {
		d.stateMu.Lock()
		fn := d.stateUnlock
		d.stateUnlock = nil
		d.stateMu.Unlock()
		if fn != nil {
			fn()
		}
	}
}

// setState replaces the current state pointer. When called from the event loop
// (i.e. d.stateUnlock is non-nil because lockState acquired the current state
// lock), setState transfers the write lock from the old state to the new state,
// releases the old lock, and updates d.stateUnlock so that the deferred unlock
// from lockState releases the new state. When called without an event-loop
// lock tracked, setState simply assigns the pointer; callers that need
// synchronization must acquire the lock separately.
// releaseStateLock releases the state lock currently tracked by d.stateUnlock
// and clears the tracker. It is used by event handlers that need to drop the
// event-loop lock before a sub-operation (such as the synchronous syncRound)
// acquires its own lock.
func (d *DaemonService) releaseStateLock() {
	if d == nil {
		return
	}
	d.stateMu.Lock()
	fn := d.stateUnlock
	d.stateUnlock = nil
	d.stateMu.Unlock()
	if fn != nil {
		fn()
	}
}

func (d *DaemonService) setState(state *stateFile) {
	if d == nil || d.Sync == nil || d.Sync.State == state {
		return
	}
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	if d.stateUnlock == nil {
		d.Sync.State = state
		return
	}
	state.Lock()
	if state.Network != nil && state.Network.RecordVerifier == nil {
		configureValidation(state.Network)
	}
	old := d.Sync.State
	d.Sync.State = state
	if old != nil {
		old.Unlock()
	}
	d.stateUnlock = state.Unlock
}

func (d *DaemonService) notifyStateChanged() {
	if d.Hooks.OnStateChanged != nil {
		d.Hooks.OnStateChanged(d.Sync.State)
	}
	if d.drainingEvents {
		d.ipsecDirty = true
		d.routingDirty = true
		return
	}
	d.ipsecDirty = true
	d.routingDirty = true
	d.flushIPsecReconcile(context.Background())
	d.flushRoutingReconcile(context.Background())
}

func (d *DaemonService) recoverIPsecLinksOnStart(ctx context.Context) {
	if d == nil {
		return
	}
	d.ipsecDirty = true
	d.flushIPsecReconcile(ctx)
}

func (d *DaemonService) recoverRoutingOnStart(ctx context.Context) {
	if d == nil {
		return
	}
	d.routingDirty = true
	d.flushRoutingReconcile(ctx)
}

func (d *DaemonService) flushRoutingReconcile(ctx context.Context) bool {
	if d == nil || !d.routingDirty {
		return false
	}
	d.routingDirty = false
	if err := d.reconcileRouting(ctx); err != nil {
		d.logWarn("routing", "reconcile_failed", map[string]any{"error": err})
	}
	return true
}

func (d *DaemonService) routingReconcileInterval() time.Duration {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return 0
	}
	instances := routingInstancesEnabled(d.Sync.App.Config)
	if len(instances) == 0 {
		return 0
	}
	return defaultRoutingReconcileInterval
}

func nextRoutingReconcileTime(now time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return time.Time{}
	}
	return now.Add(interval)
}

func (d *DaemonService) flushIPsecReconcile(ctx context.Context) bool {
	if d == nil || !d.ipsecDirty {
		return false
	}
	d.ipsecDirty = false
	if err := d.reconcileIPsecLinks(ctx); err != nil {
		d.logWarn("ipsec", "reconcile_failed", map[string]any{"error": err})
	}
	return true
}

func (d *DaemonService) ipsecReconcileInterval() time.Duration {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return 0
	}
	groups := d.Sync.App.Config.IPsec.LinkGroups
	if len(groups) == 0 {
		if d.Sync.State != nil {
			d.Sync.State.RLock()
			hasLinks := len(d.Sync.State.LinkInstances) > 0
			d.Sync.State.RUnlock()
			if hasLinks {
				return defaultIPsecReconcileInterval
			}
		}
		return 0
	}
	var interval time.Duration
	for _, group := range groups {
		groupInterval := defaultIPsecReconcileInterval
		if group.Reconcile.IntervalSeconds > 0 {
			groupInterval = time.Duration(group.Reconcile.IntervalSeconds) * time.Second
		}
		if interval == 0 || groupInterval < interval {
			interval = groupInterval
		}
	}
	return interval
}

func nextIPsecReconcileTime(now time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return time.Time{}
	}
	return now.Add(interval)
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
	service := newDaemonService(rt, state, config, interval)
	if err := service.configureIPsecDriversFromConfig(); err != nil {
		return err
	}
	return service.Run(ctx)
}

func (d *DaemonService) configureIPsecDriversFromConfig() error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil
	}
	drivers, err := newConfiguredIPsecDrivers(d.Sync.App.Config.IPsec)
	if err != nil {
		return err
	}
	return d.installConfiguredIPsecDrivers(drivers)
}

type configuredIPsecDrivers struct {
	ipsecDriver ipsec.IPsecDriver
	xfrmDriver  ipsec.XFRMDriver
	close       func() error
}

func newConfiguredIPsecDrivers(config ipsecConfig) (configuredIPsecDrivers, error) {
	driver := config.Driver
	if driver == "" {
		driver = ipsecDriverDryRun
	}
	switch driver {
	case ipsecDriverDryRun:
		return configuredIPsecDrivers{}, nil
	case ipsecDriverStrongSwan:
		client, err := ipsec.NewGoviciClient(config.VICISocket)
		if err != nil {
			return configuredIPsecDrivers{}, fmt.Errorf("initialize strongswan vici client: %w", err)
		}
		return configuredIPsecDrivers{
			ipsecDriver: &ipsec.StrongSwanDriver{VICI: client},
			xfrmDriver:  ipsec.NewSystemXFRMDriver(config.DefaultNetNS),
			close:       client.Close,
		}, nil
	default:
		return configuredIPsecDrivers{}, fmt.Errorf("unsupported ipsec driver %q", driver)
	}
}

func (d *DaemonService) installConfiguredIPsecDrivers(drivers configuredIPsecDrivers) error {
	if err := d.closeConfiguredIPsecDriver(); err != nil {
		if drivers.close != nil {
			_ = drivers.close()
		}
		return err
	}
	d.IPsecDriver = drivers.ipsecDriver
	d.XFRMDriver = drivers.xfrmDriver
	d.closeIPsecDriver = drivers.close
	return nil
}

func (d *DaemonService) closeConfiguredIPsecDriver() error {
	if d == nil || d.closeIPsecDriver == nil {
		return nil
	}
	closeFn := d.closeIPsecDriver
	d.closeIPsecDriver = nil
	err := closeFn()
	if err != nil {
		return err
	}
	return nil
}

func (d *DaemonService) logDebug(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Debug(component, event, fields)
	}
}

func (d *DaemonService) logInfo(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Info(component, event, fields)
	}
}

func (d *DaemonService) logWarn(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Warn(component, event, fields)
	}
}

func (d *DaemonService) logError(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Error(component, event, fields)
	}
}

// nextTimerWait returns the duration until the earliest non-zero deadline.
// If no deadline is set, it returns a large value so the caller can wait
// indefinitely for packets, events, or context cancellation. If a deadline is
// already due, it returns 0 or a negative duration.
func (d *DaemonService) nextTimerWait(deadlines ...time.Time) time.Duration {
	now := d.Sync.now()
	var earliest time.Time
	for _, t := range deadlines {
		if t.IsZero() {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	if earliest.IsZero() {
		return 24 * time.Hour
	}
	if !earliest.After(now) {
		return 0
	}
	return earliest.Sub(now)
}

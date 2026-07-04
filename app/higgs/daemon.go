package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Catofes/higgs/internal/observer"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/health"
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
	health            *health.Manager
	healthSpoolMu     sync.Mutex
	observerHub       *observer.Hub
	Log               *appLogger
	LogLimiter        *repeatedLogLimiter
	drainingEvents    bool
	ipsecDirty        bool
	routingDirty      bool
	firewallDirty     bool

	syncSessions      map[string]*SyncSession
	pendingSyncHints  map[string]bool
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
	birdProcessManager  birdProcessManager
	birdProcessManagers map[string]birdProcessManager
	birdClientFactory   func(socketPath string, timeout time.Duration) birdClient
	vethManager         vethManager
	firewallDriver      firewallDriver
}

type DaemonHooks struct {
	OnStateChanged   func(*stateFile)
	OnReconcileFlush func(layer string)
}

type daemonEventType string

const (
	controlConnDeadline                             = 10 * time.Second
	stateReadLockTimeout                            = 2 * time.Second
	defaultDaemonInterval                           = 60 * time.Second
	defaultIPsecReconcileInterval                   = time.Minute
	daemonEventRecordPut            daemonEventType = "record_put"
	daemonEventDelegateIssue        daemonEventType = "delegate_issue"
	daemonEventDelegateRevoke       daemonEventType = "delegate_revoke"
	daemonEventAuthorityGrant       daemonEventType = "authority_grant"
	daemonEventRecoveryImportZone   daemonEventType = "recovery_import_zone"
	daemonEventRecoveryPurgeRevoked daemonEventType = "recovery_purge_revoked"
	daemonEventJoinAccept           daemonEventType = "join_accept"
	daemonEventRootInit             daemonEventType = "root_init"
	daemonEventPacket               daemonEventType = "packet"
	daemonEventSyncTimer            daemonEventType = "timer_sync"
	daemonEventEndpointTimer        daemonEventType = "timer_endpoint_publish"
	daemonEventSyncTrigger          daemonEventType = "sync_trigger"
	daemonEventReloadConfig         daemonEventType = "reload_config"
	daemonEventRoutingReload        daemonEventType = "routing_reload"
	daemonEventIPsecCleanup         daemonEventType = "ipsec_cleanup"
	daemonEventIPsecPortRotate      daemonEventType = "ipsec_port_rotate"
	daemonEventIPsecLifecycle       daemonEventType = "ipsec_lifecycle"
	daemonEventShutdown             daemonEventType = "shutdown"
)

type daemonEvent struct {
	Type        daemonEventType
	RecordPut   *daemonRecordPut
	JoinRequest *joinRequest
	JoinBundle  *joinBundle
	PrivateKey  *privateKeyFile
	Permissions []zone.Permission
	Snapshot    *gossip.ZoneSnapshot
	Zone        zone.ZonePath
	Reason      string
	Apply       bool
	Orphans     bool
	Packet      *gossip.Packet
	VICIEvent   ipsec.VICIEvent
	ForceSync   bool
	Context     context.Context
	Reply       chan daemonEventResult
}

type daemonRecordPut struct {
	Zone  zone.ZonePath
	Key   string
	Value []byte
	Type  string
}

type daemonEventResult struct {
	Version        uint64
	CleanedLinks   int
	CleanedOrphans int
	Zone           zone.ZonePath
	RootPublicKey  []byte
	JoinBundle     *joinBundle
	PortRotate     *manualPortRotateResult
	Records        int
	Delegations    int
	Revocations    int
	Purge          *purgePlan
	Error          error
}

func newDaemonService(rt *Runtime, state *stateFile, config *syncConfigFile, interval time.Duration) *DaemonService {
	if interval <= 0 {
		interval = defaultDaemonInterval
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
	d.syncSessions = make(map[string]*SyncSession)
	d.pendingSyncHints = make(map[string]bool)
	d.syncEvents = make(chan SyncEvent, 64)
	d.objectPullResults = make(chan ObjectPullResult, 64)
	d.objectPullPool = newObjectPullPool(d.objectPullResults, 0)
	d.timerManager = NewTimerManager(NewRealClock(), d.syncEvents)
	d.configureHealthManager()
	return d
}

// configureHealthManager initializes the health probe manager from app config.
// When health probing is disabled (the default), d.health remains nil and all
// health-related operations become no-ops.
func (d *DaemonService) configureHealthManager() {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return
	}
	cfg := d.Sync.App.Config.Health
	if !cfg.Enabled {
		return
	}
	d.health = newHealthManager(cfg, health.NewICMProber(nil, health.NewUDPProber(nil)))
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
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.stopManagedBirdInstances(shutdownCtx, false); err != nil {
			d.logWarn("routing", "bird_shutdown_failed", map[string]any{"error": err})
		}
	}()
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
	d.objectPullPool.Start(ctx)
	stopControl, err := d.startControlServer(ctx)
	if err != nil {
		return err
	}
	defer stopControl()
	stopObserver, err := d.startObserverServer(ctx)
	if err != nil {
		return err
	}
	defer stopObserver()
	stopIPsecEvents := d.startIPsecLifecycleEventWatcher(ctx)
	defer stopIPsecEvents()
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
	if d.Sync.State != nil {
		updateAdmissionOnPending(d.Sync.State, d.Sync.now())
	}
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
	d.recoverFirewallOnStart(ctx)
	d.Sync.State.Unlock()
	var forceSync bool
	for {
		if ctx.Err() != nil {
			return nil
		}
		now := d.Sync.now()
		syncNow, shutdown, ipsecFlushed, routingFlushed, firewallFlushed := d.processEvents(ctx)
		if shutdown {
			return nil
		}
		_ = firewallFlushed
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
				d.logWarn("gossip", "packet_failed", addGossipErrorFields(map[string]any{
					"peer_id": packet.Message.PeerID,
					"type":    packet.Message.Type,
					"error":   result.Error,
					"reason":  gossip.RejectReason(result.Error),
				}, result.Error))
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
			unlock := d.lockState()
			recordObjectPullResult(d.Sync.State, result.PeerID, "zone", result.Zone, "", result.Bytes, result.Err, result.Unreachable, d.Sync.now())
			unlock()
			d.enqueueObjectPullResult(result)
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
		if state := d.currentState(); state != nil {
			unlock, ok := tryStateRLockWithin(state, stateReadLockTimeout)
			if !ok {
				writeControlResponse(conn, controlError(errors.New("daemon state lock busy")))
				return
			}
			linkInstances = len(state.LinkInstances)
			desiredLinks = desiredIPsecLinks(state)
			lastLinkError = lastIPsecReconcileError(state)
			unlock()
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
	case "record_get":
		if err := validateControlRecordGet(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		state := d.currentState()
		if state == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		unlock, ok := tryStateRLockWithin(state, stateReadLockTimeout)
		if !ok {
			writeControlResponse(conn, controlError(errors.New("daemon state lock busy")))
			return
		}
		record, err := lookupRecordJSON(state, zone.ZonePath(request.Zone), request.Key, request.History)
		unlock()
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Record: record})
	case "delegate_issue":
		if err := validateControlDelegateIssue(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:        daemonEventDelegateIssue,
			JoinRequest: request.JoinRequest,
			Permissions: request.Permissions,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Zone: result.Zone, JoinBundle: result.JoinBundle})
	case "authority_grant":
		if err := validateControlAuthorityGrant(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:        daemonEventAuthorityGrant,
			Zone:        zone.ZonePath(request.Zone),
			Permissions: request.Permissions,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Zone: result.Zone, JoinBundle: result.JoinBundle})
	case "recovery_import_zone":
		if err := validateControlRecoveryImportZone(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:     daemonEventRecoveryImportZone,
			Snapshot: request.Snapshot,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{
			OK:             true,
			Zone:           result.Zone,
			RecordsApplied: result.Records,
			Delegations:    result.Delegations,
			Revocations:    result.Revocations,
		})
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
	case "recovery_purge_revoked":
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:  daemonEventRecoveryPurgeRevoked,
			Zone:  zone.ZonePath(request.Zone),
			Apply: request.Apply,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, PurgePlan: result.Purge})
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
	case "routing_reload":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventRoutingReload})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Message: "routing reloaded"})
	case "ipsec_cleanup":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventIPsecCleanup, Orphans: request.Orphans})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, CleanedLinks: result.CleanedLinks, CleanedOrphans: result.CleanedOrphans, Message: "ipsec links cleaned"})
	case "ipsec_rotate_port":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventIPsecPortRotate})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, PortRotate: result.PortRotate, Message: "ipsec port rotate scheduled"})
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
		if state := d.currentState(); state != nil {
			unlock, ok := tryStateRLockWithin(state, stateReadLockTimeout)
			if !ok {
				writeControlResponse(conn, controlError(errors.New("daemon state lock busy")))
				return
			}
			instances = cloneBirdInstances(state.BirdInstances)
			if state.RoutingReconcile != nil {
				lastRoutingError = state.RoutingReconcile.LastError
			}
			unlock()
		}
		writeControlResponse(conn, controlResponse{
			OK:               true,
			BirdInstances:    instances,
			LastRoutingError: lastRoutingError,
			Message:          "bird status",
		})
	case "bird_dump":
		if strings.ContainsAny(request.Command, "\r\n") {
			writeControlResponse(conn, controlError(errors.New("bird_dump command must be a single line")))
			return
		}
		dump := d.birdDumpForControl(ctx, request.NetNS, request.Command)
		writeControlResponse(conn, controlResponse{
			OK:       true,
			BirdDump: dump,
			Message:  "bird dump",
		})
	case "routes_dump":
		state := d.currentState()
		if state == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		var routingInstances []RoutingInstance
		if d.Sync != nil && d.Sync.App != nil && d.Sync.App.Config != nil {
			routingInstances = append([]RoutingInstance(nil), d.Sync.App.Config.Routing.Instances...)
		}
		unlock, ok := tryStateRLockWithin(state, stateReadLockTimeout)
		if !ok {
			writeControlResponse(conn, controlError(errors.New("daemon state lock busy")))
			return
		}
		if state.Network == nil {
			unlock()
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		ars, err := routing.BuildAuthorizedRouteSet(state.Network, d.Sync.now())
		if err != nil {
			unlock()
			writeControlResponse(conn, controlError(err))
			return
		}
		routesDump := buildRoutesDumpResponse(state.ManagedZone, ars)
		birdStates := cloneBirdInstances(state.BirdInstances)
		unlock()
		routesDump.BIRD = d.birdRoutesForControl(ctx, routesDump, routingInstances, birdStates)
		writeControlResponse(conn, controlResponse{
			OK:         true,
			RoutesDump: routesDump,
			Message:    "routes dump",
		})
	case "admission_status":
		state := d.currentState()
		if state == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		unlock, ok := tryStateRLockWithin(state, stateReadLockTimeout)
		if !ok {
			writeControlResponse(conn, controlError(errors.New("daemon state lock busy")))
			return
		}
		diagnosis := diagnoseAutoJoinAdmission(state, d.Sync.now())
		unlock()
		writeControlResponse(conn, controlResponse{
			OK:        true,
			PeerID:    d.Sync.Config.PeerID,
			Admission: &diagnosis,
			Message:   "admission status",
		})
	case "firewall_status":
		state := d.currentState()
		if state == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		unlock, ok := tryStateRLockWithin(state, stateReadLockTimeout)
		if !ok {
			writeControlResponse(conn, controlError(errors.New("daemon state lock busy")))
			return
		}
		fwSnapshot := cloneFirewallReconcileState(state.FirewallReconcile)
		unlock()
		writeControlResponse(conn, controlResponse{
			OK:                true,
			FirewallReconcile: fwSnapshot,
			Message:           "firewall status",
		})
	case "links_status":
		state := d.currentState()
		if state == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		unlock, ok := tryStateRLockWithin(state, stateReadLockTimeout)
		if !ok {
			writeControlResponse(conn, controlError(errors.New("daemon state lock busy")))
			return
		}
		build := buildLinkInspectionFromReconcile(observerRuntime(d), state, d.healthStatusResponse())
		links := linkInspectionControlFromBuild(build)
		if state.IPsecReconcile != nil {
			links.ActualSAs = append([]linkSAState(nil), state.IPsecReconcile.ActualSAs...)
		}
		unlock()
		writeControlResponse(conn, controlResponse{
			OK:      true,
			PeerID:  d.Sync.Config.PeerID,
			Links:   links,
			Message: "links status",
		})
	case "peers_status":
		if d.currentState() == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		peerStatuses := d.peerStatusSnapshotForControl()
		writeControlResponse(conn, controlResponse{
			OK:           true,
			PeerID:       d.Sync.Config.PeerID,
			PeerStatuses: peerStatuses,
			Message:      "peers status",
		})
	case "revoke_status":
		state := d.currentState()
		if state == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		unlock, ok := tryStateRLockWithin(state, stateReadLockTimeout)
		if !ok {
			writeControlResponse(conn, controlError(errors.New("daemon state lock busy")))
			return
		}
		impacts := AllRevocationImpact(state, d.Sync.Config, d.Sync.now())
		unlock()
		writeControlResponse(conn, controlResponse{
			OK:               true,
			PeerID:           d.Sync.Config.PeerID,
			RevocationImpact: impacts,
			Message:          "revoke status",
		})
	case "health_status":
		writeControlResponse(conn, controlResponse{
			OK:      true,
			PeerID:  d.Sync.Config.PeerID,
			Health:  d.healthStatusResponse(),
			Message: "health status",
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

func (d *DaemonService) processEvents(ctx context.Context) (syncNow bool, shutdown bool, ipsecFlushed bool, routingFlushed bool, firewallFlushed bool) {
	d.drainingEvents = true
	defer func() {
		d.drainingEvents = false
		// Phase 6.5 deny-first order: revocation cleanup → firewall → routing
		// → IPsec → revocation cleanup again. This ensures revoked prefixes
		// and peer entries are removed from allow sets before any layer can
		// re-accept traffic from the revoked subtree.
		d.flushRevocationCleanup()
		firewallFlushed = d.flushFirewallReconcile(ctx)
		routingFlushed = d.flushRoutingReconcile(ctx)
		ipsecFlushed = d.flushIPsecReconcile(ctx) || ipsecFlushed
		d.flushRevocationCleanup()
	}()
	for {
		select {
		case event := <-d.Events:
			result, triggerSync, stop := d.handleEvent(event)
			if event.Type == daemonEventIPsecCleanup && result.Error == nil {
				ipsecFlushed = d.flushIPsecReconcile(ctx) || ipsecFlushed
			}
			if event.Reply != nil {
				event.Reply <- result
			}
			syncNow = syncNow || triggerSync
			shutdown = shutdown || stop
			if shutdown {
				return syncNow, shutdown, ipsecFlushed, routingFlushed, firewallFlushed
			}
		default:
			return syncNow, shutdown, ipsecFlushed, routingFlushed, firewallFlushed
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
		result, err := d.handleDelegateIssueEvent(event.JoinRequest, event.Permissions)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		return daemonEventResult{Zone: result.Zone, JoinBundle: result.Bundle}, true, false
	case daemonEventAuthorityGrant:
		bundle, err := d.handleAuthorityGrantEvent(event.Zone, event.Permissions)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		return daemonEventResult{Zone: event.Zone, JoinBundle: bundle}, true, false
	case daemonEventRecoveryImportZone:
		result, revocations, err := d.handleRecoveryImportZoneEvent(event.Snapshot)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		return daemonEventResult{
			Zone:        result.Zone,
			Records:     result.Records,
			Delegations: result.Delegation,
			Revocations: revocations,
		}, true, false
	case daemonEventDelegateRevoke:
		err := d.handleDelegateRevokeEvent(event.Zone, event.Reason)
		return daemonEventResult{Zone: event.Zone, Error: err}, err == nil, false
	case daemonEventRecoveryPurgeRevoked:
		plan, err := d.handleRecoveryPurgeRevokedEvent(controlContext(event.Context), event.Zone, event.Apply)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		// State only changes when applying; dry-run just reports the plan.
		return daemonEventResult{Purge: plan}, event.Apply, false
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
	case daemonEventSyncTrigger:
		return daemonEventResult{}, true, false
	case daemonEventReloadConfig:
		err := d.handleReloadConfigEvent()
		return daemonEventResult{Error: err}, err == nil, false
	case daemonEventRoutingReload:
		d.routingDirty = true
		d.flushRoutingReconcile(controlContext(event.Context))
		return daemonEventResult{}, false, false
	case daemonEventIPsecCleanup:
		cleaned, orphans, err := d.handleIPsecCleanupEvent(controlContext(event.Context), event.Orphans)
		if err == nil {
			d.ipsecDirty = true
		}
		return daemonEventResult{CleanedLinks: cleaned, CleanedOrphans: orphans, Error: err}, false, false
	case daemonEventIPsecPortRotate:
		result, err := d.handleIPsecPortRotateEvent()
		return daemonEventResult{PortRotate: result, Error: err}, err == nil, false
	case daemonEventIPsecLifecycle:
		d.handleIPsecLifecycleEvent(event.VICIEvent)
		return daemonEventResult{}, false, false
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
		ipsecDrivers, err = newConfiguredIPsecDrivers(config.IPsec, func(event string, fields map[string]any) {
			d.logDebug("ipsec", event, fields)
		})
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

func (d *DaemonService) handleDelegateIssueEvent(request *joinRequest, permissions []zone.Permission) (*delegationIssueResult, error) {
	latest, err := d.Sync.loadState()
	if err != nil {
		return nil, err
	}
	d.setState(latest)
	result, err := issueDelegationInState(d.Sync.App, d.Sync.State, request, permissions)
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

func (d *DaemonService) handleAuthorityGrantEvent(path zone.ZonePath, permissions []zone.Permission) (*joinBundle, error) {
	latest, err := d.Sync.loadState()
	if err != nil {
		return nil, err
	}
	d.setState(latest)
	bundle, err := grantAuthorityInState(d.Sync.App, d.Sync.State, path, permissions)
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
	return bundle, nil
}

func (d *DaemonService) handleRecoveryImportZoneEvent(snapshot *gossip.ZoneSnapshot) (*gossip.ApplyResult, int, error) {
	latest, err := d.Sync.loadState()
	if err != nil {
		return nil, 0, err
	}
	d.setState(latest)
	result, err := applyRecoveryZoneSnapshot(d.Sync.App, d.Sync.State, snapshot)
	if err != nil {
		return nil, 0, err
	}
	if err := d.Sync.saveState(); err != nil {
		return nil, 0, err
	}
	revocations := 0
	if zs := d.Sync.State.Network.Zones[result.Zone]; zs != nil {
		revocations = len(zs.Revocations)
	}
	if d.Sync.Transport != nil {
		d.Sync.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return result, revocations, nil
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

// handleRecoveryPurgeRevokedEvent runs the manual revoked-zone GC. It always
// computes the plan (returned for reporting); when apply is true it also
// executes the deletions, persists, and notifies subsystems so the running node
// reconciles (e.g. tears down orphaned IPsec for removed link instances).
func (d *DaemonService) handleRecoveryPurgeRevokedEvent(ctx context.Context, target zone.ZonePath, apply bool) (*purgePlan, error) {
	latest, err := d.Sync.loadState()
	if err != nil {
		return nil, err
	}
	d.setState(latest)
	plan, err := planPurgeRevokedZones(d.Sync.State, d.Sync.App.Now(), target)
	if err != nil {
		return nil, err
	}
	if !apply {
		return plan, nil
	}
	if err := d.cleanupPurgePlanIPsecLinks(ctx, plan); err != nil {
		return nil, err
	}
	executePurgePlan(d.Sync.State, plan)
	if err := d.Sync.saveState(); err != nil {
		return nil, err
	}
	if d.Sync.Transport != nil {
		d.Sync.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return plan, nil
}

func (d *DaemonService) cleanupPurgePlanIPsecLinks(ctx context.Context, plan *purgePlan) error {
	if plan == nil || len(plan.LinkInstances) == 0 {
		return nil
	}
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.App == nil {
		return errors.New("daemon service is not initialized")
	}
	ipsecDriver := d.IPsecDriver
	xfrmDriver := d.XFRMDriver
	var closeFn func() error
	if ipsecDriver == nil || xfrmDriver == nil {
		drivers, err := newIPsecCleanupDrivers(d.Sync.App.Config)
		if err != nil {
			return err
		}
		ipsecDriver = drivers.ipsecDriver
		xfrmDriver = drivers.xfrmDriver
		closeFn = drivers.close
	}
	if closeFn != nil {
		defer func() { _ = closeFn() }()
	}
	_, err := cleanupIPsecLinkInstancesByID(ctx, d.Sync.State, plan.LinkInstances, ipsecDriver, xfrmDriver, d.Sync.now())
	return err
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
	return d.handlePacketEventSyncSession(packet, ctx)
}

func (d *DaemonService) handleSyncTimerEvent(ctx context.Context, force bool) error {
	latest, err := d.Sync.loadState()
	if err != nil {
		return fmt.Errorf("daemon reload: %w", err)
	}
	d.setState(latest)
	d.Sync.updateDiscoveredPeers()
	return d.handleSyncTimerEventLoop(ctx, force)
}

func (d *DaemonService) zoneDigests() []gossip.ZoneDigest {
	if d == nil || d.Sync == nil || d.Sync.State == nil || d.Sync.State.Network == nil {
		return nil
	}
	d.Sync.State.RLock()
	defer d.Sync.State.RUnlock()
	return gossip.ZoneDigests(d.Sync.State.Network)
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

func (d *DaemonService) handleIPsecPortRotateEvent() (*manualPortRotateResult, error) {
	latest, err := d.Sync.loadState()
	if err != nil {
		return nil, err
	}
	d.setState(latest)
	result, err := forceLocalIPsecPortRotate(d.Sync.App.Config, d.Sync.State, d.Sync.now())
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

func (d *DaemonService) currentState() *stateFile {
	if d == nil || d.Sync == nil {
		return nil
	}
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	return d.Sync.State
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
// event-loop lock before a sub-operation that acquires its own lock.
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
	// Phase 6.7: notify the read-only observer so it can push SSE events.
	d.notifyObserver("state_changed", nil)
	// Phase 6.5: clean gossip peer cache for revoked zones before triggering
	// layer reconciles. This ensures revoked peers don't appear as discovered
	// endpoints, observed paths or object-pull candidates when the downstream
	// layers recompute desired state. The deny-first cleanup happens before
	// firewall/routing/IPsec flush so that allow sets and desired links are
	// computed without revoked entries.
	d.flushRevocationCleanup()

	if d.drainingEvents {
		d.ipsecDirty = true
		d.routingDirty = true
		d.firewallDirty = true
		return
	}
	d.ipsecDirty = true
	d.routingDirty = true
	d.firewallDirty = true
	d.flushFirewallReconcile(context.Background())
	d.notifyObserver("route_changed", nil)
	d.notifyObserver("bird_updated", nil)
	d.flushRoutingReconcile(context.Background())
	d.flushIPsecReconcile(context.Background())
	d.notifyObserver("link_updated", nil)
	// Gossip peer cache cleanup runs again after teardown to ensure observed
	// paths discovered/refreshed during the flush are cleared.
	d.flushRevocationCleanup()
	d.notifyObserver("peer_updated", nil)
	d.notifyObserver("health_updated", nil)
}

func (d *DaemonService) noteReconcileFlush(layer string) {
	if d != nil && d.Hooks.OnReconcileFlush != nil {
		d.Hooks.OnReconcileFlush(layer)
	}
}

// flushRevocationCleanup clears runtime-relevant fields from SyncPeers entries
// whose zone is currently revoked. This implements Phase 6.5.5 gossip peer
// cache cleanup: revoked peers must not maintain discovered endpoints,
// observed paths, backoff or object-pull candidates. The entry itself is
// retained with a "revoked" marker for diagnostics; it is removed via the
// normal offline cleanup policy after the cleanup_after retention window.
func (d *DaemonService) flushRevocationCleanup() {
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		return
	}
	state := d.Sync.State
	if d.hasStateLock() {
		d.flushRevocationCleanupLocked(state)
		return
	}
	state.Lock()
	defer state.Unlock()
	d.flushRevocationCleanupLocked(state)
}

func (d *DaemonService) hasStateLock() bool {
	if d == nil {
		return false
	}
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	return d.stateUnlock != nil
}

func (d *DaemonService) flushRevocationCleanupLocked(state *stateFile) {
	if d == nil || d.Sync == nil || state == nil || state.Network == nil {
		return
	}
	now := d.Sync.now()
	revokedZones := CollectAllRevokedZones(state, now)
	if len(revokedZones) == 0 {
		return
	}
	d.noteReconcileFlush("revocation_cleanup")
	CleanupRevokedPeerCache(state, revokedZones)
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
	d.noteReconcileFlush("routing")
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
	d.noteReconcileFlush("ipsec")
	if err := d.reconcileIPsecLinks(ctx); err != nil {
		d.logWarn("ipsec", "reconcile_failed", map[string]any{"error": err})
	}
	// Phase 6.6: after IPsec reconcile, refresh health probe targets and
	// dispatch any due probes. This keeps the probe scheduler in sync with
	// link create/update/teardown without adding a separate timer path.
	d.reconcileHealth(ctx)
	return true
}

type ipsecLifecycleEventSubscriber interface {
	SubscribeLifecycleEvents(context.Context) (<-chan ipsec.VICIEvent, func(), error)
}

func (d *DaemonService) startIPsecLifecycleEventWatcher(ctx context.Context) func() {
	subscriber, ok := d.IPsecDriver.(ipsecLifecycleEventSubscriber)
	if !ok || subscriber == nil {
		return func() {}
	}
	events, stop, err := subscriber.SubscribeLifecycleEvents(ctx)
	if err != nil {
		d.logWarn("ipsec", "vici_event_subscribe_failed", map[string]any{"error": err})
		return func() {}
	}
	go func() {
		for ev := range events {
			select {
			case d.Events <- daemonEvent{Type: daemonEventIPsecLifecycle, VICIEvent: ev}:
			default:
				d.logWarn("ipsec", "vici_event_dropped", map[string]any{
					"reason":     "daemon_events_full",
					"event_name": ev.Name,
					"connection": ev.Connection,
					"child":      ev.ChildSA,
				})
			}
		}
	}()
	return func() {
		if stop != nil {
			stop()
		}
	}
}

func (d *DaemonService) handleIPsecLifecycleEvent(ev ipsec.VICIEvent) {
	d.ipsecDirty = true
	d.logDebug("ipsec", "vici_lifecycle_event", map[string]any{
		"event_name": ev.Name,
		"connection": ev.Connection,
		"child":      ev.ChildSA,
		"up":         ev.Up,
		"xfrm_if_id": ev.XFRMIfID,
		"reqid":      ev.ReqID,
		"local_id":   ev.LocalIdentity,
		"remote_id":  ev.RemoteIdentity,
		"local_ep":   ev.LocalEndpoint,
		"remote_ep":  ev.RemoteEndpoint,
	})
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
	drivers, err := newConfiguredIPsecDrivers(d.Sync.App.Config.IPsec, func(event string, fields map[string]any) {
		d.logDebug("ipsec", event, fields)
	})
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

func newConfiguredIPsecDrivers(config ipsecConfig, logConfig func(event string, fields map[string]any)) (configuredIPsecDrivers, error) {
	driver := config.Driver
	if driver == "" {
		driver = ipsecDriverStrongSwan
	}
	switch driver {
	case ipsecDriverDryRun:
		return configuredIPsecDrivers{}, nil
	case ipsecDriverStrongSwan:
		if len(config.LinkGroups) == 0 {
			return configuredIPsecDrivers{}, nil
		}
		client, err := ipsec.NewReconnectingGoviciClient(config.VICISocket)
		if err != nil {
			return configuredIPsecDrivers{}, fmt.Errorf("initialize strongswan vici client: %w", err)
		}
		initiateClientFactory := func() (ipsec.VICIClient, func() error, error) {
			client, err := ipsec.NewGoviciClient(config.VICISocket)
			if err != nil {
				return nil, nil, err
			}
			return client, client.Close, nil
		}
		return configuredIPsecDrivers{
			ipsecDriver: &ipsec.StrongSwanDriver{
				VICI:                  client,
				LogConfig:             logConfig,
				InitiateAsync:         true,
				InitiateClientFactory: initiateClientFactory,
			},
			xfrmDriver: ipsec.NewSystemXFRMDriver(config.DefaultNetNS),
			close:      client.Close,
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

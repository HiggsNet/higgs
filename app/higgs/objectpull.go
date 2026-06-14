package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

const maxObjectPullConcurrency = 4
const maxObjectPullServerConcurrency = 16
const maxObjectPullPerPeerInflight = 2
const objectPullClientDialTimeout = 1500 * time.Millisecond
const objectPullClientIOTimeout = 3 * time.Second
const objectPullServerConnDeadline = 10 * time.Second

var objectPullClientLimiter = make(chan struct{}, maxObjectPullConcurrency)
var objectPullServerLimiter = make(chan struct{}, maxObjectPullServerConcurrency)
var objectPullPeerLimiter = newObjectPullPeerLimiter(maxObjectPullPerPeerInflight)
var objectPullQuota = newLockedPeerQuotas(gossip.QuotaConfig{
	ByteRate:    8 << 20,
	ByteBurst:   8 << 20,
	ObjectRate:  16,
	ObjectBurst: 16,
})

type objectPullPeerInflight struct {
	limit int
	mu    sync.Mutex
	used  map[string]int
}

func newObjectPullPeerLimiter(limit int) *objectPullPeerInflight {
	return &objectPullPeerInflight{
		limit: limit,
		used:  make(map[string]int),
	}
}

func (l *objectPullPeerInflight) acquire(peerID string) (func(), error) {
	if l == nil || l.limit <= 0 || peerID == "" {
		return func() {}, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used[peerID] >= l.limit {
		return nil, fmt.Errorf("object pull per-peer inflight limit reached for %s (%d)", peerID, l.limit)
	}
	l.used[peerID]++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.used[peerID]--
		if l.used[peerID] <= 0 {
			delete(l.used, peerID)
		}
	}, nil
}

type lockedPeerQuotas struct {
	mu     sync.Mutex
	quotas *gossip.PeerQuotas
}

func newLockedPeerQuotas(config gossip.QuotaConfig) *lockedPeerQuotas {
	return &lockedPeerQuotas{quotas: gossip.NewPeerQuotas(config)}
}

func (q *lockedPeerQuotas) allow(peerID string, bytes int64, objects int64, now time.Time) error {
	if q == nil || peerID == "" {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.quotas.Allow(peerID, bytes, objects, now)
}

func acquireObjectPullServerSlot() (func(), bool) {
	select {
	case objectPullServerLimiter <- struct{}{}:
		return func() { <-objectPullServerLimiter }, true
	default:
		return nil, false
	}
}

// objectPullTCPServe starts a minimal TCP server that serves ZoneSnapshot and
// RecordSnapshot objects over length-prefixed msgpack framing.
func objectPullTCPServe(addr string, lookup func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse) (net.Listener, error) {
	if addr == "" {
		return nil, nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			release, ok := acquireObjectPullServerSlot()
			if !ok {
				_ = conn.Close()
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				defer release()
				_ = c.SetDeadline(time.Now().Add(objectPullServerConnDeadline))
				req, err := gossip.DecodeObjectPullRequest(c)
				if err != nil {
					return
				}
				resp := lookup(req)
				if resp == nil {
					resp = &gossip.ObjectPullResponse{Error: "not found"}
				}
				data, err := gossip.EncodeObjectPullResponse(resp)
				if err != nil {
					return
				}
				_ = c.SetDeadline(time.Now().Add(objectPullServerConnDeadline))
				_, _ = c.Write(data)
			}(conn)
		}
	}()
	return listener, nil
}

// objectPullTCPAddr derives the default TCP object-pull address from a UDP
// endpoint address. TCP and UDP can share the same numeric port.
func objectPullTCPAddr(udpAddr string) string {
	udp, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return ""
	}
	tcp := &net.TCPAddr{IP: udp.IP, Port: udp.Port}
	return tcp.String()
}

// pullObjectTCP attempts to fetch an object from a peer via TCP.
func pullObjectTCP(addr string, req *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	return pullObjectTCPForPeer("", addr, req)
}

func pullObjectTCPForPeer(peerID, addr string, req *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	return pullObjectTCPForPeerUntil(peerID, addr, req, time.Time{})
}

func pullObjectTCPForPeerUntil(peerID, addr string, req *gossip.ObjectPullRequest, deadline time.Time) (*gossip.ObjectPullResponse, error) {
	select {
	case objectPullClientLimiter <- struct{}{}:
		defer func() { <-objectPullClientLimiter }()
	default:
		return nil, fmt.Errorf("object pull concurrency limit reached (%d)", maxObjectPullConcurrency)
	}
	releasePeer, err := objectPullPeerLimiter.acquire(peerID)
	if err != nil {
		return nil, err
	}
	defer releasePeer()

	data, err := gossip.EncodeObjectPullRequest(req)
	if err != nil {
		return nil, err
	}
	if err := objectPullQuota.allow(peerID, int64(len(data)), 1, time.Now()); err != nil {
		return nil, err
	}
	dialTimeout, err := objectPullClientTimeoutUntil(deadline, objectPullClientDialTimeout)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ioDeadline, err := objectPullClientDeadlineUntil(deadline, objectPullClientIOTimeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(ioDeadline)
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}
	ioDeadline, err = objectPullClientDeadlineUntil(deadline, objectPullClientIOTimeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(ioDeadline)
	resp, err := gossip.DecodeObjectPullResponse(conn)
	if err != nil {
		return nil, err
	}
	if err := objectPullQuota.allow(peerID, int64(encodedObjectPullResponseSize(resp)), 1, time.Now()); err != nil {
		return nil, err
	}
	return resp, nil
}

func objectPullClientTimeoutUntil(deadline time.Time, maxTimeout time.Duration) (time.Duration, error) {
	if maxTimeout <= 0 {
		return 0, context.DeadlineExceeded
	}
	if deadline.IsZero() {
		return maxTimeout, nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, context.DeadlineExceeded
	}
	if remaining < maxTimeout {
		return remaining, nil
	}
	return maxTimeout, nil
}

func objectPullClientDeadlineUntil(deadline time.Time, maxTimeout time.Duration) (time.Time, error) {
	timeout, err := objectPullClientTimeoutUntil(deadline, maxTimeout)
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().Add(timeout), nil
}

// objectPullLookup returns a function that can be passed to objectPullTCPServe.
// It accepts a getter so that the daemon can reload state without invalidating
// the closure.
func objectPullLookup(getState func() *stateFile) func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
	return func(req *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
		state := getState()
		if state == nil || state.Network == nil || req == nil || !req.Zone.Valid() {
			return &gossip.ObjectPullResponse{Error: "invalid request"}
		}
		configureValidation(state.Network)
		now := time.Now()
		switch req.Type {
		case gossip.ObjectPullZone:
			if state.Network.IsZoneRevoked(req.Zone, now) {
				return &gossip.ObjectPullResponse{Error: "zone revoked"}
			}
			snapshot, err := gossip.Snapshot(state.Network, req.Zone)
			if err != nil {
				return &gossip.ObjectPullResponse{Error: err.Error()}
			}
			return &gossip.ObjectPullResponse{OK: true, Snapshot: snapshot}
		case gossip.ObjectPullRecord:
			if req.Key == "" {
				return &gossip.ObjectPullResponse{Error: "missing key"}
			}
			record, err := gossip.RecordSnapshotFor(state.Network, &gossip.FetchRecord{
				Zone:    req.Zone,
				Key:     req.Key,
				Version: req.Version,
			})
			if err != nil {
				return &gossip.ObjectPullResponse{Error: err.Error()}
			}
			return &gossip.ObjectPullResponse{OK: true, Record: record}
		default:
			return &gossip.ObjectPullResponse{Error: "unsupported request type"}
		}
	}
}

// tryObjectPullTCP attempts to pull a zone snapshot over TCP from a peer.
// It derives the TCP address from the peer's discovered or bootstrap UDP address.
func tryObjectPullTCP(state *stateFile, config *syncConfigFile, peerID string, path zone.ZonePath) (*gossip.ZoneSnapshot, error) {
	return tryObjectPullTCPUntil(state, config, peerID, path, time.Time{})
}

func tryObjectPullTCPUntil(state *stateFile, config *syncConfigFile, peerID string, path zone.ZonePath, deadline time.Time) (*gossip.ZoneSnapshot, error) {
	addr := resolvePeerTCPAddr(state, config, peerID)
	if addr == "" {
		err := fmt.Errorf("no TCP address for peer %s", peerID)
		recordObjectPullResult(state, peerID, "zone", path, "", 0, err, true, time.Now())
		return nil, err
	}
	recordObjectPullAttempt(state, peerID, "zone", path, "", time.Now())
	resp, err := pullObjectTCPForPeerUntil(peerID, addr, &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullZone,
		Zone: path,
	}, deadline)
	if err != nil {
		recordObjectPullResult(state, peerID, "zone", path, "", 0, err, isObjectPullUnreachable(err), time.Now())
		return nil, err
	}
	respBytes := encodedObjectPullResponseSize(resp)
	if !resp.OK {
		err := fmt.Errorf("object pull failed: %s", resp.Error)
		recordObjectPullResult(state, peerID, "zone", path, "", respBytes, err, false, time.Now())
		return nil, err
	}
	if resp.Snapshot == nil {
		err := fmt.Errorf("object pull returned empty snapshot")
		recordObjectPullResult(state, peerID, "zone", path, "", respBytes, err, false, time.Now())
		return nil, err
	}
	recordObjectPullResult(state, peerID, "zone", path, "", respBytes, nil, false, time.Now())
	return resp.Snapshot, nil
}

func encodedObjectPullResponseSize(resp *gossip.ObjectPullResponse) int {
	data, err := gossip.EncodeObjectPullResponse(resp)
	if err != nil {
		return 0
	}
	return len(data)
}

func isObjectPullUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func recordObjectPullAttempt(state *stateFile, peerID, object string, zoneName zone.ZonePath, key string, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if peerState.ObjectPullStats == nil {
		peerState.ObjectPullStats = &objectPullStats{}
	}
	peerState.ObjectPullStats.Attempts++
	peerState.ObjectPullStats.LastUnix = now.Unix()
	peerState.ObjectPullStats.LastObject = object
	peerState.ObjectPullStats.LastZone = string(zoneName)
	peerState.ObjectPullStats.LastKey = key
	peerState.ObjectPullStats.LastSourcePeer = peerID
	peerState.ObjectPullStats.LastUnreachable = false
	state.SyncPeers[peerID] = peerState
}

func recordObjectPullResult(state *stateFile, peerID, object string, zoneName zone.ZonePath, key string, bytes int, err error, unreachable bool, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if peerState.ObjectPullStats == nil {
		peerState.ObjectPullStats = &objectPullStats{}
	}
	stats := peerState.ObjectPullStats
	stats.LastUnix = now.Unix()
	stats.LastObject = object
	stats.LastZone = string(zoneName)
	stats.LastKey = key
	stats.LastBytes = bytes
	stats.LastSourcePeer = peerID
	stats.LastUnreachable = unreachable
	if err != nil {
		stats.Failures++
		stats.LastError = err.Error()
		if unreachable {
			stats.LargeObjectUnreachable++
		}
	} else {
		stats.Successes++
		stats.LastError = ""
	}
	state.SyncPeers[peerID] = peerState
}

// resolvePeerTCPAddr returns the best-effort TCP object-pull address for a peer.
func resolvePeerTCPAddr(state *stateFile, config *syncConfigFile, targetPeerID string) string {
	if config == nil || targetPeerID == "" {
		return ""
	}
	// Prefer bootstrap address with the same numeric TCP port.
	for _, peer := range config.Bootstrap {
		if peer.ID == targetPeerID && peer.Addr != "" {
			if tcp := objectPullTCPAddr(peer.Addr); tcp != "" {
				return tcp
			}
		}
	}
	// Fall back to discovered endpoint with the same numeric TCP port.
	var privateTCP string
	if state != nil && state.Network != nil {
		for discoveredID, entries := range gossip.ExtractPeerEndpoints(state.Network) {
			if discoveredID != targetPeerID || len(entries) == 0 {
				continue
			}
			for _, entry := range sortedEndpointEntriesForDial(entries) {
				udp := net.JoinHostPort(entry.Address, fmt.Sprintf("%d", entry.Port))
				tcp := objectPullTCPAddr(udp)
				if tcp == "" {
					continue
				}
				if endpointEntryIsPrivate(entry) {
					if privateTCP == "" {
						privateTCP = tcp
					}
					continue
				}
				return tcp
			}
		}
	}
	// Last resort for first-contact bootstrap: a verified, short-lived observed
	// UDP path can reach the peer before its signed endpoint record is synced.
	if state != nil {
		peerState := state.SyncPeers[targetPeerID]
		now := time.Now()
		if observedPathActive(peerState, now) && peerChainVerified(state, targetPeerID, now) {
			if tcp := objectPullTCPAddr(peerState.ObservedAddr); tcp != "" {
				return tcp
			}
		}
	}
	if privateTCP != "" {
		return privateTCP
	}
	return ""
}

// objectPullListenAddr derives the TCP listen address from the UDP listen addr.
func objectPullListenAddr(listenAddr string) string {
	udp, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return ""
	}
	tcp := &net.TCPAddr{IP: udp.IP, Port: udp.Port}
	return tcp.String()
}

// startObjectPullServer starts the TCP object-pull server for a daemon.
func startObjectPullServer(d *DaemonService) (net.Listener, error) {
	addr := objectPullListenAddr(d.Sync.Config.ListenAddr)
	if addr == "" {
		return nil, nil
	}
	listener, err := objectPullTCPServe(addr, objectPullLookup(func() *stateFile { return d.Sync.State }))
	if err != nil {
		return nil, err
	}
	if listener != nil {
		d.logInfo("object_pull", "serve_started", map[string]any{"addr": listener.Addr()})
	}
	return listener, nil
}

// ObjectPullRequest is a work item submitted to the async object-pull pool.
type ObjectPullRequest struct {
	PeerID string
	Zone   zone.ZonePath
}

// ObjectPullResult is delivered back to the daemon event loop when an async
// object pull finishes. The event loop applies the snapshot; workers must not
// mutate NetworkState directly.
type ObjectPullResult struct {
	PeerID   string
	Zone     zone.ZonePath
	Snapshot *gossip.ZoneSnapshot
	Err      error
}

// objectPullPool runs a fixed number of workers that perform TCP object pulls
// asynchronously and return results on the event loop channel.
type objectPullPool struct {
	getState func() *stateFile
	config   *syncConfigFile
	requests chan ObjectPullRequest
	results  chan<- ObjectPullResult
	workers  int
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// newObjectPullPool creates a pool. Start must be called before submitting work.
func newObjectPullPool(getState func() *stateFile, config *syncConfigFile, results chan<- ObjectPullResult, workers int) *objectPullPool {
	if workers <= 0 {
		workers = maxObjectPullConcurrency
	}
	return &objectPullPool{
		getState: getState,
		config:   config,
		requests: make(chan ObjectPullRequest),
		results:  results,
		workers:  workers,
	}
}

// Start launches the worker goroutines.
func (p *objectPullPool) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(ctx)
	}
}

// Stop signals workers to exit and waits for them.
func (p *objectPullPool) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
}

// Submit enqueues a pull request. It returns false if the context is canceled
// or the request channel is full.
func (p *objectPullPool) Submit(ctx context.Context, req ObjectPullRequest) bool {
	select {
	case p.requests <- req:
		return true
	case <-ctx.Done():
		return false
	case <-time.After(5 * time.Second):
		return false
	}
}

func (p *objectPullPool) worker(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-p.requests:
			if !ok {
				return
			}
			result := p.doPull(ctx, req)
			select {
			case p.results <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (p *objectPullPool) doPull(ctx context.Context, req ObjectPullRequest) ObjectPullResult {
	state := p.getState()
	if state == nil {
		return ObjectPullResult{PeerID: req.PeerID, Zone: req.Zone, Err: errors.New("state not available")}
	}
	snapshot, err := tryObjectPullTCP(state, p.config, req.PeerID, req.Zone)
	return ObjectPullResult{PeerID: req.PeerID, Zone: req.Zone, Snapshot: snapshot, Err: err}
}

// objectPullResultToEvent converts a worker result to the SyncEvent consumed by
// the daemon event loop.
func objectPullResultToEvent(res ObjectPullResult) SyncEvent {
	return &ObjectPullResultEvent{
		PeerID:   res.PeerID,
		Zone:     res.Zone,
		Snapshot: res.Snapshot,
		Err:      res.Err,
	}
}

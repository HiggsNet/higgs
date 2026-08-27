package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	photonservice "github.com/HiggsNet/photon/pkg/service"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type recordMutationResult struct {
	Zone    zone.ZonePath
	Key     string
	Version uint64
	DryRun  bool
}

func cloneNetworkStateForCandidateValidation(ns *zone.NetworkState, path zone.ZonePath) *zone.NetworkState {
	if ns == nil {
		return zone.NewNetworkState()
	}
	return zone.CloneNetworkStateForZone(ns, path)
}

func validateGenericRecordPut(key, recordType string) error {
	reservedPrefixes := []string{
		routing.RecordKeyPrefixIPAMPools,
		routing.RecordKeyPrefixIPAMAssignments,
		routing.RecordKeyPrefixRoutes,
		photonservice.RecordKeyPrefix,
		"routing/",
		"ipsec/",
		gossip.EndpointRecordKeyPrefix,
	}
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(key, prefix) {
			return fmt.Errorf("record_put key %q is daemon-owned; use its typed control method", key)
		}
	}
	reservedTypes := []string{
		routing.RecordTypeIPAMPool,
		routing.RecordTypeIPAMAssignment,
		routing.RecordTypeRouteAnnouncement,
		routing.RecordTypeRoutingNetns,
		photonservice.RecordTypeSOCKS5,
		ipsec.RecordTypeProfile,
		ipsec.RecordTypeAddresses,
		ipsec.RecordTypePorts,
		ipsec.RecordTypeTransportKey,
		ipsec.RecordTypeOverlayIntent,
		"sync.endpoint",
	}
	if slices.Contains(reservedTypes, recordType) {
		return fmt.Errorf("record_put type %q is daemon-owned; use its typed control method", recordType)
	}
	return nil
}

func putRecord(path zone.ZonePath, key string, value []byte, recordType string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	if version, ok, err := putRecordViaControl(rt, path, key, value, recordType); ok {
		if err != nil {
			return err
		}
		fmt.Printf("put %s/%s version %d via daemon\n", path, key, version)
		return nil
	}
	if !direct {
		logControlFallback("record_put")
	}
	return putRecordDirect(rt, path, key, value, recordType)
}

func putRecordDirect(rt *Runtime, path zone.ZonePath, key string, value []byte, recordType string) error {
	if err := validateGenericRecordPut(key, recordType); err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	record, err := buildSignedRecordAt(state, path, key, value, recordType, rt.Now())
	if err != nil {
		return err
	}
	if err := state.Network.Put(record); err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	fmt.Printf("put %s/%s version %d\n", path, key, record.Version)
	return nil
}

func getRecord(path zone.ZonePath, key string, verbose bool) error {
	record, err := loadRecord(path, key, 0)
	if err != nil {
		return err
	}
	return inspecttext.WriteRecord(os.Stdout, *record, verbose)
}

func debugRecord(path zone.ZonePath, key string, history int) error {
	record, err := loadRecord(path, key, history)
	if err != nil {
		return err
	}
	return inspecttext.WriteJSON(os.Stdout, record)
}

func loadRecord(path zone.ZonePath, key string, history int) (*inspect.RecordDetailView, error) {
	rt, err := NewRuntime()
	if err != nil {
		return nil, err
	}
	if history < 0 {
		return nil, fmt.Errorf("history must be >= 0")
	}
	if record, ok, err := getRecordViaControl(rt, path, key, history); ok {
		if err != nil {
			return nil, err
		}
		return record, nil
	}
	logControlFallback("record_get")
	return getRecordDirect(rt, path, key, history)
}

func getRecordDirect(rt *Runtime, path zone.ZonePath, key string, history int) (*inspect.RecordDetailView, error) {
	state, err := rt.LoadState()
	if err != nil {
		return nil, err
	}
	return lookupRecordDetail(state, path, key, history)
}

func lookupRecordDetail(state *stateFile, path zone.ZonePath, key string, history int) (*inspect.RecordDetailView, error) {
	if state == nil {
		return nil, fmt.Errorf("state is nil")
	}
	return lookupRecordDetailFromNetwork(state.Network, path, key, history)
}

func lookupRecordDetailFromNetwork(network *zone.NetworkState, path zone.ZonePath, key string, history int) (*inspect.RecordDetailView, error) {
	if history < 0 {
		return nil, fmt.Errorf("history must be >= 0")
	}
	if network == nil {
		return nil, fmt.Errorf("state is nil")
	}
	zs := network.Zones[path]
	if zs == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	rec := zs.Records[key]
	if rec == nil {
		return nil, fmt.Errorf("record not found: %s/%s", path, key)
	}
	view := inspect.BuildRecordDetail(rec, zs.RecordHistory[key], history)
	return &view, nil
}

func buildSignedRecordAt(state *stateFile, path zone.ZonePath, key string, value []byte, recordType string, now time.Time) (*zone.Record, error) {
	configureValidation(state.Network)
	zs := state.Network.Zones[path]
	if zs == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	current := zs.Records[key]
	record := &zone.Record{
		Zone:      path,
		Key:       key,
		Type:      recordType,
		Value:     value,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if current != nil {
		record.Version = current.Version + 1
		record.PrevHash = photoncrypto.RecordHash(current)
	}
	signer, err := signingKeyForZone(state, path)
	if err != nil {
		return nil, err
	}
	if err := photoncrypto.SignRecord(record, signer); err != nil {
		return nil, err
	}
	return record, nil
}

func signingKeyForZone(state *stateFile, path zone.ZonePath) (ed25519.PrivateKey, error) {
	if state == nil || state.Network == nil {
		return nil, fmt.Errorf("state is nil")
	}
	zs := state.Network.Zones[path]
	if zs == nil || zs.Authority == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	if len(state.RootPrivateKey) == ed25519.PrivateKeySize && authorityHasPrivateKey(zs.Authority, state.RootPrivateKey) {
		return state.RootPrivateKey, nil
	}
	if len(state.ZonePrivateKey) == ed25519.PrivateKeySize && authorityHasPrivateKey(zs.Authority, state.ZonePrivateKey) {
		return state.ZonePrivateKey, nil
	}
	return nil, fmt.Errorf("no local signing key for zone %s", path)
}

func authorityHasPrivateKey(authority *zone.ZoneAuthority, priv ed25519.PrivateKey) bool {
	if authority == nil || len(priv) != ed25519.PrivateKeySize {
		return false
	}
	pub := priv.Public().(ed25519.PublicKey)
	return authorityHasKey(authority, pub)
}

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

const defaultStatePath = ".higgs.db"
const cliMetaKey = "cli_state"

type stateFile struct {
	ManagedZone    zone.ZonePath      `json:"managed_zone"`
	RootPrivateKey ed25519.PrivateKey `json:"root_private_key"`
	ZonePrivateKey ed25519.PrivateKey `json:"zone_private_key"`
	Network        *zone.NetworkState `json:"network"`
}

type stateMeta struct {
	ManagedZone    zone.ZonePath      `json:"managed_zone"`
	RootPrivateKey ed25519.PrivateKey `json:"root_private_key"`
	ZonePrivateKey ed25519.PrivateKey `json:"zone_private_key"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}

	switch args[0] {
	case "init":
		managedZone := zone.ZonePath("local.")
		if len(args) > 1 {
			managedZone = zone.ZonePath(args[1])
		}
		return initState(managedZone)
	case "zone":
		if len(args) != 3 || args[1] != "show" {
			return usage()
		}
		return showZone(zone.ZonePath(args[2]))
	case "record":
		if len(args) < 5 || args[1] != "put" {
			return usage()
		}
		recordType := "policy.string"
		if len(args) > 5 {
			recordType = args[5]
		}
		return putRecord(zone.ZonePath(args[2]), args[3], []byte(args[4]), recordType)
	case "verify":
		if len(args) == 2 {
			return verifyChain(zone.ZonePath(args[1]))
		}
		if len(args) == 3 && args[1] == "chain" {
			return verifyChain(zone.ZonePath(args[2]))
		}
		return usage()
	default:
		return usage()
	}
}

func usage() error {
	return errors.New("usage: higgs init [zone] | higgs zone show <zone> | higgs record put <zone> <key> <value> [type] | higgs verify [chain] <zone>")
}

func initState(managedZone zone.ZonePath) error {
	if !managedZone.Valid() || managedZone == zone.RootZone {
		return fmt.Errorf("invalid managed zone: %s", managedZone)
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	zonePub, zonePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: higgscrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	chain := zoneChain(managedZone)
	for i, path := range chain {
		authority := &zone.ZoneAuthority{
			Zone:      path,
			Epoch:     1,
			Threshold: higgscrypto.SupportedThreshold,
			Keys: []zone.AuthorizedKey{{
				Key: zonePub,
				Capabilities: []zone.Capability{{
					Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate},
				}},
			}},
		}
		ns.Zones[path] = zone.NewZoneState(path, authority)

		parent := zone.RootZone
		signer := rootPriv
		if i > 0 {
			parent = chain[i-1]
			signer = zonePriv
		}
		delegation := &zone.Delegation{
			ZoneName:  path,
			Scope:     zone.DelegationScopeDirectChild,
			Authority: *authority,
		}
		if err := higgscrypto.SignDelegation(delegation, parent, signer); err != nil {
			return err
		}
		ns.Zones[parent].Delegations[path] = delegation
	}

	state := &stateFile{
		ManagedZone:    managedZone,
		RootPrivateKey: rootPriv,
		ZonePrivateKey: zonePriv,
		Network:        ns,
	}
	if err := saveState(state); err != nil {
		return err
	}
	fmt.Printf("initialized %s in %s\n", managedZone, statePath())
	return nil
}

func showZone(path zone.ZonePath) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(zs)
}

func putRecord(path zone.ZonePath, key string, value []byte, recordType string) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	configureValidation(state.Network)

	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	current := zs.Records[key]
	record := &zone.Record{
		Zone:      path,
		Key:       key,
		Type:      recordType,
		Value:     value,
		Version:   1,
		Timestamp: time.Now().Unix(),
	}
	if current != nil {
		record.Version = current.Version + 1
		record.PrevHash = higgscrypto.RecordHash(current)
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		return err
	}
	if err := state.Network.Put(record); err != nil {
		return err
	}
	if err := saveState(state); err != nil {
		return err
	}
	fmt.Printf("put %s/%s version %d\n", path, key, record.Version)
	return nil
}

func verifyChain(path zone.ZonePath) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	configureValidation(state.Network)
	if err := higgscrypto.VerifyChain(state.Network, path, time.Now()); err != nil {
		return err
	}
	fmt.Printf("verified chain for %s\n", path)
	return nil
}

func loadState() (*stateFile, error) {
	store, err := zone.OpenBoltStore(statePath(), 0o600)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	ns, err := store.LoadNetwork()
	if err != nil {
		return nil, err
	}
	var meta stateMeta
	if err := store.LoadMetaJSON(cliMetaKey, &meta); err != nil {
		return nil, err
	}
	state := stateFile{
		ManagedZone:    meta.ManagedZone,
		RootPrivateKey: meta.RootPrivateKey,
		ZonePrivateKey: meta.ZonePrivateKey,
		Network:        ns,
	}
	if state.Network == nil || len(state.Network.Zones) == 0 {
		return nil, errors.New("state file has no network")
	}
	normalizeState(state.Network)
	return &state, nil
}

func saveState(state *stateFile) error {
	store, err := zone.OpenBoltStore(statePath(), 0o600)
	if err != nil {
		return err
	}
	defer store.Close()

	meta := stateMeta{
		ManagedZone:    state.ManagedZone,
		RootPrivateKey: state.RootPrivateKey,
		ZonePrivateKey: state.ZonePrivateKey,
	}
	if err := store.SaveMetaJSON(cliMetaKey, &meta); err != nil {
		return err
	}
	return store.SaveNetwork(state.Network)
}

func statePath() string {
	if path := os.Getenv("HIGGS_STATE"); path != "" {
		return path
	}
	return defaultStatePath
}

func zoneChain(path zone.ZonePath) []zone.ZonePath {
	ancestors := path.Ancestors()
	out := make([]zone.ZonePath, 0, len(ancestors)-1)
	for i := len(ancestors) - 2; i >= 0; i-- {
		out = append(out, ancestors[i])
	}
	return out
}

func configureValidation(ns *zone.NetworkState) {
	ns.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
}

func normalizeState(ns *zone.NetworkState) {
	if ns.Zones == nil {
		ns.Zones = make(map[zone.ZonePath]*zone.ZoneState)
	}
	for path, zs := range ns.Zones {
		if zs.Path == "" {
			zs.Path = path
		}
		if zs.Delegations == nil {
			zs.Delegations = make(map[zone.ZonePath]*zone.Delegation)
		}
		if zs.Records == nil {
			zs.Records = make(map[string]*zone.Record)
		}
		if zs.RecordHistory == nil {
			zs.RecordHistory = make(map[string][]*zone.Record)
		}
		if zs.PendingRecords == nil {
			zs.PendingRecords = make(map[string][]*zone.Record)
		}
	}
}

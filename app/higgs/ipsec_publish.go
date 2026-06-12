package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func (sr *SyncRuntime) publishIPsecRecords() error {
	if sr == nil || sr.State == nil || sr.State.Network == nil || sr.App == nil || sr.App.Config == nil {
		return nil
	}
	state := sr.State
	config := sr.App.Config
	if state.ManagedZone == zone.RootZone || !state.ManagedZone.Valid() || len(state.ZonePrivateKey) == 0 || autoJoinPending(state) {
		return nil
	}
	if len(config.IPsec.LinkGroups) == 0 {
		return nil
	}
	now := sr.now()
	key, keyRecord, err := ensureIPsecTransportKey(state, now)
	if err != nil {
		return err
	}
	state.IPsecTransportKey = key
	records, err := localIPsecRecords(config, state, state.ManagedZone, keyRecord, now)
	if err != nil {
		return err
	}
	changed := false
	for _, item := range records {
		updated, err := putSignedIPsecRecordIfChanged(state, state.ManagedZone, item.key, item.recordType, item.value, now)
		if err != nil {
			return err
		}
		changed = changed || updated
	}
	for _, item := range records {
		if item.key != ipsec.RecordKeyPorts {
			continue
		}
		var portRecord *ipsec.PortRecord
		switch v := item.value.(type) {
		case ipsec.PortRecord:
			portRecord = &v
		case *ipsec.PortRecord:
			portRecord = v
		default:
			continue
		}
		var r *ipsec.PortRange
		if portRecord.Range != nil {
			r = portRecord.Range
		}
		state.IPsecPortRecord = &ipsecPortRecordState{
			Mode:       portRecord.Mode,
			Range:      r,
			Generation: portRecord.Current.Generation,
			UpdatedAt:  portRecord.UpdatedAt,
		}
		changed = true
	}
	if changed {
		return sr.saveState()
	}
	return nil
}

type localIPsecRecord struct {
	key        string
	recordType string
	value      any
}

func ensureIPsecTransportKey(state *stateFile, now time.Time) (*ipsecTransportKeyState, *ipsec.TransportKeyRecord, error) {
	if state == nil {
		return nil, nil, fmt.Errorf("state is nil")
	}
	if key := state.IPsecTransportKey; key != nil && len(key.PublicKey) > 0 && len(key.PrivateKey) > 0 {
		record := transportKeyRecordFromState(key)
		return key, record, nil
	}
	generated, record, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, 0, zonePublicKey(state)...)
	if err != nil {
		return nil, nil, err
	}
	return &ipsecTransportKeyState{
		Kind:        generated.Kind,
		Algorithm:   generated.Algorithm,
		PublicKey:   append([]byte(nil), generated.PublicKey...),
		PrivateKey:  append([]byte(nil), generated.PrivateKey...),
		Fingerprint: record.Fingerprint,
		NotBefore:   record.NotBefore,
		NotAfter:    record.NotAfter,
		UpdatedAt:   record.UpdatedAt,
	}, record, nil
}

func transportKeyRecordFromState(key *ipsecTransportKeyState) *ipsec.TransportKeyRecord {
	record := &ipsec.TransportKeyRecord{
		Version:     1,
		Kind:        key.Kind,
		Algorithm:   key.Algorithm,
		Fingerprint: key.Fingerprint,
		NotBefore:   key.NotBefore,
		NotAfter:    key.NotAfter,
		UpdatedAt:   key.UpdatedAt,
	}
	if record.Kind == "" {
		record.Kind = ipsec.TransportKeyRawPublicKey
	}
	if record.Algorithm == "" {
		record.Algorithm = ipsec.AlgorithmEd25519
	}
	if record.Fingerprint == "" {
		record.Fingerprint = ipsec.TransportKeyFingerprint(record.Algorithm, key.PublicKey)
	}
	if record.UpdatedAt == 0 {
		record.UpdatedAt = record.NotBefore
	}
	record.PublicKey = ipsecPublicKeyString(key.PublicKey)
	return record
}

func ipsecPublicKeyString(publicKey []byte) string {
	return base64.StdEncoding.EncodeToString(publicKey)
}

func zonePublicKey(state *stateFile) [][]byte {
	if state == nil || len(state.ZonePrivateKey) != ed25519.PrivateKeySize {
		return nil
	}
	pub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
	return [][]byte{append([]byte(nil), pub...)}
}

func localIPsecRecords(config *appConfig, state *stateFile, managed zone.ZonePath, key *ipsec.TransportKeyRecord, now time.Time) ([]localIPsecRecord, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("transport key record is required")
	}
	addresses := localIPsecAddressRecord(config)
	ports, err := localIPsecPortRecord(config, state, now)
	if err != nil {
		return nil, err
	}
	profile := ipsec.ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ipsec.ProviderStrongSwan,
		IKEIdentity:             string(managed),
		TransportKeyFingerprint: key.Fingerprint,
		Accept:                  ipsec.AcceptInbound,
		AddressFamilies:         localIPsecFamilies(addresses),
		PathModes:               localIPsecPathModes(config.IPsec.LinkGroups),
		NAT:                     localIPsecNATProfile(addresses),
	}
	return []localIPsecRecord{
		{key: ipsec.RecordKeyTransportKey, recordType: ipsec.RecordTypeTransportKey, value: *key},
		{key: ipsec.RecordKeyProfile, recordType: ipsec.RecordTypeProfile, value: profile},
		{key: ipsec.RecordKeyAddresses, recordType: ipsec.RecordTypeAddresses, value: addresses},
		{key: ipsec.RecordKeyPorts, recordType: ipsec.RecordTypePorts, value: ports},
	}, nil
}

func localIPsecAddressRecord(config *appConfig) ipsec.AddressRecord {
	record := ipsec.AddressRecord{Version: 1}
	seen := map[string]bool{}
	for i, candidate := range append([]string(nil), config.AdvertiseAddrs...) {
		addr, _ := splitAdvertiseAddress(candidate)
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		family := ipsecFamily(addr)
		if family == "" {
			continue
		}
		record.Addresses = append(record.Addresses, ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("advertise-%d", i+1),
			Source:       ipsec.SourceManualAddress,
			Address:      addr,
			Family:       family,
			Priority:     100 - i,
			Reachability: ipsecReachability(addr),
			TTLSeconds:   int64(config.EndpointTTL.Seconds()),
		})
	}
	if len(record.Addresses) == 0 {
		host, _ := splitAdvertiseAddress(config.ListenAddr)
		if host != "" && host != "0.0.0.0" && host != "::" {
			if family := ipsecFamily(host); family != "" {
				record.Addresses = append(record.Addresses, ipsec.AddressAdvertisement{
					ID:           "listen",
					Source:       ipsec.SourceLocal,
					Address:      host,
					Family:       family,
					Priority:     10,
					Reachability: ipsecReachability(host),
					TTLSeconds:   int64(config.EndpointTTL.Seconds()),
				})
			}
		}
	}
	return record
}

func localIPsecPortRecord(config *appConfig, state *stateFile, now time.Time) (*ipsec.PortRecord, error) {
	ike := uint16(ipsec.DefaultIKEPort)
	natt := uint16(ipsec.DefaultNATTPort)
	if port := listenPortFromAddr(config.ListenAddr); port != 0 && port != uint16(ipsec.DefaultIKEPort) {
		natt = port
	}
	previous := previousIPsecPortRecord(state)
	mode := config.IPsec.PortMode
	if mode == "" {
		mode = ipsec.PortModeFixed
	}
	generation := uint64(1)
	var portRange *ipsec.PortRange
	if mode == ipsec.PortModeRange {
		portRange = &config.IPsec.PortRange
		generation = nextPortGeneration(state, config, now)
	}
	return ipsec.PlanPortRecord(ipsec.PortPlanOptions{
		Mode:          mode,
		Range:         portRange,
		FixedIKE:      ike,
		FixedNATT:     natt,
		Generation:    generation,
		Previous:      previous,
		PreviousGrace: config.IPsec.PortPreviousGrace,
		Now:           now,
	})
}

func previousIPsecPortRecord(state *stateFile) *ipsec.PortRecord {
	if state == nil || state.IPsecPortRecord == nil {
		return nil
	}
	prev := state.IPsecPortRecord
	record := &ipsec.PortRecord{
		Version:   1,
		Mode:      prev.Mode,
		UpdatedAt: prev.UpdatedAt,
		Current: &ipsec.PortSelection{
			Generation: prev.Generation,
			IKE:        ipsec.PortBinding{Local: uint16(ipsec.DefaultIKEPort), Advertised: uint16(ipsec.DefaultIKEPort)},
			NATT:       ipsec.PortBinding{Local: uint16(ipsec.DefaultNATTPort), Advertised: uint16(ipsec.DefaultNATTPort)},
		},
	}
	if prev.Range != nil {
		r := *prev.Range
		record.Range = &r
		ike, natt, _ := ipsec.SelectPortsFromRange(r, prev.Generation)
		record.Current.IKE = ipsec.PortBinding{Local: ike, Advertised: ike}
		record.Current.NATT = ipsec.PortBinding{Local: natt, Advertised: natt}
	}
	return record
}

func nextPortGeneration(state *stateFile, config *appConfig, now time.Time) uint64 {
	if state == nil || state.IPsecPortRecord == nil {
		return 1
	}
	prev := state.IPsecPortRecord
	if config.IPsec.PortRotateInterval <= 0 {
		return prev.Generation
	}
	if prev.UpdatedAt == 0 {
		return prev.Generation + 1
	}
	last := time.Unix(prev.UpdatedAt, 0)
	if now.After(last.Add(config.IPsec.PortRotateInterval)) {
		return prev.Generation + 1
	}
	return prev.Generation
}

func putSignedIPsecRecordIfChanged(state *stateFile, path zone.ZonePath, key, recordType string, value any, now time.Time) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	zs := state.Network.Zones[path]
	if zs != nil {
		if existing := zs.Records[key]; existing != nil && bytes.Equal(existing.Value, data) {
			return false, nil
		}
	}
	record, err := buildSignedRecordAt(state, path, key, data, recordType, now)
	if err != nil {
		return false, err
	}
	if err := state.Network.Put(record); err != nil {
		return false, err
	}
	return true, nil
}

func localIPsecFamilies(record ipsec.AddressRecord) []string {
	seen := map[string]bool{}
	var out []string
	for _, address := range record.Addresses {
		family := address.Family
		if family == "" {
			family = ipsecFamily(address.Address)
		}
		if family != "" && !seen[family] {
			seen[family] = true
			out = append(out, family)
		}
	}
	if len(out) == 0 {
		return []string{ipsec.FamilyIPv4}
	}
	return out
}

func localIPsecPathModes(groups []ipsec.LinkGroupSpec) []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range groups {
		mode := group.Normalized().DefaultPathMode
		if mode != "" && !seen[mode] {
			seen[mode] = true
			out = append(out, mode)
		}
	}
	if len(out) == 0 {
		return []string{ipsec.PathModeFamilyRedundant}
	}
	return out
}

func localIPsecNATProfile(record ipsec.AddressRecord) ipsec.NATProfile {
	for _, address := range record.Addresses {
		if address.Reachability == ipsec.ReachabilityPublic {
			return ipsec.NATProfile{Hint: ipsec.NATHintPublic, InboundReachable: ipsec.NATReachableTrue}
		}
	}
	return ipsec.NATProfile{Hint: ipsec.NATHintUnknown, InboundReachable: ipsec.NATReachableUnknown}
}

func splitAdvertiseAddress(value string) (string, uint16) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0
	}
	host, portText, err := net.SplitHostPort(value)
	if err == nil {
		port, _ := strconv.ParseUint(portText, 10, 16)
		return strings.Trim(host, "[]"), uint16(port)
	}
	if strings.Count(value, ":") > 1 {
		if addr, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
			return addr.String(), 0
		}
	}
	if strings.Contains(value, ":") {
		host, portText, ok := strings.Cut(value, ":")
		if ok {
			port, _ := strconv.ParseUint(portText, 10, 16)
			return host, uint16(port)
		}
	}
	return strings.Trim(value, "[]"), 0
}

func ipsecFamily(addr string) string {
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	if parsed.Is4() {
		return ipsec.FamilyIPv4
	}
	if parsed.Is6() {
		return ipsec.FamilyIPv6
	}
	return ""
}

func ipsecReachability(addr string) string {
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return ipsec.ReachabilityUnknown
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return ipsec.ReachabilityPrivate
	}
	return ipsec.ReachabilityPublic
}

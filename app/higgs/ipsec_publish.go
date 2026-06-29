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

	"github.com/Catofes/higgs/pkg/core/gossip"
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
		previousState := state.IPsecPortRecord
		sr.logger().Debug("ipsec", "port_publish_decision", ipsecPortPublishLogFields(config, previousState, portRecord, now))
		state.IPsecPortRecord = &ipsecPortRecordState{
			Mode:       portRecord.Mode,
			Range:      r,
			Generation: portRecord.Current.Generation,
			UpdatedAt:  portRecord.UpdatedAt,
		}
		if previousState == nil || previousState.Mode != state.IPsecPortRecord.Mode || previousState.Generation != state.IPsecPortRecord.Generation || previousState.UpdatedAt != state.IPsecPortRecord.UpdatedAt || !ipsecPortRangesEqual(previousState.Range, state.IPsecPortRecord.Range) {
			changed = true
		}
	}
	if changed {
		return sr.saveState()
	}
	return nil
}

func ipsecPortPublishLogFields(config *appConfig, previous *ipsecPortRecordState, record *ipsec.PortRecord, now time.Time) map[string]any {
	fields := map[string]any{
		"now": now.Unix(),
	}
	if config != nil {
		fields["rotate_interval_seconds"] = int64(config.IPsec.PortRotateInterval.Seconds())
		fields["previous_grace_seconds"] = int64(config.IPsec.PortPreviousGrace.Seconds())
	}
	if previous != nil {
		fields["meta_mode"] = previous.Mode
		fields["meta_generation"] = previous.Generation
		fields["meta_updated_at"] = previous.UpdatedAt
		if previous.Range != nil {
			fields["meta_range"] = fmt.Sprintf("%d-%d", previous.Range.From, previous.Range.To)
		}
		if config != nil && config.IPsec.PortRotateInterval > 0 && previous.UpdatedAt > 0 {
			dueAt := time.Unix(previous.UpdatedAt, 0).Add(config.IPsec.PortRotateInterval)
			fields["rotate_due_at"] = dueAt.Unix()
			fields["rotate_due"] = !now.Before(dueAt)
		}
	} else {
		fields["meta_generation"] = 0
	}
	if record != nil {
		fields["record_mode"] = record.Mode
		fields["record_updated_at"] = record.UpdatedAt
		if record.Range != nil {
			fields["record_range"] = fmt.Sprintf("%d-%d", record.Range.From, record.Range.To)
		}
		if record.Current != nil {
			fields["record_generation"] = record.Current.Generation
			fields["record_ike_advertised"] = record.Current.IKE.Advertised
			fields["record_natt_advertised"] = record.Current.NATT.Advertised
		}
		if len(record.Previous) > 0 {
			fields["previous_count"] = len(record.Previous)
			fields["previous_generation"] = record.Previous[0].Generation
			fields["previous_valid_until"] = record.Previous[0].ValidUntil
		}
	}
	return fields
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
	addresses := localIPsecAddressRecord(config, state, now)
	ports, err := localIPsecPortRecord(config, state, now)
	if err != nil {
		return nil, err
	}
	accept := config.IPsec.Accept
	if accept == "" {
		accept = ipsec.AcceptBidirectional
	}
	families := localIPsecFamilies(addresses)
	profile := ipsec.ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ipsec.ProviderStrongSwan,
		IKEIdentity:             string(managed),
		TransportKeyFingerprint: key.Fingerprint,
		Accept:                  accept,
		AddressFamilies:         families,
		PathModes:               localIPsecPathModes(config.IPsec.LinkGroups),
		NAT:                     localIPsecNATProfile(addresses),
	}
	records := []localIPsecRecord{
		{key: ipsec.RecordKeyTransportKey, recordType: ipsec.RecordTypeTransportKey, value: *key},
		{key: ipsec.RecordKeyProfile, recordType: ipsec.RecordTypeProfile, value: profile},
		{key: ipsec.RecordKeyAddresses, recordType: ipsec.RecordTypeAddresses, value: addresses},
		{key: ipsec.RecordKeyPorts, recordType: ipsec.RecordTypePorts, value: ports},
	}
	records = append(records, localIPsecOverlayIntentRecords(config, addresses, now)...)
	return records, nil
}

func localIPsecOverlayIntentRecords(config *appConfig, addresses ipsec.AddressRecord, now time.Time) []localIPsecRecord {
	if config == nil {
		return nil
	}
	families := localIPsecFamilies(addresses)
	var out []localIPsecRecord
	for _, group := range config.IPsec.LinkGroups {
		if err := group.Validate(); err != nil {
			continue
		}
		group = group.Normalized()
		pathKeys := localOverlayIntentPathKeys(group, families)
		if len(pathKeys) == 0 {
			continue
		}
		intent := ipsec.OverlayIntentRecord{
			Version:       1,
			OverlayID:     group.ID,
			Provider:      group.Provider,
			PathKeys:      pathKeys,
			TunnelAddress: group.TunnelAddressSpec,
			UpdatedAt:     now.Unix(),
		}
		out = append(out, localIPsecRecord{
			key:        ipsec.OverlayIntentRecordKey(group.ID),
			recordType: ipsec.RecordTypeOverlayIntent,
			value:      intent,
		})
	}
	return out
}

func localOverlayIntentPathKeys(group ipsec.LinkGroupSpec, families []string) []string {
	switch group.DefaultPathMode {
	case ipsec.PathModeExhaustive:
		return []string{ipsec.DefaultPathKey}
	case ipsec.PathModeFamilyRedundant:
		var out []string
		for _, family := range families {
			if family == ipsec.FamilyIPv4 || family == ipsec.FamilyIPv6 {
				out = append(out, "family:"+family)
			}
		}
		return out
	default:
		return nil
	}
}

func localIPsecAddressRecord(config *appConfig, state *stateFile, now time.Time) ipsec.AddressRecord {
	record := ipsec.AddressRecord{Version: 1}
	seen := map[string]bool{}
	priority := 100
	nextID := 1

	addAddress := func(ad ipsec.AddressAdvertisement) {
		if ad.ID == "" {
			ad.ID = fmt.Sprintf("addr-%d", nextID)
			nextID++
		}
		if ad.TTLSeconds == 0 {
			ad.TTLSeconds = int64(config.EndpointTTL.Seconds())
		}
		record.Addresses = append(record.Addresses, ad)
		priority--
	}

	// 1. IPsec-specific manual addresses (highest priority).
	for _, candidate := range config.IPsec.AnnounceAddrs {
		addr, _ := splitAdvertiseAddress(candidate)
		if addr == "" || seen[addr] {
			continue
		}
		family := ipsecFamily(addr)
		if family == "" {
			continue
		}
		seen[addr] = true
		addAddress(ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("announce-%d", nextID),
			Source:       ipsec.SourceManualAddress,
			Address:      addr,
			Family:       family,
			Priority:     priority,
			Reachability: ipsecReachability(addr),
		})
	}

	// 2. Top-level advertise addresses (backward compatibility).
	for _, candidate := range config.AdvertiseAddrs {
		addr, _ := splitAdvertiseAddress(candidate)
		if addr == "" || seen[addr] {
			continue
		}
		family := ipsecFamily(addr)
		if family == "" {
			continue
		}
		seen[addr] = true
		addAddress(ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("advertise-%d", nextID),
			Source:       ipsec.SourceManualAddress,
			Address:      addr,
			Family:       family,
			Priority:     priority,
			Reachability: ipsecReachability(addr),
		})
	}

	// 3. Manual DNS names.
	for _, host := range config.IPsec.AnnounceDNS {
		host = strings.TrimSpace(host)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		addAddress(ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("dns-%d", nextID),
			Source:       ipsec.SourceManualDNS,
			Host:         host,
			Families:     []string{ipsec.FamilyIPv4, ipsec.FamilyIPv6},
			Priority:     priority,
			Reachability: ipsec.ReachabilityPublic,
		})
	}

	// 4. Follow gossip endpoints (reflector / interface discovery).
	if config.IPsec.AnnounceGossipEndpoints {
		for _, ad := range ipsecAddressesFromGossipEndpoints(state, seen, int64(config.EndpointTTL.Seconds()), now) {
			addAddress(ad)
		}
	}

	// 5. Fallback to listen_addr host.
	if len(record.Addresses) == 0 {
		host, _ := splitAdvertiseAddress(config.ListenAddr)
		if host != "" && host != "0.0.0.0" && host != "::" {
			if family := ipsecFamily(host); family != "" {
				addAddress(ipsec.AddressAdvertisement{
					ID:           "listen",
					Source:       ipsec.SourceLocal,
					Address:      host,
					Family:       family,
					Priority:     priority,
					Reachability: ipsecReachability(host),
				})
			}
		}
	}
	return record
}

// ipsecAddressesFromGossipEndpoints reads the local sync/endpoint/udp record
// and converts its entries into IPsec AddressAdvertisement values.
// The seen set is updated for each converted address.
func ipsecAddressesFromGossipEndpoints(state *stateFile, seen map[string]bool, ttlSeconds int64, now time.Time) []ipsec.AddressAdvertisement {
	if state == nil || state.ManagedZone == "" || seen == nil {
		return nil
	}
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil {
		return nil
	}
	record := zs.Records[gossip.EndpointRecordKeyUDP]
	if record == nil {
		return nil
	}
	var er gossip.EndpointRecord
	if err := json.Unmarshal(record.Value, &er); err != nil {
		return nil
	}
	var out []ipsec.AddressAdvertisement
	nextID := 1
	for _, ep := range er.Endpoints {
		addr := ep.Address
		if addr == "" || seen[addr] {
			continue
		}
		family := ipsecFamily(addr)
		if family == "" {
			continue
		}
		// Skip expired grace entries; the endpoint record itself already
		// applies TTL/grace, but re-check here to avoid publishing stale
		// addresses if the record was read before LocalEndpointsToRecord
		// filtered it.
		if ep.LastObserved != 0 {
			ttl := time.Duration(er.TTL) * time.Second
			if ttl <= 0 {
				ttl = gossip.DefaultEndpointTTL
			}
			grace := time.Duration(er.GraceSeconds) * time.Second
			expiresAt := time.Unix(ep.LastObserved, 0).Add(ttl + grace)
			if now.After(expiresAt) {
				continue
			}
		}
		seen[addr] = true
		source, reachability := mapGossipEndpointSourceToIPsec(ep)
		out = append(out, ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("endpoint-%d", nextID),
			Source:       source,
			Address:      addr,
			Family:       family,
			Priority:     ep.Priority,
			Reachability: reachability,
			TTLSeconds:   ttlSeconds,
			// Do not copy LastObserved from gossip endpoints. The IPsec record
			// has its own UpdatedAt/TTL; copying endpoint timestamps would make
			// the record change every gossip publish cycle even when the set of
			// addresses is unchanged.
		})
		nextID++
	}
	return out
}

// mapGossipEndpointSourceToIPsec maps a gossip EndpointEntry to an IPsec
// address source and reachability classification.
func mapGossipEndpointSourceToIPsec(ep gossip.EndpointEntry) (source, reachability string) {
	switch strings.Split(ep.Source, "+")[0] {
	case "advertise":
		source = ipsec.SourceManualAddress
	case "reflector":
		source = ipsec.SourceReflector
	case "interface":
		if ep.Scope == "global" {
			source = ipsec.SourceDiscovery
		} else {
			source = ipsec.SourceLocal
		}
	default:
		source = ipsec.SourceDiscovery
	}
	ip := net.ParseIP(ep.Address)
	if ip == nil {
		reachability = ipsec.ReachabilityUnknown
		return
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		reachability = ipsec.ReachabilityPrivate
	} else {
		reachability = ipsec.ReachabilityPublic
	}
	return
}

func localIPsecPortRecord(config *appConfig, state *stateFile, now time.Time) (*ipsec.PortRecord, error) {
	// IPsec ports are independent of the gossip listen address. Use the IKEv2
	// defaults unless the configuration explicitly requests a different mode.
	ike := uint16(ipsec.DefaultIKEPort)
	natt := uint16(ipsec.DefaultNATTPort)
	existing := existingIPsecPortRecord(state)
	previous := existing
	if previous == nil {
		previous = previousIPsecPortRecord(state)
	}
	mode := config.IPsec.PortMode
	if mode == "" {
		mode = ipsec.PortModeFixed
	}
	generation := uint64(1)
	var portRange *ipsec.PortRange
	if mode == ipsec.PortModeRange {
		portRange = &config.IPsec.PortRange
		generation = nextPortGeneration(state, existing, config, now)
	}
	if existing != nil && existing.Current != nil && existing.Current.Generation == generation && portRecordMatchesConfig(existing, mode, portRange) {
		return existing, nil
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

func existingIPsecPortRecord(state *stateFile) *ipsec.PortRecord {
	if state == nil || state.Network == nil || !state.ManagedZone.Valid() {
		return nil
	}
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil || zs.Records == nil || zs.Records[ipsec.RecordKeyPorts] == nil {
		return nil
	}
	record, err := ipsec.ParsePortRecord(zs.Records[ipsec.RecordKeyPorts])
	if err != nil {
		return nil
	}
	return record
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

func nextPortGeneration(state *stateFile, existing *ipsec.PortRecord, config *appConfig, now time.Time) uint64 {
	prev := ipsecPortRecordStateFromMeta(state)
	if prev == nil {
		prev = ipsecPortRecordStateFromRecord(existing)
	}
	if prev == nil {
		return 1
	}
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

func ipsecPortRecordStateFromMeta(state *stateFile) *ipsecPortRecordState {
	if state == nil || state.IPsecPortRecord == nil {
		return nil
	}
	return state.IPsecPortRecord
}

func ipsecPortRecordStateFromRecord(record *ipsec.PortRecord) *ipsecPortRecordState {
	if record == nil || record.Current == nil {
		return nil
	}
	state := &ipsecPortRecordState{
		Mode:       record.Mode,
		Generation: record.Current.Generation,
		UpdatedAt:  record.UpdatedAt,
	}
	if record.Range != nil {
		r := *record.Range
		state.Range = &r
	}
	return state
}

func portRecordMatchesConfig(record *ipsec.PortRecord, mode string, r *ipsec.PortRange) bool {
	if record == nil {
		return false
	}
	recordMode := record.Mode
	if recordMode == "" {
		recordMode = ipsec.PortModeFixed
	}
	if recordMode != mode {
		return false
	}
	if mode != ipsec.PortModeRange {
		return true
	}
	return ipsecPortRangesEqual(record.Range, r)
}

func ipsecPortRangesEqual(a, b *ipsec.PortRange) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.From == b.From && a.To == b.To
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
	add := func(family string) {
		if (family == ipsec.FamilyIPv4 || family == ipsec.FamilyIPv6) && !seen[family] {
			seen[family] = true
			out = append(out, family)
		}
	}
	for _, address := range record.Addresses {
		family := address.Family
		if family == "" {
			family = ipsecFamily(address.Address)
		}
		add(family)
		for _, family := range address.Families {
			add(family)
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
	// Avoid claiming inbound reachability based solely on having a public
	// address. Reflector-observed public addresses or static public IPs do not
	// prove that IKE/NAT-T can be delivered to this host (firewall, DNAT,
	// provider NAT). Keep the hint conservative and default to unknown.
	hint := ipsec.NATHintUnknown
	for _, address := range record.Addresses {
		if address.Reachability == ipsec.ReachabilityPublic {
			hint = ipsec.NATHintPublic
			break
		}
	}
	return ipsec.NATProfile{Hint: hint, InboundReachable: ipsec.NATReachableUnknown}
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

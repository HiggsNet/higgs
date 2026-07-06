package inspect

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

type ZoneDetailInput struct {
	Path           zone.ZonePath
	State          *zone.ZoneState
	Network        *zone.NetworkState
	Now            time.Time
	IncludeHistory bool
}

type ZoneDetail struct {
	Path            string           `json:"path"`
	Parent          string           `json:"parent"`
	Authority       *AuthorityView   `json:"authority"`
	AuthorityHash   string           `json:"authority_hash"`
	ParentProof     []DelegationView `json:"parent_proof"`
	Records         []RecordView     `json:"records"`
	RecordHistory   []RecordView     `json:"record_history"`
	Delegations     []DelegationView `json:"delegations"`
	Revocations     []RevocationView `json:"revocations"`
	Revoked         bool             `json:"revoked"`
	RecordCount     int              `json:"record_count"`
	HistoryCount    int              `json:"history_count"`
	DelegationCount int              `json:"delegation_count"`
	RevocationCount int              `json:"revocation_count"`
	MerkleRoot      string           `json:"merkle_root"`
}

type ZoneDebugView struct {
	Detail           ZoneDetail
	RootHash         string
	VerifyResult     string
	ActiveRevocation *RevocationView
}

type RecordView struct {
	Zone         string `json:"zone"`
	Key          string `json:"key"`
	Version      uint64 `json:"version"`
	Type         string `json:"type"`
	Value        string `json:"value"`
	ValueB64     string `json:"value_b64"`
	ValueHash    string `json:"value_hash"`
	RecordHash   string `json:"record_hash"`
	PrevHash     string `json:"prev_hash"`
	Timestamp    int64  `json:"timestamp"`
	SignedBy     string `json:"signed_by"`
	Signature    string `json:"signature"`
	HistoryCount int    `json:"history_count"`
	ValueJSON    any    `json:"value_json,omitempty"`
}

type RecordDetailView struct {
	RecordView
	RecordHistory []RecordView `json:"record_history,omitempty"`
}

type RecordsDebugInput struct {
	Network *zone.NetworkState
	Path    zone.ZonePath
	Prefix  string
}

type RecordsDebugView struct {
	Zones       []RecordsDebugZoneView
	ZoneCount   int
	RecordCount int
	Prefix      string
}

type RecordsDebugZoneView struct {
	Path    string
	Records []RecordView
}

type AuthorityView struct {
	Zone      string              `json:"zone"`
	Epoch     uint64              `json:"epoch"`
	Threshold uint8               `json:"threshold"`
	Keys      []AuthorizedKeyView `json:"keys"`
}

type AuthorizedKeyView struct {
	Key          string           `json:"key"`
	KeyID        string           `json:"key_id"`
	NotBefore    int64            `json:"not_before"`
	NotAfter     int64            `json:"not_after"`
	Capabilities []CapabilityView `json:"capabilities"`
}

type CapabilityView struct {
	Permissions []string `json:"permissions"`
	KeyPrefix   string   `json:"key_prefix"`
}

type DelegationView struct {
	Child          string         `json:"child"`
	Scope          string         `json:"scope"`
	AuthorityEpoch uint64         `json:"authority_epoch"`
	AuthorityHash  string         `json:"authority_hash"`
	Authority      *AuthorityView `json:"authority"`
	ExpiresAt      string         `json:"expires_at"`
	SignedBy       string         `json:"signed_by"`
	Signature      string         `json:"signature"`
}

type RevocationView struct {
	Child                 string `json:"child"`
	Parent                string `json:"parent"`
	RevokedAuthorityEpoch uint64 `json:"revoked_authority_epoch"`
	RevokedAuthorityHash  string `json:"revoked_authority_hash"`
	Reason                string `json:"reason"`
	RevokedAt             int64  `json:"revoked_at"`
	TTLSeconds            int64  `json:"ttl_seconds"`
	GraceSeconds          int64  `json:"grace_seconds"`
	SignedBy              string `json:"signed_by"`
	Signature             string `json:"signature"`
}

func BuildZoneDetail(input ZoneDetailInput) ZoneDetail {
	zs := input.State
	path := input.Path
	if path == "" && zs != nil {
		path = zs.Path
	}
	view := ZoneDetail{
		Path:   string(path),
		Parent: string(path.Parent()),
	}
	if zs == nil {
		return view
	}
	if input.Network != nil {
		view.Revoked = input.Network.IsZoneRevoked(path, input.Now)
	}
	view.Authority = BuildAuthority(zs.Authority)
	view.AuthorityHash = AuthorityHashHex(zs.Authority)
	view.ParentProof = BuildDelegations(zs.ParentProof)
	view.Records = buildRecords(zs.Records, zs.RecordHistory)
	if input.IncludeHistory {
		view.RecordHistory = buildRecordHistory(zs.RecordHistory)
	}
	view.Delegations = buildDelegationMap(zs.Delegations)
	view.Revocations = buildRevocationMap(zs.Revocations)
	view.RecordCount = len(zs.Records)
	view.HistoryCount = countRecordHistory(zs.RecordHistory)
	view.DelegationCount = len(zs.Delegations)
	view.RevocationCount = len(zs.Revocations)
	view.MerkleRoot = hexOrEmpty(zs.MerkleRoot)
	return view
}

func BuildRecord(rec *zone.Record, historyCount int) RecordView {
	if rec == nil {
		return RecordView{}
	}
	out := RecordView{
		Zone:         string(rec.Zone),
		Key:          rec.Key,
		Version:      rec.Version,
		Type:         rec.Type,
		Value:        string(rec.Value),
		ValueB64:     base64.StdEncoding.EncodeToString(rec.Value),
		ValueHash:    hexOrEmpty(rec.ValueHash),
		RecordHash:   hexOrEmpty(higgscrypto.RecordHash(rec)),
		PrevHash:     hexOrEmpty(rec.PrevHash),
		Timestamp:    rec.Timestamp,
		SignedBy:     hexOrEmpty(rec.SignedBy),
		Signature:    hexOrEmpty(rec.Signature),
		HistoryCount: historyCount,
	}
	var parsed any
	if len(rec.Value) > 0 && json.Unmarshal(rec.Value, &parsed) == nil {
		out.ValueJSON = parsed
	}
	return out
}

func BuildRecordDetail(rec *zone.Record, history []*zone.Record, historyLimit int) RecordDetailView {
	view := RecordDetailView{RecordView: BuildRecord(rec, len(history))}
	if historyLimit <= 0 || len(history) == 0 {
		return view
	}
	if historyLimit > len(history) {
		historyLimit = len(history)
	}
	view.RecordHistory = make([]RecordView, 0, historyLimit)
	for i := len(history) - 1; i >= 0 && len(view.RecordHistory) < historyLimit; i-- {
		view.RecordHistory = append(view.RecordHistory, BuildRecord(history[i], 0))
	}
	return view
}

func BuildRecordsDebug(input RecordsDebugInput) RecordsDebugView {
	view := RecordsDebugView{Prefix: input.Prefix}
	if input.Network == nil {
		return view
	}
	paths := make([]zone.ZonePath, 0, len(input.Network.Zones))
	if input.Path.Valid() {
		paths = append(paths, input.Path)
	} else {
		for p := range input.Network.Zones {
			paths = append(paths, p)
		}
		sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	}
	view.ZoneCount = len(paths)
	for _, p := range paths {
		zs := input.Network.Zones[p]
		if zs == nil {
			continue
		}
		keys := make([]string, 0, len(zs.Records))
		for key, record := range zs.Records {
			if record == nil {
				continue
			}
			if input.Prefix == "" || strings.HasPrefix(key, input.Prefix) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		zoneView := RecordsDebugZoneView{
			Path:    string(p),
			Records: make([]RecordView, 0, len(keys)),
		}
		for _, key := range keys {
			zoneView.Records = append(zoneView.Records, BuildRecord(zs.Records[key], len(zs.RecordHistory[key])))
		}
		view.RecordCount += len(zoneView.Records)
		view.Zones = append(view.Zones, zoneView)
	}
	return view
}

func BuildAuthority(authority *zone.ZoneAuthority) *AuthorityView {
	if authority == nil {
		return nil
	}
	keys := make([]AuthorizedKeyView, 0, len(authority.Keys))
	for _, key := range authority.Keys {
		caps := make([]CapabilityView, 0, len(key.Capabilities))
		for _, cap := range key.Capabilities {
			perms := make([]string, 0, len(cap.Permissions))
			for _, perm := range cap.Permissions {
				perms = append(perms, string(perm))
			}
			caps = append(caps, CapabilityView{
				Permissions: perms,
				KeyPrefix:   cap.KeyPrefix,
			})
		}
		keys = append(keys, AuthorizedKeyView{
			Key:          hexOrEmpty(key.Key),
			KeyID:        hexOrEmpty(higgscrypto.KeyID(key.Key)),
			NotBefore:    key.NotBefore,
			NotAfter:     key.NotAfter,
			Capabilities: caps,
		})
	}
	return &AuthorityView{
		Zone:      string(authority.Zone),
		Epoch:     authority.Epoch,
		Threshold: authority.Threshold,
		Keys:      keys,
	}
}

func BuildDelegation(del *zone.Delegation) DelegationView {
	if del == nil {
		return DelegationView{}
	}
	expiresAt := ""
	if del.ExpiresAt != nil {
		expiresAt = del.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return DelegationView{
		Child:          string(del.ZoneName),
		Scope:          string(del.Scope),
		AuthorityEpoch: del.AuthorityEpoch,
		AuthorityHash:  hexOrEmpty(del.AuthorityHash),
		Authority:      BuildAuthority(&del.Authority),
		ExpiresAt:      expiresAt,
		SignedBy:       hexOrEmpty(del.SignedBy),
		Signature:      hexOrEmpty(del.Signature),
	}
}

func BuildDelegations(delegations []*zone.Delegation) []DelegationView {
	out := make([]DelegationView, 0, len(delegations))
	for _, del := range delegations {
		out = append(out, BuildDelegation(del))
	}
	return out
}

func BuildRevocation(rev *zone.DelegationRevocation) RevocationView {
	if rev == nil {
		return RevocationView{}
	}
	return RevocationView{
		Child:                 string(rev.ChildZone),
		Parent:                string(rev.ParentZone),
		RevokedAuthorityEpoch: rev.RevokedAuthorityEpoch,
		RevokedAuthorityHash:  hexOrEmpty(rev.RevokedAuthorityHash),
		Reason:                rev.Reason,
		RevokedAt:             rev.RevokedAt,
		TTLSeconds:            rev.TTLSeconds,
		GraceSeconds:          rev.GraceSeconds,
		SignedBy:              hexOrEmpty(rev.SignedBy),
		Signature:             hexOrEmpty(rev.Signature),
	}
}

func AuthorityHashHex(authority *zone.ZoneAuthority) string {
	if authority == nil {
		return ""
	}
	return hexOrEmpty(higgscrypto.AuthorityHash(authority))
}

func buildRecords(records map[string]*zone.Record, history map[string][]*zone.Record) []RecordView {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]RecordView, 0, len(keys))
	for _, key := range keys {
		out = append(out, BuildRecord(records[key], len(history[key])))
	}
	return out
}

func buildRecordHistory(history map[string][]*zone.Record) []RecordView {
	keys := make([]string, 0, len(history))
	for key := range history {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]RecordView, 0)
	for _, key := range keys {
		versions := history[key]
		for i := len(versions) - 1; i >= 0; i-- {
			out = append(out, BuildRecord(versions[i], 0))
		}
	}
	return out
}

func countRecordHistory(history map[string][]*zone.Record) int {
	total := 0
	for _, versions := range history {
		total += len(versions)
	}
	return total
}

func buildDelegationMap(delegations map[zone.ZonePath]*zone.Delegation) []DelegationView {
	paths := make([]zone.ZonePath, 0, len(delegations))
	for childPath := range delegations {
		paths = append(paths, childPath)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	out := make([]DelegationView, 0, len(paths))
	for _, childPath := range paths {
		out = append(out, BuildDelegation(delegations[childPath]))
	}
	return out
}

func buildRevocationMap(revocations map[zone.ZonePath]*zone.DelegationRevocation) []RevocationView {
	paths := make([]zone.ZonePath, 0, len(revocations))
	for childPath := range revocations {
		paths = append(paths, childPath)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	out := make([]RevocationView, 0, len(paths))
	for _, childPath := range paths {
		out = append(out, BuildRevocation(revocations[childPath]))
	}
	return out
}

func hexOrEmpty(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return hex.EncodeToString(data)
}

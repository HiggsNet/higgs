package routing

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
)

const (
	RecordTypeRouteAnnouncement = "route.announcement"
	RecordKeyPrefixRoutes       = "routes/announcements/"

	RecordTypeIPAMPool       = "ipam.pool"
	RecordKeyPrefixIPAMPools = "ipam/pools/"

	RecordTypeIPAMAssignment       = "ipam.assignment"
	RecordKeyPrefixIPAMAssignments = "ipam/assignments/"

	RecordTypeRoutingNetns = "routing.netns.v1"
	RecordKeyRoutingNetns  = "routing/netns"
)

// RoutingNetnsRecord announces the network namespaces a node uses for routing.
// Other nodes use this to reverse-derive Router-ID → (zone, netns) for
// control-plane cross-audit of learned Babel routes.
type RoutingNetnsRecord struct {
	Version int      `json:"version"` // schema version, 1
	Netns   []string `json:"netns"`   // stable netns names (e.g. ["h2", "host"])
}

// RouteAnnouncementRecord represents a route announcement or withdrawal
// under the routes/announcements/<prefix> key.
type RouteAnnouncementRecord struct {
	Version int    `json:"version"` // schema version, 1
	Prefix  string `json:"prefix"`  // canonical CIDR prefix
	Active  bool   `json:"active"`  // true=announced, false=withdrawn
}

// IPAMPoolRecord represents a pool delegation: a zone declares it has the
// authority to assign prefixes from this pool to sub-zones.
type IPAMPoolRecord struct {
	Version     int           `json:"version"`      // schema version, 1
	Prefix      string        `json:"prefix"`       // canonical CIDR prefix
	DelegatedTo zone.ZonePath `json:"delegated_to"` // zone that receives delegation
	Active      bool          `json:"active"`       // true=delegated, false=revoked
}

// IPAMAssignmentRecord represents an assignment of a prefix to a specific zone.
type IPAMAssignmentRecord struct {
	Version    int           `json:"version"`     // schema version, 1
	Prefix     string        `json:"prefix"`      // canonical CIDR prefix
	AssignedTo zone.ZonePath `json:"assigned_to"` // zone that may announce the prefix
	Active     bool          `json:"active"`      // true=assigned, false=revoked
}

// CanonicalizePrefix parses a CIDR and returns its canonical form (masked network address).
// This ensures 10.0.1.1/24 and 10.0.1.0/24 map to the same key and prefix field.
func CanonicalizePrefix(prefix string) (string, error) {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return "", err
	}
	return p.Masked().String(), nil
}

// NormalizeRouteAnnouncementKey returns the stable record key for a route
// announcement prefix. The prefix is first canonicalized; then '/' is replaced by '_'.
func NormalizeRouteAnnouncementKey(prefix string) (string, error) {
	canonical, err := CanonicalizePrefix(prefix)
	if err != nil {
		return "", err
	}
	return RecordKeyPrefixRoutes + strings.ReplaceAll(canonical, "/", "_"), nil
}

// NormalizeIPAMPoolKey returns the stable record key for an IPAM pool prefix.
func NormalizeIPAMPoolKey(prefix string) (string, error) {
	canonical, err := CanonicalizePrefix(prefix)
	if err != nil {
		return "", err
	}
	return RecordKeyPrefixIPAMPools + strings.ReplaceAll(canonical, "/", "_"), nil
}

// NormalizeIPAMAssignmentKey returns the stable record key for an IPAM assignment prefix.
func NormalizeIPAMAssignmentKey(prefix string) (string, error) {
	canonical, err := CanonicalizePrefix(prefix)
	if err != nil {
		return "", err
	}
	return RecordKeyPrefixIPAMAssignments + strings.ReplaceAll(canonical, "/", "_"), nil
}

// ParseRouteAnnouncementRecord parses a signed zone.Record into a RouteAnnouncementRecord.
// It enforces that record.Key, ann.Prefix and the canonical prefix all agree.
func ParseRouteAnnouncementRecord(record *zone.Record) (*RouteAnnouncementRecord, error) {
	if record == nil {
		return nil, errors.New("route announcement record is nil")
	}
	if record.Type != RecordTypeRouteAnnouncement {
		return nil, fmt.Errorf("expected record type %s, got %s", RecordTypeRouteAnnouncement, record.Type)
	}
	var ann RouteAnnouncementRecord
	if err := json.Unmarshal(record.Value, &ann); err != nil {
		return nil, fmt.Errorf("unmarshal route announcement: %w", err)
	}
	if ann.Prefix == "" {
		return nil, errors.New("route announcement prefix is empty")
	}
	canonical, err := CanonicalizePrefix(ann.Prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid route announcement prefix %q: %w", ann.Prefix, err)
	}
	expectedKey, err := NormalizeRouteAnnouncementKey(ann.Prefix)
	if err != nil {
		return nil, fmt.Errorf("normalize route announcement key: %w", err)
	}
	if record.Key != expectedKey {
		return nil, fmt.Errorf("route_announcement_key_mismatch: record key %q does not match prefix key %q", record.Key, expectedKey)
	}
	ann.Prefix = canonical
	if err := ann.Validate(record.Zone); err != nil {
		return nil, err
	}
	return &ann, nil
}

// ValidateRouteAnnouncementAgainstHistory rejects prefix changes on the same key.
// Callers should pass the current active record for the same zone+key, if any.
func ValidateRouteAnnouncementAgainstHistory(ann *RouteAnnouncementRecord, current *zone.Record) error {
	if current == nil {
		return nil
	}
	currentAnn, err := ParseRouteAnnouncementRecord(current)
	if err != nil {
		return fmt.Errorf("route_announcement_history_invalid: %w", err)
	}
	if currentAnn.Prefix != ann.Prefix {
		return fmt.Errorf("route_announcement_key_mismatch: key %q previously announced %s, cannot change to %s; withdraw and re-announce under new key", current.Key, currentAnn.Prefix, ann.Prefix)
	}
	return nil
}

// Validate checks the route announcement schema and prefix.
func (r RouteAnnouncementRecord) Validate(owner zone.ZonePath) error {
	if r.Version != 1 {
		return fmt.Errorf("unsupported route announcement schema version: %d", r.Version)
	}
	if r.Prefix == "" {
		return errors.New("route announcement prefix is empty")
	}
	if _, err := CanonicalizePrefix(r.Prefix); err != nil {
		return fmt.Errorf("invalid route announcement prefix %q: %w", r.Prefix, err)
	}
	_ = owner
	return nil
}

// ParseIPAMPoolRecord parses a signed zone.Record into an IPAMPoolRecord.
func ParseIPAMPoolRecord(record *zone.Record) (*IPAMPoolRecord, error) {
	if record == nil {
		return nil, errors.New("ipam pool record is nil")
	}
	if record.Type != RecordTypeIPAMPool {
		return nil, fmt.Errorf("expected record type %s, got %s", RecordTypeIPAMPool, record.Type)
	}
	var pool IPAMPoolRecord
	if err := json.Unmarshal(record.Value, &pool); err != nil {
		return nil, fmt.Errorf("unmarshal ipam pool: %w", err)
	}
	if pool.Prefix == "" {
		return nil, errors.New("ipam pool prefix is empty")
	}
	canonical, err := CanonicalizePrefix(pool.Prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid ipam pool prefix %q: %w", pool.Prefix, err)
	}
	expectedKey, err := NormalizeIPAMPoolKey(pool.Prefix)
	if err != nil {
		return nil, fmt.Errorf("normalize ipam pool key: %w", err)
	}
	if record.Key != expectedKey {
		return nil, fmt.Errorf("ipam_pool_key_mismatch: record key %q does not match prefix key %q", record.Key, expectedKey)
	}
	pool.Prefix = canonical
	if err := pool.Validate(record.Zone); err != nil {
		return nil, err
	}
	return &pool, nil
}

// Validate checks the IPAM pool schema and prefix.
func (r IPAMPoolRecord) Validate(owner zone.ZonePath) error {
	if r.Version != 1 {
		return fmt.Errorf("unsupported ipam pool schema version: %d", r.Version)
	}
	if r.Prefix == "" {
		return errors.New("ipam pool prefix is empty")
	}
	if _, err := CanonicalizePrefix(r.Prefix); err != nil {
		return fmt.Errorf("invalid ipam pool prefix %q: %w", r.Prefix, err)
	}
	if r.DelegatedTo == "" {
		return errors.New("ipam pool delegated_to is empty")
	}
	_ = owner
	return nil
}

// ParseIPAMAssignmentRecord parses a signed zone.Record into an IPAMAssignmentRecord.
func ParseIPAMAssignmentRecord(record *zone.Record) (*IPAMAssignmentRecord, error) {
	if record == nil {
		return nil, errors.New("ipam assignment record is nil")
	}
	if record.Type != RecordTypeIPAMAssignment {
		return nil, fmt.Errorf("expected record type %s, got %s", RecordTypeIPAMAssignment, record.Type)
	}
	var assignment IPAMAssignmentRecord
	if err := json.Unmarshal(record.Value, &assignment); err != nil {
		return nil, fmt.Errorf("unmarshal ipam assignment: %w", err)
	}
	if assignment.Prefix == "" {
		return nil, errors.New("ipam assignment prefix is empty")
	}
	canonical, err := CanonicalizePrefix(assignment.Prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid ipam assignment prefix %q: %w", assignment.Prefix, err)
	}
	expectedKey, err := NormalizeIPAMAssignmentKey(assignment.Prefix)
	if err != nil {
		return nil, fmt.Errorf("normalize ipam assignment key: %w", err)
	}
	if record.Key != expectedKey {
		return nil, fmt.Errorf("ipam_assignment_key_mismatch: record key %q does not match prefix key %q", record.Key, expectedKey)
	}
	assignment.Prefix = canonical
	if err := assignment.Validate(record.Zone); err != nil {
		return nil, err
	}
	return &assignment, nil
}

// Validate checks the IPAM assignment schema and prefix.
func (r IPAMAssignmentRecord) Validate(owner zone.ZonePath) error {
	if r.Version != 1 {
		return fmt.Errorf("unsupported ipam assignment schema version: %d", r.Version)
	}
	if r.Prefix == "" {
		return errors.New("ipam assignment prefix is empty")
	}
	if _, err := CanonicalizePrefix(r.Prefix); err != nil {
		return fmt.Errorf("invalid ipam assignment prefix %q: %w", r.Prefix, err)
	}
	if r.AssignedTo == "" {
		return errors.New("ipam assignment assigned_to is empty")
	}
	_ = owner
	return nil
}

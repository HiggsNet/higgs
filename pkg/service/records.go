package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
)

const (
	RecordTypeSOCKS5 = "service.socks5.v1"
	RecordKeyPrefix  = "services/"
	TypeSOCKS5       = "socks5"
)

var serviceIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62})$`)

// SOCKS5Record is the public, signed service description. Access policy and
// container rendering details intentionally remain local configuration.
type SOCKS5Record struct {
	Type    string `json:"type"`
	Region  string `json:"region"`
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	// Active is optional for compatibility: records created before explicit
	// withdrawal support omitted it and are therefore active by default.
	Active *bool `json:"active,omitempty"`
}

func (r SOCKS5Record) IsActive() bool { return r.Active == nil || *r.Active }

func NormalizeID(raw string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(raw))
	if !serviceIDPattern.MatchString(id) {
		return "", fmt.Errorf("invalid service id %q: use 1-63 lowercase letters, digits, '.', '_' or '-'", raw)
	}
	return id, nil
}

func RecordKey(id string) (string, error) {
	normalized, err := NormalizeID(id)
	if err != nil {
		return "", err
	}
	return RecordKeyPrefix + normalized, nil
}

// ParseSOCKS5Record validates the record type, key and strict JSON schema.
func ParseSOCKS5Record(record *zone.Record) (*SOCKS5Record, error) {
	if record == nil {
		return nil, errors.New("socks5 service record is nil")
	}
	if record.Type != RecordTypeSOCKS5 {
		return nil, fmt.Errorf("expected record type %s, got %s", RecordTypeSOCKS5, record.Type)
	}
	if !strings.HasPrefix(record.Key, RecordKeyPrefix) {
		return nil, fmt.Errorf("service_record_key_mismatch: record key %q is outside %q", record.Key, RecordKeyPrefix)
	}
	id := strings.TrimPrefix(record.Key, RecordKeyPrefix)
	expectedKey, err := RecordKey(id)
	if err != nil || record.Key != expectedKey {
		return nil, fmt.Errorf("service_record_key_mismatch: invalid service record key %q", record.Key)
	}

	var value SOCKS5Record
	decoder := json.NewDecoder(bytes.NewReader(record.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("unmarshal socks5 service: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("unmarshal socks5 service: %w", err)
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return &value, nil
}

func (r SOCKS5Record) Validate() error {
	if r.Type != TypeSOCKS5 {
		return fmt.Errorf("service type must be %q", TypeSOCKS5)
	}
	if strings.TrimSpace(r.Region) == "" {
		return errors.New("service region is required")
	}
	addr, err := netip.ParseAddr(r.Address)
	if err != nil {
		return fmt.Errorf("invalid service address %q: %w", r.Address, err)
	}
	if addr.IsUnspecified() || addr.IsMulticast() {
		return fmt.Errorf("service address %s is not a usable unicast address", addr)
	}
	if r.Address != addr.String() {
		return fmt.Errorf("service address %q is not canonical; use %q", r.Address, addr)
	}
	if r.Port == 0 {
		return errors.New("service port must be between 1 and 65535")
	}
	return nil
}

// AuthorizeSOCKS5Record checks that the service address belongs to an active,
// valid IPAM assignment for the record's zone. The route authorization model
// supplies the assignment set so invalid pools and overlapping assignments are
// rejected consistently with Babel route publication.
func AuthorizeSOCKS5Record(record *zone.Record, authorized *routing.AuthorizedRouteSet) (*routing.AssignmentEntry, error) {
	value, err := ParseSOCKS5Record(record)
	if err != nil {
		return nil, err
	}
	if authorized == nil {
		return nil, errors.New("service authorization set is nil")
	}
	if !value.IsActive() {
		return nil, errors.New("service record is withdrawn")
	}
	addr := netip.MustParseAddr(value.Address)
	var best *routing.AssignmentEntry
	for _, assignment := range authorized.AllAssignments {
		if assignment == nil || assignment.Shared || assignment.AssignedTo != record.Zone || !assignment.Prefix.Contains(addr) {
			continue
		}
		if best == nil || assignment.Prefix.Bits() > best.Prefix.Bits() {
			best = assignment
		}
	}
	if best == nil {
		return nil, fmt.Errorf("service_address_unauthorized: address %s is not covered by an active non-shared IPAM assignment to %s", addr, record.Zone)
	}
	return best, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

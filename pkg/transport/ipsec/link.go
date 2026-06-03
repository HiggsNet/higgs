package ipsec

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

const (
	DirectionInbound       = "inbound"
	DirectionOutbound      = "outbound"
	DirectionBidirectional = "bidirectional"

	NetNSHost = "host"
)

type MeshPolicy struct {
	OverlayID       string
	Provider        string
	Direction       string
	AddressFamilies []string
	Sources         []string
	PathMode        string
}

type NetNSSpec struct {
	Kind string
	Name string
	Path string
}

type BackoffPolicy struct {
	InitialSeconds int
	MaxSeconds     int
}

type ReconcilePolicy struct {
	IntervalSeconds int
	Backoff         BackoffPolicy
}

type LinkGroupSpec struct {
	ID                 string
	Name               string
	Provider           string
	NetNS              NetNSSpec
	DefaultPathMode    string
	Direction          string
	AddressSourceOrder []string
	MaxPeers           int
	MaxLinksPerPeer    int
	TunnelAddressPool  netip.Prefix
	Reconcile          ReconcilePolicy
}

type TransportLinkSpec struct {
	LocalZone       zone.ZonePath
	PeerZone        zone.ZonePath
	OverlayID       string
	Provider        string
	TransportID     string
	Direction       string
	PathMode        string
	IKEIdentity     string
	AuthRef         string
	ContactPoints   []ContactPoint
	XFRMIfID        uint32
	InterfaceName   string
	LocalTunnelAddr netip.Addr
	PeerTunnelAddr  netip.Addr
	NetNS           string
}

type TransportLinkOptions struct {
	TransportID     string
	Provider        string
	Direction       string
	PathMode        string
	NetNS           string
	LocalTunnelAddr netip.Addr
	PeerTunnelAddr  netip.Addr
}

func NewTransportLinkSpec(local, peer zone.ZonePath, overlayID, transportID string, records *NodeRecords, contacts []ContactPoint) (TransportLinkSpec, error) {
	return NewTransportLinkSpecWithOptions(local, peer, overlayID, records, contacts, TransportLinkOptions{
		TransportID: transportID,
	})
}

func NewTransportLinkSpecWithOptions(local, peer zone.ZonePath, overlayID string, records *NodeRecords, contacts []ContactPoint, opts TransportLinkOptions) (TransportLinkSpec, error) {
	if overlayID == "" {
		return TransportLinkSpec{}, fmt.Errorf("overlay id is required")
	}
	transportID := opts.TransportID
	if transportID == "" {
		transportID = StableTransportID(local, peer, overlayID)
	}
	if records == nil || records.Profile == nil {
		return TransportLinkSpec{}, fmt.Errorf("ipsec profile is required")
	}
	provider := records.Profile.Provider
	if provider == "" {
		provider = ProviderStrongSwan
	}
	if opts.Provider != "" {
		provider = opts.Provider
	}
	if provider != ProviderStrongSwan {
		return TransportLinkSpec{}, fmt.Errorf("unsupported provider %q", provider)
	}
	if records.TransportKey != nil && records.Profile.TransportKeyFingerprint != records.TransportKey.Fingerprint {
		return TransportLinkSpec{}, fmt.Errorf("transport key fingerprint mismatch")
	}
	ifID := StableXFRMIfID(local, peer, transportID)
	return TransportLinkSpec{
		LocalZone:       local,
		PeerZone:        peer,
		OverlayID:       overlayID,
		Provider:        provider,
		TransportID:     transportID,
		Direction:       opts.Direction,
		PathMode:        opts.PathMode,
		IKEIdentity:     records.Profile.IKEIdentity,
		AuthRef:         records.Profile.TransportKeyFingerprint,
		ContactPoints:   append([]ContactPoint(nil), contacts...),
		XFRMIfID:        ifID,
		InterfaceName:   StableInterfaceName(ifID),
		LocalTunnelAddr: opts.LocalTunnelAddr,
		PeerTunnelAddr:  opts.PeerTunnelAddr,
		NetNS:           opts.NetNS,
	}, nil
}

func NewTransportLinkSpecForGroup(local, peer zone.ZonePath, group LinkGroupSpec, records *NodeRecords, contacts []ContactPoint, linkIndex int) (TransportLinkSpec, error) {
	if err := group.Validate(); err != nil {
		return TransportLinkSpec{}, err
	}
	group = group.Normalized()
	localAddr, peerAddr, err := group.TunnelAddresses(linkIndex)
	if err != nil {
		return TransportLinkSpec{}, err
	}
	return NewTransportLinkSpecWithOptions(local, peer, group.ID, records, contacts, TransportLinkOptions{
		Provider:        group.Provider,
		Direction:       group.Direction,
		PathMode:        group.DefaultPathMode,
		NetNS:           group.NetNS.Target(),
		LocalTunnelAddr: localAddr,
		PeerTunnelAddr:  peerAddr,
	})
}

func (g LinkGroupSpec) Validate() error {
	if g.ID == "" {
		return fmt.Errorf("link group id is required")
	}
	provider := g.Provider
	if provider == "" {
		provider = ProviderStrongSwan
	}
	if provider != ProviderStrongSwan {
		return fmt.Errorf("unsupported link group provider %q", provider)
	}
	direction := g.Direction
	if direction == "" {
		direction = DirectionOutbound
	}
	if !oneOf(direction, DirectionInbound, DirectionOutbound, DirectionBidirectional) {
		return fmt.Errorf("unsupported link group direction %q", direction)
	}
	pathMode := g.DefaultPathMode
	if pathMode == "" {
		pathMode = PathModeFamilyRedundant
	}
	if !oneOf(pathMode, PathModeFamilyRedundant, PathModeExhaustive) {
		return fmt.Errorf("unsupported link group path mode %q", pathMode)
	}
	for _, source := range g.AddressSourceOrder {
		if !oneOf(source, SourceManualAddress, SourceManualDNS, SourceDiscovery, SourceReflector, SourceLocal) {
			return fmt.Errorf("unsupported link group address source %q", source)
		}
	}
	if g.MaxPeers < 0 {
		return fmt.Errorf("max peers must be non-negative")
	}
	if g.MaxLinksPerPeer < 0 {
		return fmt.Errorf("max links per peer must be non-negative")
	}
	if err := g.NetNS.Validate(); err != nil {
		return err
	}
	if g.Reconcile.Backoff.MaxSeconds != 0 && g.Reconcile.Backoff.InitialSeconds > g.Reconcile.Backoff.MaxSeconds {
		return fmt.Errorf("backoff initial must not exceed max")
	}
	return nil
}

func (g LinkGroupSpec) Normalized() LinkGroupSpec {
	out := g
	if out.Provider == "" {
		out.Provider = ProviderStrongSwan
	}
	if out.DefaultPathMode == "" {
		out.DefaultPathMode = PathModeFamilyRedundant
	}
	if out.Direction == "" {
		out.Direction = DirectionOutbound
	}
	if out.NetNS.Kind == "" {
		out.NetNS.Kind = NetNSHost
	}
	if len(out.AddressSourceOrder) == 0 {
		out.AddressSourceOrder = append([]string(nil), defaultAddressSourceOrder...)
	}
	return out
}

func (g LinkGroupSpec) TunnelAddresses(linkIndex int) (netip.Addr, netip.Addr, error) {
	if !g.TunnelAddressPool.IsValid() {
		return netip.Addr{}, netip.Addr{}, nil
	}
	if linkIndex < 0 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("link index must be non-negative")
	}
	local, ok := addrAt(g.TunnelAddressPool, uint64(linkIndex*2+1))
	if !ok {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("link index %d exceeds tunnel address pool", linkIndex)
	}
	peer, ok := addrAt(g.TunnelAddressPool, uint64(linkIndex*2+2))
	if !ok {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("link index %d exceeds tunnel address pool", linkIndex)
	}
	return local, peer, nil
}

func (n NetNSSpec) Validate() error {
	kind := n.Kind
	if kind == "" {
		kind = NetNSHost
	}
	switch kind {
	case NetNSHost:
		if n.Name != "" || n.Path != "" {
			return fmt.Errorf("host netns must not set name or path")
		}
	case "name":
		if n.Name == "" {
			return fmt.Errorf("netns name is required")
		}
		if n.Path != "" {
			return fmt.Errorf("netns name mode must not set path")
		}
	case "path":
		if n.Path == "" {
			return fmt.Errorf("netns path is required")
		}
		if n.Name != "" {
			return fmt.Errorf("netns path mode must not set name")
		}
	default:
		return fmt.Errorf("unsupported netns kind %q", kind)
	}
	return nil
}

func (n NetNSSpec) Target() string {
	switch n.Kind {
	case "", NetNSHost:
		return ""
	case "name":
		return n.Name
	case "path":
		return n.Path
	default:
		return ""
	}
}

func StableTransportID(local, peer zone.ZonePath, overlayID string) string {
	hash := higgscrypto.Hash([]byte(local), []byte{0}, []byte(peer), []byte{0}, []byte(overlayID))
	return "ipsec-" + hex.EncodeToString(hash[:6])
}

func StableXFRMIfID(local, peer zone.ZonePath, transportID string) uint32 {
	hash := higgscrypto.Hash([]byte(local), []byte{0}, []byte(peer), []byte{0}, []byte(transportID))
	ifID := binary.BigEndian.Uint32(hash[:4])
	if ifID == 0 {
		return 1
	}
	return ifID
}

func StableInterfaceName(ifID uint32) string {
	return fmt.Sprintf("hgs%x", ifID)
}

func ShouldInitiate(local, peer zone.ZonePath, direction, remoteAccept string) bool {
	switch direction {
	case DirectionOutbound:
		return remoteAccept == AcceptInbound || remoteAccept == AcceptBidirectional
	case DirectionInbound:
		return false
	case DirectionBidirectional:
		switch remoteAccept {
		case AcceptInbound:
			return true
		case AcceptBidirectional:
			return strings.Compare(string(local), string(peer)) < 0
		default:
			return false
		}
	default:
		return false
	}
}

func addrAt(prefix netip.Prefix, offset uint64) (netip.Addr, bool) {
	base := prefix.Masked().Addr()
	addr := base
	for offset > 0 {
		next := addr.Next()
		if !next.IsValid() || !prefix.Contains(next) {
			return netip.Addr{}, false
		}
		addr = next
		offset--
	}
	return addr, true
}

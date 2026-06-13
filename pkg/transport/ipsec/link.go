package ipsec

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/netip"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

const (
	DirectionInbound       = "inbound"
	DirectionOutbound      = "outbound"
	DirectionBidirectional = "bidirectional"

	NetNSHost        = "host"
	NetNSName        = "name"
	NetNSPath        = "path"
	DefaultNetNSName = "h2"

	TunnelAddressDerivedLinkLocal TunnelAddressMode = "derived-link-local"
	TunnelAddressDerivedPool      TunnelAddressMode = "derived-pool"
	TunnelAddressSequentialPool   TunnelAddressMode = "sequential-pool"
	TunnelAddressDisabled         TunnelAddressMode = "disabled"

	InitiatorRolePrimary           = "primary"
	InitiatorRoleSecondaryStandby  = "secondary-standby"
	InitiatorRoleSecondaryTakeover = "secondary-takeover"
	InitiatorRoleConverged         = "converged"
	InitiatorRoleCooldown          = "cooldown"
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
	Kind   string `yaml:"kind" json:"kind"`
	Name   string `yaml:"name,omitempty" json:"name,omitempty"`
	Path   string `yaml:"path,omitempty" json:"path,omitempty"`
	Create bool   `yaml:"create,omitempty" json:"create,omitempty"`
}

type TunnelAddressMode string

type TunnelAddressSpec struct {
	Mode   TunnelAddressMode `yaml:"mode" json:"mode"`
	Family string            `yaml:"family" json:"family"`
	Pool   netip.Prefix      `yaml:"pool" json:"pool"`
}

type BackoffPolicy struct {
	InitialSeconds int
	MaxSeconds     int
}

type ReconcilePolicy struct {
	IntervalSeconds        int
	RotateRetentionSeconds int
	Backoff                BackoffPolicy
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
	TunnelAddressSpec  TunnelAddressSpec
	Reconcile          ReconcilePolicy
	ConnectRules       []string
	DenyRules          []string
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
	// LocalAddress is the local underlay address used for the IKE endpoint.
	// If empty, the IPsec daemon binds to any address.
	LocalAddress string
	NetNS        string

	// LocalPrivateKey is the raw private key material for the local transport
	// identity. The driver is responsible for loading it into the IPsec daemon.
	LocalPrivateKey []byte
	// LocalPrivateKeyAlgorithm is one of AlgorithmEd25519 or AlgorithmECDSAP256.
	LocalPrivateKeyAlgorithm string
	// PeerPublicKey is the raw public key material for the peer transport
	// identity. The driver materializes it as needed (e.g. a PEM file for
	// StrongSwan raw-public-key authentication).
	PeerPublicKey []byte

	// InitiatorRole is a runtime planner/reconcile hint. It does not affect the
	// StrongSwan configuration and is excluded from the spec hash.
	InitiatorRole string
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
		IKEIdentity:     string(local),
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
	localAddr, peerAddr, err := group.DeriveTunnelAddresses(local, peer, linkIndex)
	if err != nil {
		return TransportLinkSpec{}, err
	}
	if group.normalizedTunnelAddress().Mode == TunnelAddressSequentialPool && peer < local {
		localAddr, peerAddr = peerAddr, localAddr
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
	netns := g.NetNS.Normalized()
	if err := netns.Validate(); err != nil {
		return err
	}
	if g.Reconcile.Backoff.MaxSeconds != 0 && g.Reconcile.Backoff.InitialSeconds > g.Reconcile.Backoff.MaxSeconds {
		return fmt.Errorf("backoff initial must not exceed max")
	}
	if g.Reconcile.RotateRetentionSeconds < 0 {
		return fmt.Errorf("rotate retention must be non-negative")
	}
	spec := g.normalizedTunnelAddress()
	switch spec.Mode {
	case TunnelAddressDisabled, TunnelAddressDerivedLinkLocal, TunnelAddressDerivedPool, TunnelAddressSequentialPool:
		// ok
	default:
		return fmt.Errorf("unsupported tunnel address mode %q", spec.Mode)
	}
	if spec.Mode != TunnelAddressDisabled && spec.Family != FamilyIPv4 && spec.Family != FamilyIPv6 {
		return fmt.Errorf("unsupported tunnel address family %q", spec.Family)
	}
	if (spec.Mode == TunnelAddressDerivedPool || spec.Mode == TunnelAddressSequentialPool) && !spec.Pool.IsValid() {
		return fmt.Errorf("tunnel address mode %q requires a pool", spec.Mode)
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
	if out.Reconcile.RotateRetentionSeconds == 0 {
		out.Reconcile.RotateRetentionSeconds = 3600
	}
	out.NetNS = out.NetNS.Normalized()
	if len(out.AddressSourceOrder) == 0 {
		out.AddressSourceOrder = append([]string(nil), defaultAddressSourceOrder...)
	}
	out.TunnelAddressSpec = out.normalizedTunnelAddress()
	if out.TunnelAddressSpec.Mode == TunnelAddressSequentialPool && out.TunnelAddressSpec.Pool.IsValid() {
		out.TunnelAddressPool = out.TunnelAddressSpec.Pool
	}
	return out
}

func (g LinkGroupSpec) TunnelAddresses(linkIndex int) (netip.Addr, netip.Addr, error) {
	return g.DeriveTunnelAddresses("", "", linkIndex)
}

func (g LinkGroupSpec) DeriveTunnelAddresses(local, peer zone.ZonePath, linkIndex int) (netip.Addr, netip.Addr, error) {
	if linkIndex < 0 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("link index must be non-negative")
	}
	spec := g.normalizedTunnelAddress()
	switch spec.Mode {
	case TunnelAddressDisabled:
		return netip.Addr{}, netip.Addr{}, nil
	case TunnelAddressSequentialPool:
		pool := spec.Pool
		if !pool.IsValid() {
			pool = g.TunnelAddressPool
		}
		return tunnelAddressesSequential(pool, linkIndex)
	case TunnelAddressDerivedLinkLocal:
		return deriveLinkLocalAddresses(local, peer, g.ID, g.Provider, linkIndex)
	case TunnelAddressDerivedPool:
		return derivePoolAddresses(local, peer, g.ID, g.Provider, spec.Pool, linkIndex)
	default:
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("unsupported tunnel address mode %q", spec.Mode)
	}
}

func (g LinkGroupSpec) normalizedTunnelAddress() TunnelAddressSpec {
	spec := g.TunnelAddressSpec
	if spec.Mode == "" && g.TunnelAddressPool.IsValid() {
		spec.Mode = TunnelAddressSequentialPool
		spec.Pool = g.TunnelAddressPool
	}
	if spec.Mode == "" && spec.Pool.IsValid() {
		spec.Mode = TunnelAddressSequentialPool
	}
	if spec.Mode == "" {
		switch spec.Family {
		case FamilyIPv4:
			spec.Mode = TunnelAddressDisabled
		default:
			spec.Mode = TunnelAddressDerivedLinkLocal
			if spec.Family == "" {
				spec.Family = FamilyIPv6
			}
		}
	}
	if spec.Family == "" {
		if spec.Pool.IsValid() {
			if spec.Pool.Addr().Is4() {
				spec.Family = FamilyIPv4
			} else {
				spec.Family = FamilyIPv6
			}
		} else {
			spec.Family = FamilyIPv6
		}
	}
	return spec
}

func tunnelAddressesSequential(pool netip.Prefix, linkIndex int) (netip.Addr, netip.Addr, error) {
	if !pool.IsValid() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("sequential-pool requires a valid pool")
	}
	local, ok := addrAt(pool, uint64(linkIndex*2+1))
	if !ok {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("link index %d exceeds tunnel address pool", linkIndex)
	}
	peer, ok := addrAt(pool, uint64(linkIndex*2+2))
	if !ok {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("link index %d exceeds tunnel address pool", linkIndex)
	}
	return local, peer, nil
}

func deriveLinkLocalAddresses(local, peer zone.ZonePath, overlayID, provider string, linkIndex int) (netip.Addr, netip.Addr, error) {
	const maxRetry = 64
	prefix := netip.MustParsePrefix("fe80::/64")
	lower, higher := sortedPair(local, peer)
	lowerID, err := deriveInterfaceID(lower, higher, overlayID, provider, FamilyIPv6, string(TunnelAddressDerivedLinkLocal), linkIndex, "lower", maxRetry)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	higherID, err := deriveInterfaceID(lower, higher, overlayID, provider, FamilyIPv6, string(TunnelAddressDerivedLinkLocal), linkIndex, "higher", maxRetry)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	lowerAddr := prefix.Addr().As16()
	higherAddr := prefix.Addr().As16()
	for i := 0; i < 8; i++ {
		lowerAddr[8+i] = byte(lowerID >> (56 - i*8))
		higherAddr[8+i] = byte(higherID >> (56 - i*8))
	}
	localAddr := netip.AddrFrom16(lowerAddr)
	peerAddr := netip.AddrFrom16(higherAddr)
	if local > peer {
		localAddr, peerAddr = peerAddr, localAddr
	}
	return localAddr, peerAddr, nil
}

func derivePoolAddresses(local, peer zone.ZonePath, overlayID, provider string, pool netip.Prefix, linkIndex int) (netip.Addr, netip.Addr, error) {
	if !pool.IsValid() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("derived-pool requires a valid pool")
	}
	const maxRetry = 256
	lower, higher := sortedPair(local, peer)
	localAddr, err := derivePoolAddr(lower, higher, overlayID, provider, pool, linkIndex, "lower", maxRetry)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	peerAddr, err := derivePoolAddr(lower, higher, overlayID, provider, pool, linkIndex, "higher", maxRetry)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	if local > peer {
		localAddr, peerAddr = peerAddr, localAddr
	}
	return localAddr, peerAddr, nil
}

func deriveInterfaceID(lower, higher zone.ZonePath, overlayID, provider, family, mode string, linkIndex int, role string, maxRetry int) (uint64, error) {
	for retry := 0; retry < maxRetry; retry++ {
		hash := higgscrypto.Hash(
			[]byte(overlayID),
			[]byte(lower),
			[]byte(higher),
			[]byte(family),
			[]byte(mode),
			[]byte(provider),
			[]byte(role),
			[]byte(fmt.Sprintf("%d:%d", linkIndex, retry)),
		)
		id := binary.BigEndian.Uint64(hash[:8])
		if id == 0 {
			continue
		}
		return id, nil
	}
	return 0, fmt.Errorf("exhausted retries deriving interface id for %s/%s", overlayID, role)
}

func derivePoolAddr(lower, higher zone.ZonePath, overlayID, provider string, pool netip.Prefix, linkIndex int, role string, maxRetry int) (netip.Addr, error) {
	bits := pool.Bits()
	if pool.Addr().Is4() {
		if bits < 1 || bits > 30 {
			return netip.Addr{}, fmt.Errorf("IPv4 derived-pool prefix %s has no usable hosts", pool)
		}
		hostBits := uint32(32 - bits)
		mask := uint32(1)<<hostBits - 1
		for retry := 0; retry < maxRetry; retry++ {
			hash := higgscrypto.Hash(
				[]byte(overlayID),
				[]byte(lower),
				[]byte(higher),
				[]byte(FamilyIPv4),
				[]byte(string(TunnelAddressDerivedPool)),
				[]byte(provider),
				[]byte(role),
				[]byte(fmt.Sprintf("%d:%d", linkIndex, retry)),
			)
			host := binary.BigEndian.Uint32(hash[:4]) & mask
			addr := pool.Masked().Addr().As4()
			base := binary.BigEndian.Uint32(addr[:])
			candidate := base | host
			if !isUsableIPv4Host(candidate, mask) {
				continue
			}
			out := netip.AddrFrom4(addrU32(candidate))
			if !pool.Contains(out) {
				continue
			}
			return out, nil
		}
		return netip.Addr{}, fmt.Errorf("exhausted retries deriving IPv4 address from %s", pool)
	}
	if bits < 1 || bits > 126 {
		return netip.Addr{}, fmt.Errorf("IPv6 derived-pool prefix %s has no usable hosts", pool)
	}
	hostBits := 128 - bits
	baseInt := addrToBig(pool.Masked().Addr())
	hostMask := big.NewInt(1)
	hostMask.Lsh(hostMask, uint(hostBits))
	hostMask.Sub(hostMask, big.NewInt(1))
	for retry := 0; retry < maxRetry; retry++ {
		hash := higgscrypto.Hash(
			[]byte(overlayID),
			[]byte(lower),
			[]byte(higher),
			[]byte(FamilyIPv6),
			[]byte(string(TunnelAddressDerivedPool)),
			[]byte(provider),
			[]byte(role),
			[]byte(fmt.Sprintf("%d:%d", linkIndex, retry)),
		)
		host := big.NewInt(0).SetBytes(hash[:16])
		host.And(host, hostMask)
		candidate := new(big.Int).Or(baseInt, host)
		out := bigToAddr16(candidate)
		if !pool.Contains(out) {
			continue
		}
		if out == pool.Masked().Addr() {
			continue
		}
		if !isUsableIPv6Host(out) {
			continue
		}
		return out, nil
	}
	return netip.Addr{}, fmt.Errorf("exhausted retries deriving IPv6 address from %s", pool)
}

func sortedPair(a, b zone.ZonePath) (zone.ZonePath, zone.ZonePath) {
	if a < b {
		return a, b
	}
	return b, a
}

func isUsableIPv4Host(candidate, mask uint32) bool {
	host := candidate & mask
	if host == 0 || host == mask {
		return false
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, candidate)
	if b[0] == 0 || b[0] == 255 {
		return false
	}
	return true
}

func isUsableIPv6Host(addr netip.Addr) bool {
	if !addr.Is6() {
		return false
	}
	return addr != netip.IPv6Unspecified() && !addr.IsLoopback() && addr != netip.MustParsePrefix("fe80::/64").Masked().Addr()
}

func addrU32(v uint32) [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b
}

func addrToBig(addr netip.Addr) *big.Int {
	b := addr.As16()
	return big.NewInt(0).SetBytes(b[:])
}

func bigToAddr16(v *big.Int) netip.Addr {
	b := v.Bytes()
	var out [16]byte
	copy(out[16-len(b):], b)
	return netip.AddrFrom16(out)
}

func (n NetNSSpec) Validate() error {
	n = n.Normalized()
	kind := n.Kind
	switch kind {
	case NetNSHost:
		if n.Name != "" || n.Path != "" || n.Create {
			return fmt.Errorf("host netns must not set name, path, or create")
		}
	case NetNSName:
		if n.Name == "" {
			return fmt.Errorf("netns name is required")
		}
		if n.Path != "" {
			return fmt.Errorf("netns name mode must not set path")
		}
	case NetNSPath:
		if n.Path == "" {
			return fmt.Errorf("netns path is required")
		}
		if n.Name != "" {
			return fmt.Errorf("netns path mode must not set name")
		}
		if n.Create {
			return fmt.Errorf("netns path mode cannot create namespaces")
		}
	default:
		return fmt.Errorf("unsupported netns kind %q", kind)
	}
	return nil
}

func (n NetNSSpec) Normalized() NetNSSpec {
	out := n
	if out.Kind == "" {
		out.Kind = NetNSName
	}
	if out.Kind == NetNSName && out.Name == "" {
		out.Name = DefaultNetNSName
	}
	if out.Kind == NetNSName && n.Kind == "" && n.Name == "" && n.Path == "" {
		out.Create = true
	}
	return out
}

func (n NetNSSpec) Target() string {
	n = n.Normalized()
	switch n.Kind {
	case NetNSHost:
		return ""
	case NetNSName:
		return n.Name
	case NetNSPath:
		return n.Path
	default:
		return ""
	}
}

func FormatScopedTunnelAddress(addr netip.Addr, ifName, netns string) string {
	if !addr.IsValid() {
		return "-"
	}
	s := addr.String()
	if addr.Is6() && addr.IsLinkLocalUnicast() {
		s += "%" + ifName
	}
	if netns != "" {
		s += " netns=" + netns
	}
	return s
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

// InitiatorRoleForPeer returns the local runtime role for a peer link.
// DirectionInbound still participates by loading a responder/trap config; it
// just never actively initiates. An empty role means policy/accept intent says
// the local node should not participate in this link at all.
func InitiatorRoleForPeer(local, peer zone.ZonePath, direction, remoteAccept string) string {
	switch direction {
	case DirectionOutbound:
		if remoteAccept == AcceptInbound || remoteAccept == AcceptBidirectional {
			return InitiatorRolePrimary
		}
	case DirectionInbound:
		return InitiatorRolePrimary
	case DirectionBidirectional:
		switch remoteAccept {
		case AcceptInbound:
			return InitiatorRolePrimary
		case AcceptBidirectional:
			if strings.Compare(string(local), string(peer)) < 0 {
				return InitiatorRolePrimary
			}
			return InitiatorRoleSecondaryStandby
		}
	}
	return ""
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

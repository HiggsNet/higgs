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
)

type MeshPolicy struct {
	OverlayID       string
	Provider        string
	Direction       string
	AddressFamilies []string
	Sources         []string
	PathMode        string
}

type TransportLinkSpec struct {
	LocalZone       zone.ZonePath
	PeerZone        zone.ZonePath
	OverlayID       string
	Provider        string
	TransportID     string
	IKEIdentity     string
	AuthRef         string
	ContactPoints   []ContactPoint
	XFRMIfID        uint32
	InterfaceName   string
	LocalTunnelAddr netip.Addr
	PeerTunnelAddr  netip.Addr
	NetNS           string
}

func NewTransportLinkSpec(local, peer zone.ZonePath, overlayID, transportID string, records *NodeRecords, contacts []ContactPoint) (TransportLinkSpec, error) {
	if overlayID == "" {
		return TransportLinkSpec{}, fmt.Errorf("overlay id is required")
	}
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
	if provider != ProviderStrongSwan {
		return TransportLinkSpec{}, fmt.Errorf("unsupported provider %q", provider)
	}
	if records.TransportKey != nil && records.Profile.TransportKeyFingerprint != records.TransportKey.Fingerprint {
		return TransportLinkSpec{}, fmt.Errorf("transport key fingerprint mismatch")
	}
	ifID := StableXFRMIfID(local, peer, transportID)
	return TransportLinkSpec{
		LocalZone:     local,
		PeerZone:      peer,
		OverlayID:     overlayID,
		Provider:      provider,
		TransportID:   transportID,
		IKEIdentity:   records.Profile.IKEIdentity,
		AuthRef:       records.Profile.TransportKeyFingerprint,
		ContactPoints: append([]ContactPoint(nil), contacts...),
		XFRMIfID:      ifID,
		InterfaceName: StableInterfaceName(ifID),
	}, nil
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

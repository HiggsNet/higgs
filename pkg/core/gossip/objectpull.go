package gossip

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/vmihailenco/msgpack/v5"
)

// ObjectPullRequestType defines the kind of object being requested.
type ObjectPullRequestType string

const (
	ObjectPullZone   ObjectPullRequestType = "zone"
	ObjectPullRecord ObjectPullRequestType = "record"
)

// ObjectPullRequest is sent over TCP to request a zone snapshot or a single record.
type ObjectPullRequest struct {
	Type    ObjectPullRequestType `msgpack:"t"`
	Zone    zone.ZonePath         `msgpack:"z"`
	Key     string                `msgpack:"k,omitempty"`
	Version uint64                `msgpack:"v,omitempty"`
}

// ObjectPullResponse is returned by the TCP object-pull server.
type ObjectPullResponse struct {
	OK       bool            `msgpack:"ok"`
	Snapshot *ZoneSnapshot   `msgpack:"s,omitempty"`
	Record   *RecordSnapshot `msgpack:"r,omitempty"`
	Error    string          `msgpack:"e,omitempty"`
}

// EncodeObjectPullRequest serializes a request with a 4-byte big-endian length prefix.
func EncodeObjectPullRequest(req *ObjectPullRequest) ([]byte, error) {
	payload, err := msgpack.Marshal(req)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out, nil
}

// DecodeObjectPullRequest reads a length-prefixed request from r.
func DecodeObjectPullRequest(r io.Reader) (*ObjectPullRequest, error) {
	payload, err := readLengthPrefixed(r, 1<<20) // 1 MiB max request
	if err != nil {
		return nil, err
	}
	var req ObjectPullRequest
	if err := msgpack.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// EncodeObjectPullResponse serializes a response with a 4-byte big-endian length prefix.
func EncodeObjectPullResponse(resp *ObjectPullResponse) ([]byte, error) {
	payload, err := msgpack.Marshal(resp)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out, nil
}

// DecodeObjectPullResponse reads a length-prefixed response from r.
func DecodeObjectPullResponse(r io.Reader) (*ObjectPullResponse, error) {
	payload, err := readLengthPrefixed(r, 8<<20) // 8 MiB max response
	if err != nil {
		return nil, err
	}
	var resp ObjectPullResponse
	if err := msgpack.Unmarshal(payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func EncodeZoneSnapshotObject(snapshot *ZoneSnapshot) ([]byte, error) {
	return msgpack.Marshal(snapshot)
}

func DecodeZoneSnapshotObject(data []byte) (*ZoneSnapshot, error) {
	var snapshot ZoneSnapshot
	if err := msgpack.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func readLengthPrefixed(r io.Reader, maxSize int) ([]byte, error) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint32(sizeBuf[:]))
	if size > maxSize {
		return nil, fmt.Errorf("object pull payload size %d exceeds max %d", size, maxSize)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

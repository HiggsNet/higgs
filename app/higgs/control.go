package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

const controlSocketName = "higgs.sock"

type controlRequest struct {
	Method    string `json:"method"`
	Zone      string `json:"zone,omitempty"`
	Key       string `json:"key,omitempty"`
	Value     []byte `json:"value,omitempty"`
	ValueText string `json:"value_text,omitempty"`
	Type      string `json:"type,omitempty"`
}

type controlResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	PeerID  string `json:"peer_id,omitempty"`
	Version uint64 `json:"version,omitempty"`
	Message string `json:"message,omitempty"`
}

func controlSocketPath(config *appConfig) string {
	if path := os.Getenv("HIGGS_CONTROL_SOCKET"); path != "" {
		return path
	}
	if os.Geteuid() == 0 {
		if _, err := os.Stat("/run/higgs"); err == nil {
			return filepath.Join("/run/higgs", controlSocketName)
		}
	}
	dataDir := "."
	if config != nil && config.DataDir != "" {
		dataDir = config.DataDir
	}
	return filepath.Join(dataDir, controlSocketName)
}

func sendControlRequest(path string, request controlRequest) (*controlResponse, error) {
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, err
	}
	var response controlResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return nil, err
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "daemon control request failed"
		}
		return &response, errors.New(response.Error)
	}
	return &response, nil
}

func daemonStatusViaControl(rt *Runtime) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "status"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

func putRecordViaControl(rt *Runtime, path zone.ZonePath, key string, value []byte, recordType string) (uint64, bool, error) {
	socketPath := controlSocketPath(rt.Config)
	response, err := sendControlRequest(socketPath, controlRequest{
		Method: "record_put",
		Zone:   path.String(),
		Key:    key,
		Value:  value,
		Type:   recordType,
	})
	if err != nil {
		if isControlSocketUnavailable(err) {
			return 0, false, nil
		}
		return 0, true, err
	}
	return response.Version, true, nil
}

func isControlSocketUnavailable(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	return errors.Is(err, os.ErrNotExist)
}

func writeControlResponse(conn net.Conn, response controlResponse) {
	if !response.OK && response.Error == "" {
		response.Error = "request failed"
	}
	_ = json.NewEncoder(conn).Encode(response)
}

func controlError(err error) controlResponse {
	return controlResponse{OK: false, Error: err.Error()}
}

func parseControlRecordValue(request controlRequest) []byte {
	if request.Value != nil {
		return request.Value
	}
	return []byte(request.ValueText)
}

func controlContext(ctx context.Context) context.Context {
	if ctx != nil {
		return ctx
	}
	return context.Background()
}

func validateControlRecordPut(request controlRequest) error {
	if zone.ZonePath(request.Zone) == "" || request.Key == "" {
		return fmt.Errorf("record_put requires zone and key")
	}
	if request.Type == "" {
		return fmt.Errorf("record_put requires type")
	}
	return nil
}

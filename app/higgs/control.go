package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
)

type routesDumpResponse struct {
	LocalZone   zone.ZonePath                  `json:"local_zone"`
	ExportSet   []string                       `json:"export_set"`
	Authorized  map[string][]string            `json:"authorized"`
	Assignments map[string]routeAssignmentInfo `json:"assignments"`
	Errors      []routeAuthorizationErrorJSON  `json:"errors"`
}

type routeAssignmentInfo struct {
	Source     string `json:"source"`
	AssignedTo string `json:"assigned_to"`
}

type routeAuthorizationErrorJSON struct {
	Zone   string `json:"zone"`
	Prefix string `json:"prefix,omitempty"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

const controlSocketName = "higgs.sock"

type controlRequest struct {
	Method      string          `json:"method"`
	Zone        string          `json:"zone,omitempty"`
	Key         string          `json:"key,omitempty"`
	Value       []byte          `json:"value,omitempty"`
	ValueText   string          `json:"value_text,omitempty"`
	Type        string          `json:"type,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	JoinRequest *joinRequest    `json:"join_request,omitempty"`
	JoinBundle  *joinBundle     `json:"join_bundle,omitempty"`
	PrivateKey  *privateKeyFile `json:"private_key,omitempty"`
}

type controlResponse struct {
	OK                bool                          `json:"ok"`
	Error             string                        `json:"error,omitempty"`
	PeerID            string                        `json:"peer_id,omitempty"`
	LinkInstances     int                           `json:"link_instances,omitempty"`
	DesiredLinks      int                           `json:"desired_links,omitempty"`
	LastLinkError     string                        `json:"last_link_error,omitempty"`
	LastRoutingError  string                        `json:"last_routing_error,omitempty"`
	Version           uint64                        `json:"version,omitempty"`
	Message           string                        `json:"message,omitempty"`
	Zone              zone.ZonePath                 `json:"zone,omitempty"`
	RootPublicKey     ed25519.PublicKey             `json:"root_public_key,omitempty"`
	JoinBundle        *joinBundle                   `json:"join_bundle,omitempty"`
	BirdInstances     map[string]*BirdInstanceState `json:"bird_instances,omitempty"`
	RoutesDump        *routesDumpResponse           `json:"routes_dump,omitempty"`
	Admission         *admissionDiagnosis           `json:"admission,omitempty"`
	FirewallReconcile *firewallReconcileState       `json:"firewall_reconcile,omitempty"`
	PeerStatuses      []PeerStatusInfo              `json:"peer_statuses,omitempty"`
	RevocationImpact  []RevocationImpact            `json:"revocation_impact,omitempty"`
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

func birdStatusViaControl(rt *Runtime) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "bird_status"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

func routesDumpViaControl(rt *Runtime) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "routes_dump"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

func admissionStatusViaControl(rt *Runtime) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "admission_status"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

func buildRoutesDumpResponse(managedZone zone.ZonePath, ars *routing.AuthorizedRouteSet) *routesDumpResponse {
	if ars == nil {
		return &routesDumpResponse{LocalZone: managedZone}
	}
	exportSet := make([]string, 0)
	for p := range ars.Announced[managedZone] {
		exportSet = append(exportSet, p.String())
	}
	sort.Strings(exportSet)
	authorized := make(map[string][]string, len(ars.Announced))
	for z, prefixes := range ars.Announced {
		ps := make([]string, 0, len(prefixes))
		for p := range prefixes {
			ps = append(ps, p.String())
		}
		sort.Strings(ps)
		authorized[string(z)] = ps
	}
	assignments := make(map[string]routeAssignmentInfo, len(ars.Assignments))
	for p, entry := range ars.Assignments {
		assignments[p.String()] = routeAssignmentInfo{
			Source:     string(entry.Source),
			AssignedTo: string(entry.AssignedTo),
		}
	}
	errors := make([]routeAuthorizationErrorJSON, 0, len(ars.Errors))
	for _, e := range ars.Errors {
		prefix := ""
		if e.Prefix.IsValid() {
			prefix = e.Prefix.String()
		}
		errors = append(errors, routeAuthorizationErrorJSON{
			Zone:   string(e.Zone),
			Prefix: prefix,
			Code:   e.Code,
			Detail: e.Detail,
		})
	}
	return &routesDumpResponse{
		LocalZone:   managedZone,
		ExportSet:   exportSet,
		Authorized:  authorized,
		Assignments: assignments,
		Errors:      errors,
	}
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

func issueDelegationViaControl(rt *Runtime, request *joinRequest) (*joinBundle, bool, error) {
	response, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method:      "delegate_issue",
		JoinRequest: request,
	})
	if err != nil || !ok {
		return nil, ok, err
	}
	if response.JoinBundle == nil {
		return nil, true, errors.New("daemon delegate_issue response missing join bundle")
	}
	return response.JoinBundle, true, nil
}

func revokeDelegationViaControl(rt *Runtime, path zone.ZonePath, reason string) (bool, error) {
	_, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method: "delegate_revoke",
		Zone:   path.String(),
		Reason: reason,
	})
	return ok, err
}

func acceptJoinBundleViaControl(rt *Runtime, bundle *joinBundle, key *privateKeyFile) (bool, error) {
	_, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method:     "join_accept",
		JoinBundle: bundle,
		PrivateKey: key,
	})
	return ok, err
}

func initRootViaControl(rt *Runtime) (ed25519.PublicKey, bool, error) {
	response, ok, err := sendAdminControlRequest(rt, controlRequest{Method: "root_init"})
	if err != nil || !ok {
		return nil, ok, err
	}
	return response.RootPublicKey, true, nil
}

func sendAdminControlRequest(rt *Runtime, request controlRequest) (*controlResponse, bool, error) {
	socketPath := controlSocketPath(nil)
	if rt != nil {
		socketPath = controlSocketPath(rt.Config)
	}
	response, err := sendControlRequest(socketPath, request)
	if err != nil {
		if isControlSocketUnavailable(err) {
			return nil, false, nil
		}
		return nil, true, err
	}
	return response, true, nil
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
	_ = conn.SetWriteDeadline(time.Now().Add(controlConnDeadline))
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

func validateControlDelegateIssue(request controlRequest) error {
	if request.JoinRequest == nil {
		return errors.New("delegate_issue requires join_request")
	}
	return validateJoinRequest(request.JoinRequest)
}

func validateControlDelegateRevoke(request controlRequest) error {
	if zone.ZonePath(request.Zone) == "" {
		return errors.New("delegate_revoke requires zone")
	}
	return nil
}

func validateControlJoinAccept(request controlRequest) error {
	if request.JoinBundle == nil {
		return errors.New("join_accept requires join_bundle")
	}
	if request.PrivateKey == nil {
		return errors.New("join_accept requires private_key")
	}
	return validatePrivateKeyFile(request.PrivateKey)
}

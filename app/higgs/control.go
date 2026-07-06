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

	"github.com/Catofes/higgs/internal/inspect"
	inspecthttp "github.com/Catofes/higgs/internal/inspect/http"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

const controlSocketName = "higgs.sock"

type controlRequest struct {
	Method      string               `json:"method"`
	Zone        string               `json:"zone,omitempty"`
	Key         string               `json:"key,omitempty"`
	Value       []byte               `json:"value,omitempty"`
	ValueText   string               `json:"value_text,omitempty"`
	Type        string               `json:"type,omitempty"`
	History     int                  `json:"history,omitempty"`
	Reason      string               `json:"reason,omitempty"`
	JoinRequest *joinRequest         `json:"join_request,omitempty"`
	JoinBundle  *joinBundle          `json:"join_bundle,omitempty"`
	PrivateKey  *privateKeyFile      `json:"private_key,omitempty"`
	Permissions []zone.Permission    `json:"permissions,omitempty"`
	Snapshot    *gossip.ZoneSnapshot `json:"snapshot,omitempty"`
	Apply       bool                 `json:"apply,omitempty"`
	Orphans     bool                 `json:"orphans,omitempty"`
	NetNS       string               `json:"netns,omitempty"`
	Command     string               `json:"command,omitempty"`
}

type controlResponse struct {
	OK                bool                          `json:"ok"`
	Error             string                        `json:"error,omitempty"`
	StateRevision     uint64                        `json:"state_revision,omitempty"`
	SnapshotTimeUnix  int64                         `json:"snapshot_time_unix,omitempty"`
	Dirty             daemonDirtyFlags              `json:"dirty,omitempty"`
	ReconcileProgress daemonReconcileStatus         `json:"reconcile_in_progress,omitempty"`
	PeerID            string                        `json:"peer_id,omitempty"`
	LinkInstances     int                           `json:"link_instances,omitempty"`
	CleanedLinks      int                           `json:"cleaned_links,omitempty"`
	CleanedOrphans    int                           `json:"cleaned_orphans,omitempty"`
	DesiredLinks      int                           `json:"desired_links,omitempty"`
	LastLinkError     string                        `json:"last_link_error,omitempty"`
	LastRoutingError  string                        `json:"last_routing_error,omitempty"`
	Version           uint64                        `json:"version,omitempty"`
	Message           string                        `json:"message,omitempty"`
	Zone              zone.ZonePath                 `json:"zone,omitempty"`
	RootPublicKey     ed25519.PublicKey             `json:"root_public_key,omitempty"`
	JoinBundle        *joinBundle                   `json:"join_bundle,omitempty"`
	BirdInstances     map[string]*BirdInstanceState `json:"bird_instances,omitempty"`
	BirdDump          *inspect.BirdDumpResponse     `json:"bird_dump,omitempty"`
	RoutesDump        *inspecthttp.RoutesResponse   `json:"routes_dump,omitempty"`
	Admission         *inspect.AdmissionDiagnosis   `json:"admission,omitempty"`
	FirewallReconcile *firewallReconcileState       `json:"firewall_reconcile,omitempty"`
	Links             *linkInspectionControl        `json:"links,omitempty"`
	PeerStatuses      []inspect.PeerStatusInfo      `json:"peer_statuses,omitempty"`
	RevocationImpact  []inspect.RevocationImpact    `json:"revocation_impact,omitempty"`
	Health            []healthLinkJSON              `json:"health,omitempty"`
	Record            *inspect.RecordDetailView     `json:"record,omitempty"`
	PortRotate        *manualPortRotateResult       `json:"port_rotate,omitempty"`
	RecordsApplied    int                           `json:"records_applied,omitempty"`
	Delegations       int                           `json:"delegations,omitempty"`
	Revocations       int                           `json:"revocations,omitempty"`
	PurgePlan         *purgePlan                    `json:"purge_plan,omitempty"`
}

type linkInspectionControl struct {
	Inspection        inspect.LinkInspection `json:"inspection"`
	ReplannedDesired  int                    `json:"replanned_desired"`
	ReplanIgnored     bool                   `json:"replan_ignored,omitempty"`
	LastDesiredLinks  int                    `json:"last_desired_links,omitempty"`
	DesiredPlanSource string                 `json:"desired_plan_source,omitempty"`
	ActualSAs         []linkSAState          `json:"actual_sas,omitempty"`
}

// healthLinkJSON is the JSON representation of health.LinkHealth for the
// control API. It keeps time.Duration fields as millisecond integers for
// compact serialization.
type healthLinkJSON struct {
	ProbeID         string `json:"probe_id,omitempty"`
	InstanceID      string `json:"instance_id"`
	ProbeRole       string `json:"probe_role,omitempty"`
	InterfaceName   string `json:"interface_name,omitempty"`
	State           string `json:"state"`
	ProbeType       string `json:"probe_type"`
	Sent            int    `json:"sent"`
	Received        int    `json:"received"`
	Lost            int    `json:"lost"`
	LossRatio       int    `json:"loss_ratio_pct"`
	LastRTTMs       int64  `json:"last_rtt_ms"`
	EWMARTTMs       int64  `json:"ewma_rtt_ms"`
	P50RTTMs        int64  `json:"p50_rtt_ms"`
	P95RTTMs        int64  `json:"p95_rtt_ms"`
	P99RTTMs        int64  `json:"p99_rtt_ms"`
	JitterMs        int64  `json:"jitter_ms"`
	ConsecutiveFail int    `json:"consecutive_fail"`
	LastError       string `json:"last_error,omitempty"`
	NextProbeUnix   int64  `json:"next_probe_unix,omitempty"`
	CutoverBlocking bool   `json:"cutover_blocking,omitempty"`
}

func healthLinkJSONFromHealth(h healthLinkHealthView) healthLinkJSON {
	return healthLinkJSON{
		ProbeID:         h.ProbeID,
		InstanceID:      h.InstanceID,
		ProbeRole:       h.ProbeRole,
		InterfaceName:   h.InterfaceName,
		State:           h.State,
		ProbeType:       h.ProbeType,
		Sent:            h.Sent,
		Received:        h.Received,
		Lost:            h.Lost,
		LossRatio:       int(h.LossRatio * 100),
		LastRTTMs:       h.LastRTT.Milliseconds(),
		EWMARTTMs:       h.EWMARTT.Milliseconds(),
		P50RTTMs:        h.P50RTT.Milliseconds(),
		P95RTTMs:        h.P95RTT.Milliseconds(),
		P99RTTMs:        h.P99RTT.Milliseconds(),
		JitterMs:        h.Jitter.Milliseconds(),
		ConsecutiveFail: h.ConsecutiveFail,
		LastError:       h.LastError,
		NextProbeUnix:   h.NextProbeUnix,
		CutoverBlocking: h.CutoverBlocking,
	}
}

// healthLinkHealthView is a local view type used to convert health.LinkHealth
// without importing pkg/health in control.go (kept for layered imports).
type healthLinkHealthView struct {
	ProbeID         string
	InstanceID      string
	ProbeRole       string
	InterfaceName   string
	State           string
	ProbeType       string
	Sent            int
	Received        int
	Lost            int
	LossRatio       float64
	LastRTT         time.Duration
	EWMARTT         time.Duration
	P50RTT          time.Duration
	P95RTT          time.Duration
	P99RTT          time.Duration
	Jitter          time.Duration
	ConsecutiveFail int
	LastError       string
	NextProbeUnix   int64
	CutoverBlocking bool
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
	_ = conn.SetDeadline(time.Now().Add(controlConnDeadline))
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

func routingReloadViaControl(rt *Runtime) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "routing_reload"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

func birdDumpViaControl(rt *Runtime, netnsName, command string) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "bird_dump", NetNS: netnsName, Command: command})
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

func linksStatusViaControl(rt *Runtime) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "links_status"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

func (d *DaemonService) birdRoutesForControl(ctx context.Context, dump *inspecthttp.RoutesResponse, instances []RoutingInstance, birdStates map[string]*BirdInstanceState) []inspecthttp.BirdRoutesView {
	if d == nil || dump == nil {
		return nil
	}
	views := make([]inspecthttp.BirdRoutesView, 0, len(instances))
	for _, inst := range instances {
		if !inst.Enabled || inst.Mode == ipsec.RoutingModeDisabled {
			continue
		}
		state := birdStates[inst.NetNS]
		view := inspecthttp.BirdRoutesView{
			NetNS:      inst.NetNS,
			InstanceID: inst.ID,
		}
		socketPath := inst.ControlSocket
		if state != nil {
			view.State = state.State
			if state.LastError != "" {
				view.Error = state.LastError
			}
			if state.ControlSocket != "" {
				socketPath = state.ControlSocket
			}
		}
		if socketPath == "" {
			if view.Error == "" {
				view.Error = "control socket not configured"
			}
			views = append(views, view)
			continue
		}
		observed, err := d.newBirdClient(socketPath).Status(ctx)
		if err != nil {
			view.Error = err.Error()
			views = append(views, view)
			continue
		}
		if observed != nil {
			view.Routes = inspecthttp.BuildBirdRouteViews(dump, observed.Routes)
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].NetNS != views[j].NetNS {
			return views[i].NetNS < views[j].NetNS
		}
		return views[i].InstanceID < views[j].InstanceID
	})
	return views
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

func getRecordViaControl(rt *Runtime, path zone.ZonePath, key string, history int) (*inspect.RecordDetailView, bool, error) {
	socketPath := controlSocketPath(rt.Config)
	response, err := sendControlRequest(socketPath, controlRequest{
		Method:  "record_get",
		Zone:    path.String(),
		Key:     key,
		History: history,
	})
	if err != nil {
		if isControlSocketUnavailable(err) {
			return nil, false, nil
		}
		return nil, true, err
	}
	if response.Record == nil {
		return nil, true, errors.New("daemon record_get response missing record")
	}
	return response.Record, true, nil
}

func rotateIPsecPortViaControl(rt *Runtime) (*manualPortRotateResult, bool, error) {
	socketPath := controlSocketPath(rt.Config)
	response, err := sendControlRequest(socketPath, controlRequest{Method: "ipsec_rotate_port"})
	if err != nil {
		if isControlSocketUnavailable(err) {
			return nil, false, nil
		}
		return nil, true, err
	}
	if response.PortRotate == nil {
		return nil, true, errors.New("daemon ipsec_rotate_port response missing result")
	}
	return response.PortRotate, true, nil
}

func issueDelegationViaControl(rt *Runtime, request *joinRequest, permissions []zone.Permission) (*joinBundle, bool, error) {
	response, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method:      "delegate_issue",
		JoinRequest: request,
		Permissions: permissions,
	})
	if err != nil || !ok {
		return nil, ok, err
	}
	if response.JoinBundle == nil {
		return nil, true, errors.New("daemon delegate_issue response missing join bundle")
	}
	return response.JoinBundle, true, nil
}

func grantAuthorityViaControl(rt *Runtime, path zone.ZonePath, permissions []zone.Permission) (*joinBundle, bool, error) {
	response, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method:      "authority_grant",
		Zone:        path.String(),
		Permissions: permissions,
	})
	if err != nil || !ok {
		return nil, ok, err
	}
	return response.JoinBundle, true, nil
}

func importRecoveryZoneViaControl(rt *Runtime, snapshot *gossip.ZoneSnapshot) (*gossip.ApplyResult, int, bool, error) {
	response, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method:   "recovery_import_zone",
		Snapshot: snapshot,
	})
	if err != nil || !ok {
		return nil, 0, ok, err
	}
	return &gossip.ApplyResult{
		Zone:       response.Zone,
		Records:    response.RecordsApplied,
		Delegation: response.Delegations,
	}, response.Revocations, true, nil
}

func revokeDelegationViaControl(rt *Runtime, path zone.ZonePath, reason string) (bool, error) {
	_, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method: "delegate_revoke",
		Zone:   path.String(),
		Reason: reason,
	})
	return ok, err
}

func purgeRevokedViaControl(rt *Runtime, apply bool, target zone.ZonePath) (*purgePlan, bool, error) {
	response, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method: "recovery_purge_revoked",
		Zone:   target.String(),
		Apply:  apply,
	})
	if err != nil || !ok {
		return nil, ok, err
	}
	return response.PurgePlan, true, nil
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

func validateControlRecordGet(request controlRequest) error {
	if zone.ZonePath(request.Zone) == "" || request.Key == "" {
		return fmt.Errorf("record_get requires zone and key")
	}
	if request.History < 0 {
		return fmt.Errorf("record_get history must be >= 0")
	}
	return nil
}

func validateControlDelegateIssue(request controlRequest) error {
	if request.JoinRequest == nil {
		return errors.New("delegate_issue requires join_request")
	}
	return validateJoinRequest(request.JoinRequest)
}

func validateControlAuthorityGrant(request controlRequest) error {
	path := zone.ZonePath(request.Zone)
	if !path.Valid() {
		return fmt.Errorf("invalid authority zone: %s", request.Zone)
	}
	if len(request.Permissions) == 0 {
		return errors.New("authority_grant requires permissions")
	}
	for _, permission := range request.Permissions {
		if _, err := parseAuthorityPermission(string(permission)); err != nil {
			return err
		}
	}
	return nil
}

func validateControlRecoveryImportZone(request controlRequest) error {
	if request.Snapshot == nil {
		return errors.New("recovery_import_zone requires snapshot")
	}
	if !request.Snapshot.Zone.Valid() {
		return fmt.Errorf("invalid recovery zone: %s", request.Snapshot.Zone)
	}
	return nil
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
		return nil
	}
	return validatePrivateKeyFile(request.PrivateKey)
}

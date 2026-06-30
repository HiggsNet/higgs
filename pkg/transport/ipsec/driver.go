package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultVICIOperationTimeout     = 10 * time.Second
	defaultVICIInitiateAsyncTimeout = 5 * time.Minute
)

type SAState struct {
	Name           string
	Peer           string
	ChildSA        string
	IKEState       string
	ChildState     string
	XFRMIfID       uint32
	ReqID          uint32
	LocalIdentity  string
	RemoteIdentity string
	LocalEndpoint  string
	RemoteEndpoint string
	Endpoint       string
	Established    bool
}

type VICIEvent struct {
	Name           string
	Connection     string
	ChildSA        string
	Up             bool
	XFRMIfID       uint32
	ReqID          uint32
	LocalIdentity  string
	RemoteIdentity string
	LocalEndpoint  string
	RemoteEndpoint string
	Raw            map[string]any
}

type VICIClient interface {
	Call(context.Context, string, map[string]any) (map[string]any, error)
	CallStreaming(context.Context, string, string, map[string]any) ([]map[string]any, error)
}

type VICIEventClient interface {
	SubscribeEvents(context.Context, ...string) (<-chan VICIEvent, func(), error)
}

type IPsecDriver interface {
	LoadConnection(context.Context, TransportLinkSpec) error
	UnloadConnection(context.Context, string) error
	TerminateSA(context.Context, string) error
	ListSAs(context.Context) ([]SAState, error)
	LoadPrivateKey(ctx context.Context, id string, key []byte, algorithm string) error
	UnloadPrivateKey(ctx context.Context, id string) error
}

type ChildInitiator interface {
	InitiateChild(context.Context, string) error
}

type XFRMDriver interface {
	EnsureNamespace(context.Context, NetNSSpec) error
	EnsureInterface(context.Context, TransportLinkSpec) error
	DeleteInterface(context.Context, string) error
	AssignAddress(context.Context, TransportLinkSpec, string) error
}

type XFRMLinkState struct {
	NetNS           NetNSSpec
	NamespaceExists bool
	InterfaceExists bool
}

type XFRMLinkInspector interface {
	InspectLink(context.Context, TransportLinkSpec) (XFRMLinkState, error)
}

type XFRMSAFilter interface {
	FilterSAsWithMissingLinks(context.Context, []TransportLinkSpec, []SAState) ([]SAState, map[string]TransportLinkSpec, error)
}

type DryRunDriver struct {
	Connections  []TransportLinkSpec
	Initiated    []string
	Unloaded     []string
	Terminated   []string
	Interfaces   []TransportLinkSpec
	Namespaces   []NetNSSpec
	DeletedIFs   []string
	Addresses    []string
	PrivateKeys  []DryRunPrivateKey
	UnloadedKeys []string
}

type DryRunPrivateKey struct {
	ID        string
	Algorithm string
	Len       int
}

type ApplyOperation struct {
	Action string
	Target string
	Detail string
}

type ApplyPlan struct {
	Operations []ApplyOperation
}

type StrongSwanDriver struct {
	VICI                  VICIClient
	KeyDir                string
	LogConfig             func(event string, fields map[string]any)
	OperationTimeout      time.Duration
	InitiateAsync         bool
	InitiateTimeout       time.Duration
	InitiateClientFactory func() (VICIClient, func() error, error)

	keyIDs       map[string]string
	keyIDsMu     sync.Mutex
	initiateMu   sync.Mutex
	initiateBusy map[string]struct{}
}

func PlanApply(spec TransportLinkSpec, netns NetNSSpec) ApplyPlan {
	netns = netns.Normalized()
	plan := ApplyPlan{}
	plan.add("ensure_namespace", netns.Target(), netns.Kind)
	if len(spec.LocalPrivateKey) > 0 {
		plan.add("load_private_key", spec.TransportID, spec.LocalPrivateKeyAlgorithm)
	}
	plan.add("load_connection", spec.TransportID, string(spec.PeerZone))
	plan.add("ensure_interface", spec.InterfaceName, fmt.Sprintf("if_id=%d netns=%s", spec.XFRMIfID, spec.NetNS))
	if spec.LocalTunnelAddr.IsValid() {
		plan.add("assign_address", spec.InterfaceName, FormatScopedTunnelAddress(spec.LocalTunnelAddr, spec.InterfaceName, spec.NetNS))
	}
	return plan
}

func PlanTeardown(spec TransportLinkSpec) ApplyPlan {
	plan := ApplyPlan{}
	plan.add("terminate_sa", spec.TransportID, string(spec.PeerZone))
	plan.add("unload_connection", spec.TransportID, string(spec.PeerZone))
	if len(spec.LocalPrivateKey) > 0 {
		plan.add("unload_private_key", spec.TransportID, spec.LocalPrivateKeyAlgorithm)
	}
	plan.add("delete_interface", spec.InterfaceName, fmt.Sprintf("if_id=%d netns=%s", spec.XFRMIfID, spec.NetNS))
	return plan
}

func ApplyStagedConnection(ctx context.Context, ipsec IPsecDriver, xfrm XFRMDriver, spec TransportLinkSpec, netns NetNSSpec) (ApplyPlan, error) {
	if ipsec == nil {
		return ApplyPlan{}, fmt.Errorf("ipsec driver is required")
	}
	if xfrm == nil {
		return ApplyPlan{}, fmt.Errorf("xfrm driver is required")
	}
	plan := PlanApply(spec, netns)
	var filtered []ApplyOperation
	for _, op := range plan.Operations {
		if op.Action != "load_private_key" {
			filtered = append(filtered, op)
		}
	}
	plan.Operations = filtered
	if err := xfrm.EnsureNamespace(ctx, netns); err != nil {
		return plan, fmt.Errorf("ensure namespace: %w", err)
	}
	// Unload the base connection before loading the staged one. This prevents
	// StrongSwan from matching incoming rotation packets against the base
	// config and creating the staged IKE_SA under the wrong connection name.
	// The base IKE_SA remains established because we only unload the config.
	baseName := BaseConnectionName(spec.TransportID)
	if baseName != spec.TransportID {
		_ = ipsec.UnloadConnection(ctx, baseName)
	}
	if err := ipsec.LoadConnection(ctx, spec); err != nil {
		return plan, fmt.Errorf("load connection: %w", err)
	}
	if err := xfrm.EnsureInterface(ctx, spec); err != nil {
		return plan, fmt.Errorf("ensure interface: %w", err)
	}
	if spec.LocalTunnelAddr.IsValid() {
		if err := xfrm.AssignAddress(ctx, spec, tunnelAddressPrefix(spec.LocalTunnelAddr)); err != nil {
			return plan, fmt.Errorf("assign address: %w", err)
		}
	}
	// Staged connections rely on StrongSwan's start_action (start/trap) instead
	// of an explicit vici initiate. This avoids racing with the auto-start that
	// load-conn triggers for active initiators while still letting responders
	// install a trap policy.
	if IsActiveInitiatorRole(spec.InitiatorRole) {
		child := ChildSAName(spec)
		plan.add("initiate_child", child, spec.TransportID)
	}
	return plan, nil
}

func ApplyTransportLink(ctx context.Context, ipsec IPsecDriver, xfrm XFRMDriver, spec TransportLinkSpec, netns NetNSSpec) (ApplyPlan, error) {
	if ipsec == nil {
		return ApplyPlan{}, fmt.Errorf("ipsec driver is required")
	}
	if xfrm == nil {
		return ApplyPlan{}, fmt.Errorf("xfrm driver is required")
	}
	plan := PlanApply(spec, netns)
	if err := xfrm.EnsureNamespace(ctx, netns); err != nil {
		return plan, fmt.Errorf("ensure namespace: %w", err)
	}
	if len(spec.LocalPrivateKey) > 0 {
		if err := ipsec.LoadPrivateKey(ctx, spec.TransportID, spec.LocalPrivateKey, spec.LocalPrivateKeyAlgorithm); err != nil {
			return plan, fmt.Errorf("load private key: %w", err)
		}
	}
	if err := ipsec.LoadConnection(ctx, spec); err != nil {
		return plan, fmt.Errorf("load connection: %w", err)
	}
	if err := xfrm.EnsureInterface(ctx, spec); err != nil {
		return plan, fmt.Errorf("ensure interface: %w", err)
	}
	if spec.LocalTunnelAddr.IsValid() {
		if err := xfrm.AssignAddress(ctx, spec, tunnelAddressPrefix(spec.LocalTunnelAddr)); err != nil {
			return plan, fmt.Errorf("assign address: %w", err)
		}
	}
	return plan, nil
}

func InitiateTransportChild(ctx context.Context, ipsec IPsecDriver, spec TransportLinkSpec, plan *ApplyPlan) error {
	if !IsActiveInitiatorRole(spec.InitiatorRole) {
		return nil
	}
	initiator, ok := ipsec.(ChildInitiator)
	if !ok {
		return nil
	}
	child := ChildSAName(spec)
	if plan != nil {
		plan.add("initiate_child", child, spec.TransportID)
	}
	if err := initiator.InitiateChild(ctx, child); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return fmt.Errorf("initiate child: %w", err)
	}
	return nil
}

func tunnelAddressPrefix(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	bits := 32
	if addr.Is6() {
		bits = 128
		if addr.IsLinkLocalUnicast() {
			bits = 64
		}
	}
	return netip.PrefixFrom(addr, bits).String()
}

func TeardownTransportLink(ctx context.Context, ipsec IPsecDriver, xfrm XFRMDriver, spec TransportLinkSpec) (ApplyPlan, error) {
	if ipsec == nil {
		return ApplyPlan{}, fmt.Errorf("ipsec driver is required")
	}
	if xfrm == nil {
		return ApplyPlan{}, fmt.Errorf("xfrm driver is required")
	}
	plan := PlanTeardown(spec)
	if err := ipsec.TerminateSA(ctx, spec.TransportID); err != nil {
		return plan, fmt.Errorf("terminate sa: %w", err)
	}
	if err := ipsec.UnloadConnection(ctx, spec.TransportID); err != nil {
		return plan, fmt.Errorf("unload connection: %w", err)
	}
	if len(spec.LocalPrivateKey) > 0 {
		if err := ipsec.UnloadPrivateKey(ctx, spec.TransportID); err != nil {
			return plan, fmt.Errorf("unload private key: %w", err)
		}
	}
	if err := xfrm.DeleteInterface(ctx, spec.InterfaceName); err != nil {
		return plan, fmt.Errorf("delete interface: %w", err)
	}
	return plan, nil
}

func TeardownConnectionOnly(ctx context.Context, ipsec IPsecDriver, spec TransportLinkSpec) (ApplyPlan, error) {
	if ipsec == nil {
		return ApplyPlan{}, fmt.Errorf("ipsec driver is required")
	}
	plan := ApplyPlan{}
	plan.add("terminate_sa", spec.TransportID, string(spec.PeerZone))
	plan.add("unload_connection", spec.TransportID, string(spec.PeerZone))
	if err := ipsec.TerminateSA(ctx, spec.TransportID); err != nil {
		return plan, fmt.Errorf("terminate sa: %w", err)
	}
	if err := ipsec.UnloadConnection(ctx, spec.TransportID); err != nil {
		return plan, fmt.Errorf("unload connection: %w", err)
	}
	return plan, nil
}

func (d *StrongSwanDriver) LoadConnection(ctx context.Context, spec TransportLinkSpec) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	msg, err := d.buildLoadConnMessage(spec)
	if err != nil {
		return err
	}
	d.logVICIConfig("vici_load_conn", spec.TransportID, msg)
	_, err = d.VICI.Call(ctx, "load-conn", msg)
	return err
}

func (d *StrongSwanDriver) UnloadConnection(ctx context.Context, id string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if id == "" {
		return fmt.Errorf("connection id is required")
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	_, err := d.VICI.Call(ctx, "unload-conn", map[string]any{"name": id})
	// Idempotent: the connection may already be gone (e.g., unloaded during
	// prepare rotation or manually removed by an operator).
	if err != nil && strings.Contains(err.Error(), "not found") {
		return nil
	}
	return err
}

func (d *StrongSwanDriver) TerminateSA(ctx context.Context, id string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if id == "" {
		return fmt.Errorf("sa id is required")
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	_, err := d.VICI.Call(ctx, "terminate", map[string]any{"ike": id, "force": "yes"})
	// Terminating an already-gone SA is a no-op: the caller just wants the
	// SA gone before the next step (e.g. bounded break-before-make rotate).
	if err != nil && strings.Contains(err.Error(), "no matching SAs to terminate found") {
		return nil
	}
	return err
}

func (d *StrongSwanDriver) InitiateChild(ctx context.Context, child string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if child == "" {
		return fmt.Errorf("child sa name is required")
	}
	if d.InitiateAsync {
		return d.initiateChildAsync(ctx, child)
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	_, err := d.VICI.Call(ctx, "initiate", map[string]any{"child": child})
	return err
}

func (d *StrongSwanDriver) initiateChildAsync(ctx context.Context, child string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if d.markInitiateBusy(child) {
		return nil
	}
	client := d.VICI
	var closeFn func() error
	if d.InitiateClientFactory != nil {
		var err error
		client, closeFn, err = d.InitiateClientFactory()
		if err != nil {
			d.clearInitiateBusy(child)
			return err
		}
	}
	if client == nil {
		d.clearInitiateBusy(child)
		return fmt.Errorf("vici client is required")
	}
	go func() {
		defer d.clearInitiateBusy(child)
		callCtx, cancel := d.viciInitiateContext(ctx)
		defer cancel()
		if closeFn != nil {
			defer func() { _ = closeFn() }()
		}
		_, _ = client.Call(callCtx, "initiate", map[string]any{"child": child})
	}()
	return nil
}

func (d *StrongSwanDriver) markInitiateBusy(child string) bool {
	d.initiateMu.Lock()
	defer d.initiateMu.Unlock()
	if d.initiateBusy == nil {
		d.initiateBusy = make(map[string]struct{})
	}
	if _, ok := d.initiateBusy[child]; ok {
		return true
	}
	d.initiateBusy[child] = struct{}{}
	return false
}

func (d *StrongSwanDriver) clearInitiateBusy(child string) {
	d.initiateMu.Lock()
	defer d.initiateMu.Unlock()
	delete(d.initiateBusy, child)
}

func (d *StrongSwanDriver) ListSAs(ctx context.Context) ([]SAState, error) {
	if d.VICI == nil {
		return nil, fmt.Errorf("vici client is required")
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	events, err := d.VICI.CallStreaming(ctx, "list-sas", "list-sa", nil)
	if err != nil {
		return nil, err
	}
	states := make([]SAState, 0, len(events))
	for _, event := range events {
		states = append(states, parseSAStates(event)...)
	}
	return states, nil
}

func (d *StrongSwanDriver) SubscribeLifecycleEvents(ctx context.Context) (<-chan VICIEvent, func(), error) {
	client, ok := d.VICI.(VICIEventClient)
	if !ok {
		return nil, nil, fmt.Errorf("vici client does not support lifecycle events")
	}
	return client.SubscribeEvents(ctx, "child-updown", "ike-updown")
}

func parseVICIEvent(name string, raw map[string]any) VICIEvent {
	ev := VICIEvent{Name: name, Raw: raw}
	if raw == nil {
		return ev
	}
	ev.Connection = firstString(raw["ike"], raw["ike-name"], raw["conn"], raw["name"])
	ev.ChildSA = stripChildSAReqidSuffix(firstString(raw["child"], raw["child-name"], raw["child-sa"]))
	ev.Up = boolLike(raw["up"]) || strings.EqualFold(firstString(raw["state"]), "up") || strings.EqualFold(firstString(raw["child-state"]), "INSTALLED")
	ev.XFRMIfID = firstUint32(raw["if_id_out"], raw["if-id-out"], raw["if_id_in"], raw["if-id-in"])
	ev.ReqID = firstUint32(raw["reqid"], raw["req-id"])
	ev.LocalIdentity = firstString(raw["local_id"], raw["local-id"], raw["local"])
	ev.RemoteIdentity = firstString(raw["remote_id"], raw["remote-id"], raw["remote"])
	ev.LocalEndpoint = joinEndpoint(firstString(raw["local-host"], raw["local_host"]), firstString(raw["local-port"], raw["local_port"]))
	ev.RemoteEndpoint = joinEndpoint(firstString(raw["remote-host"], raw["remote_host"]), firstString(raw["remote-port"], raw["remote_port"]))
	return ev
}

func firstString(values ...any) string {
	for _, value := range values {
		if s := stringValue(value); s != "" {
			return s
		}
	}
	return ""
}

func boolLike(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "yes") || strings.EqualFold(v, "true") || v == "1"
	case []byte:
		return boolLike(string(v))
	default:
		return false
	}
}

func (d *StrongSwanDriver) LoadPrivateKey(ctx context.Context, id string, key []byte, algorithm string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if id == "" {
		return fmt.Errorf("private key id is required")
	}
	if len(key) == 0 {
		return fmt.Errorf("private key data is required")
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	pemBytes, err := PEMEncodePrivateKey(key)
	if err != nil {
		return err
	}
	resp, err := d.VICI.Call(ctx, "load-key", map[string]any{
		"type": KeyTypeForAlgorithm(algorithm),
		"data": string(pemBytes),
	})
	if err != nil {
		return err
	}
	keyID := stringValue(resp["id"])
	if keyID != "" {
		d.keyIDsMu.Lock()
		if d.keyIDs == nil {
			d.keyIDs = make(map[string]string)
		}
		d.keyIDs[id] = keyID
		d.keyIDsMu.Unlock()
	}
	return nil
}

func (d *StrongSwanDriver) UnloadPrivateKey(ctx context.Context, id string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if id == "" {
		return fmt.Errorf("private key id is required")
	}
	if d.KeyDir != "" {
		_ = os.Remove(filepath.Join(d.KeyDir, id+"-peer.pub.pem"))
	}
	d.keyIDsMu.Lock()
	keyID := d.keyIDs[id]
	delete(d.keyIDs, id)
	d.keyIDsMu.Unlock()
	if keyID == "" {
		return nil
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	_, err := d.VICI.Call(ctx, "unload-key", map[string]any{"id": keyID})
	return err
}

func (d *StrongSwanDriver) viciContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	timeout := defaultVICIOperationTimeout
	if d != nil && d.OperationTimeout > 0 {
		timeout = d.OperationTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func (d *StrongSwanDriver) viciInitiateContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	timeout := defaultVICIInitiateAsyncTimeout
	if d != nil && d.InitiateTimeout > 0 {
		timeout = d.InitiateTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func (d *StrongSwanDriver) logVICIConfig(event, connection string, msg map[string]any) {
	if d == nil || d.LogConfig == nil {
		return
	}
	sanitized := sanitizeVICIConfigForLog(msg)
	fields := map[string]any{
		"connection": connection,
		"command":    "load-conn",
		"config":     sanitized,
	}
	if data, err := json.Marshal(sanitized); err == nil {
		fields["config_json"] = string(data)
	}
	d.LogConfig(event, fields)
}

func sanitizeVICIConfigForLog(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			switch key {
			case "pubkeys", "privkey", "private_key", "data":
				out[key] = redactVICIConfigValue(item)
			default:
				out[key] = sanitizeVICIConfigForLog(item)
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, sanitizeVICIConfigForLog(item))
		}
		return out
	case []string:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, sanitizeVICIConfigForLog(item))
		}
		return out
	default:
		return v
	}
}

func redactVICIConfigValue(value any) any {
	switch v := value.(type) {
	case []string:
		if len(v) == 0 {
			return nil
		}
		return fmt.Sprintf("present:%d", len(v))
	case []any:
		if len(v) == 0 {
			return nil
		}
		return fmt.Sprintf("present:%d", len(v))
	case string:
		if v == "" {
			return ""
		}
		return "present"
	default:
		if v == nil {
			return nil
		}
		return "present"
	}
}

func (p *ApplyPlan) add(action, target, detail string) {
	p.Operations = append(p.Operations, ApplyOperation{Action: action, Target: target, Detail: detail})
}

func (d *DryRunDriver) LoadConnection(_ context.Context, spec TransportLinkSpec) error {
	d.Connections = append(d.Connections, spec)
	return nil
}

func (d *DryRunDriver) InitiateChild(_ context.Context, child string) error {
	d.Initiated = append(d.Initiated, child)
	return nil
}

func (d *DryRunDriver) UnloadConnection(_ context.Context, id string) error {
	d.Unloaded = append(d.Unloaded, id)
	return nil
}

func (d *DryRunDriver) TerminateSA(_ context.Context, id string) error {
	d.Terminated = append(d.Terminated, id)
	return nil
}

func (d *DryRunDriver) ListSAs(context.Context) ([]SAState, error) {
	return nil, nil
}

func (d *DryRunDriver) LoadPrivateKey(_ context.Context, id string, key []byte, algorithm string) error {
	d.PrivateKeys = append(d.PrivateKeys, DryRunPrivateKey{ID: id, Algorithm: algorithm, Len: len(key)})
	return nil
}

func (d *DryRunDriver) UnloadPrivateKey(_ context.Context, id string) error {
	d.UnloadedKeys = append(d.UnloadedKeys, id)
	return nil
}

func (d *DryRunDriver) EnsureNamespace(_ context.Context, spec NetNSSpec) error {
	d.Namespaces = append(d.Namespaces, spec.Normalized())
	return nil
}

func (d *DryRunDriver) EnsureInterface(_ context.Context, spec TransportLinkSpec) error {
	d.Interfaces = append(d.Interfaces, spec)
	return nil
}

func (d *DryRunDriver) DeleteInterface(_ context.Context, name string) error {
	d.DeletedIFs = append(d.DeletedIFs, name)
	return nil
}

func (d *DryRunDriver) AssignAddress(_ context.Context, spec TransportLinkSpec, address string) error {
	d.Addresses = append(d.Addresses, spec.InterfaceName+"="+address)
	return nil
}

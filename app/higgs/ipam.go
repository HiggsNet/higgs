package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/urfave/cli/v3"
)

func cmdIPAM() *cli.Command {
	return &cli.Command{
		Name:  "ipam",
		Usage: "IPAM pool and assignment management",
		Commands: []*cli.Command{
			{
				Name:  "pool",
				Usage: "IPAM pool management commands",
				Commands: []*cli.Command{
					{
						Name:      "create",
						Usage:     "Create or update an IPAM pool delegation",
						UsageText: "higgs ipam pool create [--direct] <zone> <prefix> --delegated-to <zone>",
						Description: "Delegate authority to assign prefixes from a pool to a sub-zone.\n" +
							"The prefix is canonicalized before storage.",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "delegated-to", Usage: "Zone that receives the pool delegation", Required: true},
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs ipam pool create <zone> <prefix> --delegated-to <zone>", 1)
							}
							return createIPAMPool(
								zone.ZonePath(cmd.Args().Get(0)),
								cmd.Args().Get(1),
								zone.ZonePath(cmd.String("delegated-to")),
								cmd.Bool("direct"),
							)
						},
					},
					{
						Name:        "revoke",
						Usage:       "Revoke an IPAM pool delegation",
						UsageText:   "higgs ipam pool revoke [--direct] <zone> <prefix>",
						Description: "Withdraw a previously created IPAM pool delegation by publishing a higher-version record with active=false.",
						Flags: []cli.Flag{
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs ipam revoke pool <zone> <prefix>", 1)
							}
							return revokeIPAMPool(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Bool("direct"))
						},
					},
				},
			},
			{
				Name:      "assign",
				Usage:     "Assign a prefix to a zone",
				UsageText: "higgs ipam assign [--direct] <zone> <prefix> --to <zone> [--shared] [--tag <tag>]",
				Description: "Assign a CIDR prefix to a zone so it may announce routes within it.\n" +
					"The prefix is canonicalized before storage.\n" +
					"--shared marks this as an anycast assignment, allowing multiple zones to hold the same prefix.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "to", Usage: "Zone that receives the assignment", Required: true},
					&cli.BoolFlag{Name: "shared", Usage: "Mark as anycast/shared assignment (allows prefix overlap with other shared assignments)", Value: false},
					&cli.StringFlag{Name: "tag", Usage: "Stable selector for a shared assignment group"},
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: higgs ipam assign <zone> <prefix> --to <zone> [--shared] [--tag <tag>]", 1)
					}
					return assignIPAM(
						zone.ZonePath(cmd.Args().Get(0)),
						cmd.Args().Get(1),
						zone.ZonePath(cmd.String("to")),
						cmd.Bool("shared"),
						cmd.String("tag"),
						cmd.Bool("direct"),
					)
				},
			},
			{
				Name:      "revoke",
				Usage:     "Revoke an IPAM record",
				UsageText: "higgs ipam revoke assignment|pool <zone> <prefix>",
				Commands: []*cli.Command{
					{
						Name:        "assignment",
						Usage:       "Revoke an IPAM assignment",
						UsageText:   "higgs ipam revoke assignment [--direct] [--to <zone>] <zone> <prefix>",
						Description: "Withdraw a previously created IPAM assignment by publishing a higher-version record with active=false.",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "to", Usage: "Assigned member Zone; required when a shared prefix has multiple members"},
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs ipam revoke assignment [--to <zone>] <zone> <prefix>", 1)
							}
							return revokeIPAMAssignmentTo(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), zone.ZonePath(cmd.String("to")), cmd.Bool("direct"))
						},
					},
					{
						Name:        "pool",
						Usage:       "Revoke an IPAM pool delegation",
						UsageText:   "higgs ipam revoke pool [--direct] <zone> <prefix>",
						Description: "Withdraw a previously created IPAM pool delegation by publishing a higher-version record with active=false.",
						Flags: []cli.Flag{
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs ipam revoke pool <zone> <prefix>", 1)
							}
							return revokeIPAMPool(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Bool("direct"))
						},
					},
				},
			},
			{
				Name:      "assigned",
				Usage:     "List authorized IPAM assignments",
				UsageText: "higgs ipam assigned [--zone <zone>]",
				Description: "Print authorized IPAM assignments as JSON.\n" +
					"If --zone is given, only assignments whose source or assigned_to matches are shown.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "zone", Usage: "Filter by source or assigned zone"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs ipam assigned [--zone <zone>]", 1)
					}
					return listIPAMAssignments(zone.ZonePath(cmd.String("zone")))
				},
			},
			{
				Name:        "mine",
				Usage:       "Show IPAM prefixes and pools for the local managed zone",
				UsageText:   "higgs ipam mine",
				Description: "Print the local managed zone's authorized IPAM assignments and owned pools as JSON.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs ipam mine", 1)
					}
					return showLocalIPAM()
				},
			},
			{
				Name:      "get",
				Usage:     "Explain IPAM ownership and assignment for an address or prefix",
				UsageText: "higgs ipam get <addr-or-prefix> [--json]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "json", Usage: "Print structured JSON output", Value: false},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs ipam get <addr-or-prefix> [--json]", 1)
					}
					return getIPAM(cmd.Args().First(), cmd.Bool("json"))
				},
			},
		},
	}
}

func createIPAMPool(path zone.ZonePath, prefix string, delegatedTo zone.ZonePath, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return createIPAMPoolWithRuntime(rt, path, prefix, delegatedTo)
}

func createIPAMPoolWithRuntime(rt *Runtime, path zone.ZonePath, prefix string, delegatedTo zone.ZonePath) error {
	canonical, key, value, err := prepareIPAMPoolRecord(prefix, delegatedTo, true)
	if err != nil {
		return err
	}
	if err := dryRunIPAMRecord(rt, path, key, value, routing.RecordTypeIPAMPool, canonical, "ipam_pool_owner_mismatch", "ipam_pool_overlap"); err != nil {
		return err
	}
	return submitIPAMRecord(rt, path, key, value, canonical, routing.RecordTypeIPAMPool, true, "created")
}

func assignIPAM(path zone.ZonePath, prefix string, assignedTo zone.ZonePath, shared bool, tag string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return assignIPAMWithRuntimeTag(rt, path, prefix, assignedTo, shared, tag)
}

func assignIPAMWithRuntime(rt *Runtime, path zone.ZonePath, prefix string, assignedTo zone.ZonePath, shared bool) error {
	return assignIPAMWithRuntimeTag(rt, path, prefix, assignedTo, shared, "")
}

func assignIPAMWithRuntimeTag(rt *Runtime, path zone.ZonePath, prefix string, assignedTo zone.ZonePath, shared bool, tag string) error {
	canonical, key, value, err := prepareIPAMAssignmentRecordTag(prefix, assignedTo, true, shared, tag)
	if err != nil {
		return err
	}
	if err := dryRunIPAMRecord(rt, path, key, value, routing.RecordTypeIPAMAssignment, canonical, "ipam_assignment_pool_mismatch", "ipam_assignment_overlap"); err != nil {
		return err
	}
	return submitIPAMRecord(rt, path, key, value, canonical, routing.RecordTypeIPAMAssignment, true, "assigned")
}

func revokeIPAMPool(path zone.ZonePath, prefix string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return revokeIPAMPoolWithRuntime(rt, path, prefix)
}

func revokeIPAMPoolWithRuntime(rt *Runtime, path zone.ZonePath, prefix string) error {
	canonical, key, delegatedTo, err := currentIPAMPoolInfo(rt, path, prefix)
	if err != nil {
		return err
	}
	value, err := marshalIPAMPoolRecord(canonical, delegatedTo, false)
	if err != nil {
		return err
	}
	return submitIPAMRecord(rt, path, key, value, canonical, routing.RecordTypeIPAMPool, false, "revoked")
}

func revokeIPAMAssignment(path zone.ZonePath, prefix string, direct bool) error {
	return revokeIPAMAssignmentTo(path, prefix, "", direct)
}

func revokeIPAMAssignmentTo(path zone.ZonePath, prefix string, assignedTo zone.ZonePath, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return revokeIPAMAssignmentWithRuntimeTo(rt, path, prefix, assignedTo)
}

func revokeIPAMAssignmentWithRuntime(rt *Runtime, path zone.ZonePath, prefix string) error {
	return revokeIPAMAssignmentWithRuntimeTo(rt, path, prefix, "")
}

func revokeIPAMAssignmentWithRuntimeTo(rt *Runtime, path zone.ZonePath, prefix string, target zone.ZonePath) error {
	canonical, key, assignedTo, shared, tag, err := currentIPAMAssignmentInfoFor(rt, path, prefix, target)
	if err != nil {
		return err
	}
	value, err := marshalIPAMAssignmentRecordTag(canonical, assignedTo, false, shared, tag)
	if err != nil {
		return err
	}
	return submitIPAMRecord(rt, path, key, value, canonical, routing.RecordTypeIPAMAssignment, false, "revoked")
}

func prepareIPAMPoolRecord(prefix string, delegatedTo zone.ZonePath, active bool) (canonical, key string, value []byte, err error) {
	canonical, err = routing.CanonicalizePrefix(prefix)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	key, err = routing.NormalizeIPAMPoolKey(prefix)
	if err != nil {
		return "", "", nil, fmt.Errorf("normalize pool key for %q: %w", prefix, err)
	}
	value, err = marshalIPAMPoolRecord(canonical, delegatedTo, active)
	if err != nil {
		return "", "", nil, err
	}
	return canonical, key, value, nil
}

func prepareIPAMAssignmentRecord(prefix string, assignedTo zone.ZonePath, active bool, shared bool) (canonical, key string, value []byte, err error) {
	return prepareIPAMAssignmentRecordTag(prefix, assignedTo, active, shared, "")
}

func prepareIPAMAssignmentRecordTag(prefix string, assignedTo zone.ZonePath, active bool, shared bool, tag string) (canonical, key string, value []byte, err error) {
	canonical, err = routing.CanonicalizePrefix(prefix)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	key, err = routing.NormalizeIPAMAssignmentKey(prefix)
	if err != nil {
		return "", "", nil, fmt.Errorf("normalize assignment key for %q: %w", prefix, err)
	}
	if shared {
		key += "#" + strings.TrimSuffix(assignedTo.String(), ".")
	}
	value, err = marshalIPAMAssignmentRecordTag(canonical, assignedTo, active, shared, tag)
	if err != nil {
		return "", "", nil, err
	}
	return canonical, key, value, nil
}

func marshalIPAMPoolRecord(canonical string, delegatedTo zone.ZonePath, active bool) ([]byte, error) {
	record := routing.IPAMPoolRecord{Version: 1, Prefix: canonical, DelegatedTo: delegatedTo, Active: active}
	value, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal ipam pool record: %w", err)
	}
	return value, nil
}

func marshalIPAMAssignmentRecord(canonical string, assignedTo zone.ZonePath, active bool, shared bool) ([]byte, error) {
	return marshalIPAMAssignmentRecordTag(canonical, assignedTo, active, shared, "")
}

func marshalIPAMAssignmentRecordTag(canonical string, assignedTo zone.ZonePath, active bool, shared bool, tag string) ([]byte, error) {
	record := routing.IPAMAssignmentRecord{Version: 1, Prefix: canonical, AssignedTo: assignedTo, Active: active, Shared: shared, Tag: tag}
	if err := record.Validate(""); err != nil {
		return nil, err
	}
	value, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal ipam assignment record: %w", err)
	}
	return value, nil
}

func currentIPAMPoolInfo(rt *Runtime, path zone.ZonePath, prefix string) (canonical, key string, delegatedTo zone.ZonePath, err error) {
	canonical, err = routing.CanonicalizePrefix(prefix)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	key, err = routing.NormalizeIPAMPoolKey(prefix)
	if err != nil {
		return "", "", "", fmt.Errorf("normalize pool key for %q: %w", prefix, err)
	}
	state, err := rt.LoadState()
	if err != nil {
		return "", "", "", err
	}
	zs := state.Network.Zones[path]
	if zs == nil {
		return "", "", "", fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	current := zs.Records[key]
	if current == nil {
		return "", "", "", fmt.Errorf("no active ipam.pool for %s in %s", canonical, path)
	}
	pool, err := routing.ParseIPAMPoolRecord(current)
	if err != nil {
		return "", "", "", fmt.Errorf("current pool record for %s is invalid: %w", canonical, err)
	}
	if !pool.Active {
		return "", "", "", fmt.Errorf("pool %s in %s is already revoked", canonical, path)
	}
	return canonical, key, pool.DelegatedTo, nil
}

func currentIPAMAssignmentInfo(rt *Runtime, path zone.ZonePath, prefix string) (canonical, key string, assignedTo zone.ZonePath, shared bool, err error) {
	canonical, key, assignedTo, shared, _, err = currentIPAMAssignmentInfoFor(rt, path, prefix, "")
	return
}

func currentIPAMAssignmentInfoFor(rt *Runtime, path zone.ZonePath, prefix string, target zone.ZonePath) (canonical, key string, assignedTo zone.ZonePath, shared bool, tag string, err error) {
	canonical, err = routing.CanonicalizePrefix(prefix)
	if err != nil {
		return "", "", "", false, "", fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	baseKey, err := routing.NormalizeIPAMAssignmentKey(prefix)
	if err != nil {
		return "", "", "", false, "", fmt.Errorf("normalize assignment key for %q: %w", prefix, err)
	}
	state, err := rt.LoadState()
	if err != nil {
		return "", "", "", false, "", err
	}
	zs := state.Network.Zones[path]
	if zs == nil {
		return "", "", "", false, "", fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	type match struct {
		key    string
		record *routing.IPAMAssignmentRecord
	}
	var matches []match
	foundRevoked := false
	for candidateKey, current := range zs.Records {
		if candidateKey != baseKey && !strings.HasPrefix(candidateKey, baseKey+"#") {
			continue
		}
		assignment, parseErr := routing.ParseIPAMAssignmentRecord(current)
		if parseErr != nil || assignment.Prefix != canonical {
			continue
		}
		if target.Valid() && assignment.AssignedTo != target {
			continue
		}
		if !assignment.Active {
			foundRevoked = true
			continue
		}
		matches = append(matches, match{key: candidateKey, record: assignment})
	}
	if len(matches) == 0 {
		if foundRevoked {
			return "", "", "", false, "", fmt.Errorf("assignment %s in %s is already revoked", canonical, path)
		}
		return "", "", "", false, "", fmt.Errorf("no active ipam.assignment for %s in %s", canonical, path)
	}
	if len(matches) > 1 {
		return "", "", "", false, "", fmt.Errorf("multiple shared assignments exist for %s in %s; specify --to", canonical, path)
	}
	assignment := matches[0].record
	return canonical, matches[0].key, assignment.AssignedTo, assignment.Shared, assignment.Tag, nil
}

func submitIPAMRecord(rt *Runtime, path zone.ZonePath, key string, value []byte, canonical string, recordType string, active bool, op string) error {
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	if err := checkIPAMWriteCapability(state, path, key); err != nil {
		return err
	}
	if !active {
		if err := checkIPAMRevokeAllowed(state, path, key, canonical, recordType); err != nil {
			return err
		}
	}

	if version, ok, err := putRecordViaControl(rt, path, key, value, recordType); ok {
		if err != nil {
			return err
		}
		fmt.Printf("%s %s/%s version %d via daemon\n", op, path, key, version)
		return nil
	}
	if !rt.DisableControl {
		logControlFallback("ipam_submit")
	}
	return putIPAMRecordDirect(rt, path, key, value, recordType, state)
}

func putIPAMRecordDirect(rt *Runtime, path zone.ZonePath, key string, value []byte, recordType string, state *stateFile) error {
	if state == nil {
		var err error
		state, err = rt.LoadState()
		if err != nil {
			return err
		}
	}
	record, err := buildSignedRecordAt(state, path, key, value, recordType, rt.Now())
	if err != nil {
		return err
	}
	if err := state.Network.Put(record); err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	fmt.Printf("put %s/%s version %d\n", path, key, record.Version)
	return nil
}

func dryRunIPAMRecord(rt *Runtime, path zone.ZonePath, key string, value []byte, recordType, canonical string, rejectCodes ...string) error {
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	if err := checkIPAMWriteCapability(state, path, key); err != nil {
		return err
	}
	ns := cloneNetworkStateForIPAMDryRun(state.Network)
	zs := ns.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	zs.Records[key] = &zone.Record{Zone: path, Key: key, Type: recordType, Value: value}
	ars, err := routing.BuildAuthorizedRouteSet(ns, rt.Now())
	if err != nil {
		return err
	}
	reject := make(map[string]bool, len(rejectCodes))
	for _, code := range rejectCodes {
		reject[code] = true
	}
	for _, authErr := range ars.Errors {
		if authErr.Zone != path || authErr.Prefix.String() != canonical || !reject[authErr.Code] {
			continue
		}
		return fmt.Errorf("%s: %s", authErr.Code, authErr.Detail)
	}
	return nil
}

func cloneNetworkStateForIPAMDryRun(ns *zone.NetworkState) *zone.NetworkState {
	if ns == nil {
		return zone.NewNetworkState()
	}
	clone := &zone.NetworkState{
		Zones:          make(map[zone.ZonePath]*zone.ZoneState, len(ns.Zones)),
		GlobalRoot:     ns.GlobalRoot,
		RecordVerifier: ns.RecordVerifier,
		RecordHasher:   ns.RecordHasher,
	}
	for path, zs := range ns.Zones {
		if zs == nil {
			continue
		}
		czs := *zs
		czs.Records = make(map[string]*zone.Record, len(zs.Records))
		for key, rec := range zs.Records {
			czs.Records[key] = rec
		}
		clone.Zones[path] = &czs
	}
	return clone
}

func checkIPAMWriteCapability(state *stateFile, path zone.ZonePath, key string) error {
	if state == nil || state.Network == nil {
		return fmt.Errorf("state is nil")
	}
	zs := state.Network.Zones[path]
	if zs == nil || zs.Authority == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	for _, authorizedKey := range zs.Authority.Keys {
		for _, capability := range authorizedKey.Capabilities {
			if capability.KeyPrefix != "" && !strings.HasPrefix(key, capability.KeyPrefix) {
				continue
			}
			for _, permission := range capability.Permissions {
				if permission == zone.PermAllocateIP {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("zone %s authority lacks allocate-ip capability for key %s", path, key)
}

func checkIPAMRevokeAllowed(state *stateFile, path zone.ZonePath, key, canonical, recordType string) error {
	if state == nil || state.Network == nil {
		return fmt.Errorf("state is nil")
	}
	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	current := zs.Records[key]
	if current == nil {
		return fmt.Errorf("no active %s for %s in %s", recordType, canonical, path)
	}
	switch recordType {
	case routing.RecordTypeIPAMPool:
		pool, err := routing.ParseIPAMPoolRecord(current)
		if err != nil {
			return fmt.Errorf("current pool record for %s is invalid: %w", canonical, err)
		}
		if !pool.Active {
			return fmt.Errorf("pool %s in %s is already revoked", canonical, path)
		}
	case routing.RecordTypeIPAMAssignment:
		assignment, err := routing.ParseIPAMAssignmentRecord(current)
		if err != nil {
			return fmt.Errorf("current assignment record for %s is invalid: %w", canonical, err)
		}
		if !assignment.Active {
			return fmt.Errorf("assignment %s in %s is already revoked", canonical, path)
		}
	default:
		return fmt.Errorf("unsupported ipam record type %q", recordType)
	}
	return nil
}

func listIPAMAssignments(filterZone zone.ZonePath) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return listIPAMAssignmentsWithRuntime(rt, filterZone)
}

func listIPAMAssignmentsWithRuntime(rt *Runtime, filterZone zone.ZonePath) error {
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		return err
	}

	type assignmentRow struct {
		Prefix     string `json:"prefix"`
		Source     string `json:"source"`
		AssignedTo string `json:"assigned_to"`
		Shared     bool   `json:"shared,omitempty"`
		Tag        string `json:"tag,omitempty"`
	}
	rows := make([]assignmentRow, 0, len(ars.AllAssignments))
	filter := string(filterZone)
	for _, entry := range ars.AllAssignments {
		if filter != "" && string(entry.Source) != filter && string(entry.AssignedTo) != filter {
			continue
		}
		rows = append(rows, assignmentRow{
			Prefix:     entry.Prefix.String(),
			Source:     string(entry.Source),
			AssignedTo: string(entry.AssignedTo),
			Shared:     entry.Shared,
			Tag:        entry.Tag,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		pi, _ := netip.ParsePrefix(rows[i].Prefix)
		pj, _ := netip.ParsePrefix(rows[j].Prefix)
		if cmp := strings.Compare(pi.Addr().String(), pj.Addr().String()); cmp != 0 {
			return cmp < 0
		}
		return pi.Bits() < pj.Bits()
	})

	out, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func showLocalIPAM() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return showLocalIPAMWithRuntime(rt)
}

func showLocalIPAMWithRuntime(rt *Runtime) error {
	report, err := buildIPAMMineReport(rt)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

type ipamMineReport struct {
	ManagedZone string                  `json:"managed_zone"`
	Assignments []ipamMineAssignmentRow `json:"assignments"`
	Pools       []ipamMinePoolRow       `json:"pools"`
}

type ipamMineAssignmentRow struct {
	Prefix string `json:"prefix"`
	Source string `json:"source"`
	Shared bool   `json:"shared,omitempty"`
	Tag    string `json:"tag,omitempty"`
}

type ipamMinePoolRow struct {
	Prefix      string   `json:"prefix"`
	Source      string   `json:"source"`
	DelegatedTo string   `json:"delegated_to"`
	Relation    []string `json:"relation"`
}

func buildIPAMMineReport(rt *Runtime) (*ipamMineReport, error) {
	state, err := rt.LoadState()
	if err != nil {
		return nil, err
	}
	if state.ManagedZone == "" || !state.ManagedZone.Valid() {
		return nil, fmt.Errorf("managed_zone is not set")
	}
	if state.Network == nil {
		return nil, fmt.Errorf("network state is nil")
	}
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		return nil, err
	}

	managed := state.ManagedZone
	report := &ipamMineReport{
		ManagedZone: string(managed),
		Assignments: []ipamMineAssignmentRow{},
		Pools:       []ipamMinePoolRow{},
	}
	for _, entry := range ars.AllAssignments {
		if entry.AssignedTo != managed {
			continue
		}
		report.Assignments = append(report.Assignments, ipamMineAssignmentRow{
			Prefix: entry.Prefix.String(),
			Source: string(entry.Source),
			Shared: entry.Shared,
			Tag:    entry.Tag,
		})
	}
	for _, entry := range ars.AllPools {
		relation := localIPAMPoolRelation(entry, managed)
		if len(relation) == 0 {
			continue
		}
		report.Pools = append(report.Pools, ipamMinePoolRow{
			Prefix:      entry.Prefix.String(),
			Source:      string(entry.Source),
			DelegatedTo: string(entry.DelegatedTo),
			Relation:    relation,
		})
	}
	sort.Slice(report.Assignments, func(i, j int) bool {
		return comparePrefixStrings(report.Assignments[i].Prefix, report.Assignments[j].Prefix) < 0
	})
	sort.Slice(report.Pools, func(i, j int) bool {
		if cmp := comparePrefixStrings(report.Pools[i].Prefix, report.Pools[j].Prefix); cmp != 0 {
			return cmp < 0
		}
		if report.Pools[i].Source != report.Pools[j].Source {
			return report.Pools[i].Source < report.Pools[j].Source
		}
		return report.Pools[i].DelegatedTo < report.Pools[j].DelegatedTo
	})
	return report, nil
}

func localIPAMPoolRelation(entry *routing.PoolEntry, managed zone.ZonePath) []string {
	if entry == nil {
		return nil
	}
	var relation []string
	if entry.Source == managed {
		relation = append(relation, "published_by_managed_zone")
	}
	if entry.DelegatedTo == managed {
		relation = append(relation, "delegated_to_managed_zone")
	}
	return relation
}

func getIPAM(query string, jsonOut bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	report, err := buildIPAMGetReport(rt, query)
	if err != nil {
		return err
	}
	if jsonOut {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}
	printIPAMGetReport(report)
	return nil
}

type ipamGetReport struct {
	Query       string                 `json:"query"`
	PoolChain   []ipamGetPoolRow       `json:"pool_chain"`
	BestPool    *ipamGetPoolRow        `json:"best_pool"`
	Assignments []ipamGetAssignmentRow `json:"assignments"`
	AssignedTo  *string                `json:"assigned_to"`
	Routes      []ipamGetRouteRow      `json:"routes"`
	Diagnostics []ipamGetDiagnosticRow `json:"diagnostics"`
}

type ipamGetPoolRow struct {
	Prefix      string `json:"prefix"`
	Source      string `json:"source"`
	DelegatedTo string `json:"delegated_to"`
	Relation    string `json:"relation,omitempty"`
}

type ipamGetAssignmentRow struct {
	Prefix     string `json:"prefix"`
	Source     string `json:"source"`
	AssignedTo string `json:"assigned_to"`
	Shared     bool   `json:"shared,omitempty"`
	Tag        string `json:"tag,omitempty"`
}

type ipamGetRouteRow struct {
	Prefix string `json:"prefix"`
	Source string `json:"source"`
}

type ipamGetDiagnosticRow struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func buildIPAMGetReport(rt *Runtime, query string) (*ipamGetReport, error) {
	state, err := rt.LoadState()
	if err != nil {
		return nil, err
	}
	prefix, err := normalizeIPAMGetQuery(query)
	if err != nil {
		return nil, err
	}
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		return nil, err
	}
	report := &ipamGetReport{
		Query:       prefix.String(),
		PoolChain:   []ipamGetPoolRow{},
		Assignments: []ipamGetAssignmentRow{},
		Routes:      []ipamGetRouteRow{},
		Diagnostics: []ipamGetDiagnosticRow{},
	}
	for _, pool := range ars.AllPools {
		if !containsIPAMQuery(pool.Prefix, prefix) {
			continue
		}
		report.PoolChain = append(report.PoolChain, ipamGetPoolRow{
			Prefix:      pool.Prefix.String(),
			Source:      string(pool.Source),
			DelegatedTo: string(pool.DelegatedTo),
			Relation:    ipamGetPoolRelation(pool),
		})
	}
	sort.Slice(report.PoolChain, func(i, j int) bool {
		pi := netip.MustParsePrefix(report.PoolChain[i].Prefix)
		pj := netip.MustParsePrefix(report.PoolChain[j].Prefix)
		if pi.Bits() != pj.Bits() {
			return pi.Bits() < pj.Bits()
		}
		if report.PoolChain[i].Source != report.PoolChain[j].Source {
			return report.PoolChain[i].Source < report.PoolChain[j].Source
		}
		return report.PoolChain[i].DelegatedTo < report.PoolChain[j].DelegatedTo
	})
	if len(report.PoolChain) > 0 {
		best := report.PoolChain[len(report.PoolChain)-1]
		report.BestPool = &best
	}
	for _, assignment := range ars.AllAssignments {
		if !prefixesRelatedForIPAMQuery(prefix, assignment.Prefix) {
			continue
		}
		report.Assignments = append(report.Assignments, ipamGetAssignmentRow{
			Prefix:     assignment.Prefix.String(),
			Source:     string(assignment.Source),
			AssignedTo: string(assignment.AssignedTo),
			Shared:     assignment.Shared,
			Tag:        assignment.Tag,
		})
	}
	sort.Slice(report.Assignments, func(i, j int) bool {
		return comparePrefixStrings(report.Assignments[i].Prefix, report.Assignments[j].Prefix) < 0
	})
	if len(report.Assignments) == 1 && !report.Assignments[0].Shared {
		assignedTo := report.Assignments[0].AssignedTo
		report.AssignedTo = &assignedTo
	}
	for source, routes := range ars.Announced {
		for p := range routes {
			if !prefixesRelatedForIPAMQuery(prefix, p) {
				continue
			}
			report.Routes = append(report.Routes, ipamGetRouteRow{Prefix: p.String(), Source: string(source)})
		}
	}
	sort.Slice(report.Routes, func(i, j int) bool {
		if cmp := comparePrefixStrings(report.Routes[i].Prefix, report.Routes[j].Prefix); cmp != 0 {
			return cmp < 0
		}
		return report.Routes[i].Source < report.Routes[j].Source
	})
	for _, authErr := range ars.Errors {
		if !strings.HasPrefix(authErr.Code, "ipam_") {
			continue
		}
		if authErr.Prefix.IsValid() && !prefixesRelatedForIPAMQuery(prefix, authErr.Prefix) {
			continue
		}
		report.Diagnostics = append(report.Diagnostics, ipamGetDiagnosticRow{Code: authErr.Code, Detail: authErr.Detail})
	}
	if report.BestPool == nil {
		report.Diagnostics = append(report.Diagnostics, ipamGetDiagnosticRow{Code: "ipam_no_pool", Detail: fmt.Sprintf("no valid pool covers %s", prefix)})
	} else if len(report.Assignments) == 0 {
		report.Diagnostics = append(report.Diagnostics, ipamGetDiagnosticRow{Code: "ipam_unassigned", Detail: fmt.Sprintf("no assignment covers %s", prefix)})
	}
	return report, nil
}

func normalizeIPAMGetQuery(query string) (netip.Prefix, error) {
	if strings.Contains(query, "/") {
		p, err := netip.ParsePrefix(query)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid prefix %q: %w", query, err)
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(query)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address or prefix %q: %w", query, err)
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	}
	return netip.PrefixFrom(addr, 128), nil
}

func ipamGetPoolRelation(pool *routing.PoolEntry) string {
	if pool.Source == pool.DelegatedTo {
		return "owner"
	}
	return "delegated"
}

func containsIPAMQuery(pool, query netip.Prefix) bool {
	return containsPrefixLocal(pool, query)
}

func prefixesRelatedForIPAMQuery(query, candidate netip.Prefix) bool {
	return containsPrefixLocal(query, candidate) || containsPrefixLocal(candidate, query)
}

func containsPrefixLocal(outer, inner netip.Prefix) bool {
	if outer.Bits() > inner.Bits() {
		return false
	}
	return outer.Contains(inner.Masked().Addr())
}

func printIPAMGetReport(report *ipamGetReport) {
	fmt.Printf("query: %s\n\n", report.Query)
	printIPAMGetPools(report)
	printIPAMGetAssignments(report)
	printIPAMGetRoutes(report)
	printIPAMGetDiagnostics(report)
}

func printIPAMGetPools(report *ipamGetReport) {
	if len(report.PoolChain) == 0 {
		fmt.Println("pool chain: none")
		fmt.Println("best pool: none")
		return
	}
	fmt.Println("pool chain:")
	for _, pool := range report.PoolChain {
		fmt.Printf("  %s  source=%s  delegated_to=%s  relation=%s\n", pool.Prefix, pool.Source, pool.DelegatedTo, pool.Relation)
	}
	fmt.Println()
	fmt.Println("best pool:")
	fmt.Printf("  %s  source=%s  delegated_to=%s\n", report.BestPool.Prefix, report.BestPool.Source, report.BestPool.DelegatedTo)
}

func printIPAMGetAssignments(report *ipamGetReport) {
	fmt.Println()
	if len(report.Assignments) == 0 {
		fmt.Println("assignment: none")
		return
	}
	fmt.Println("assignment:")
	for _, assignment := range report.Assignments {
		shared := ""
		if assignment.Shared {
			shared = "  shared=true"
		}
		fmt.Printf("  %s  source=%s  assigned_to=%s%s\n", assignment.Prefix, assignment.Source, assignment.AssignedTo, shared)
	}
}

func printIPAMGetRoutes(report *ipamGetReport) {
	if len(report.Routes) == 0 {
		fmt.Println("routes: none")
		return
	}
	fmt.Println("routes:")
	for _, route := range report.Routes {
		fmt.Printf("  %s  source=%s\n", route.Prefix, route.Source)
	}
}

func printIPAMGetDiagnostics(report *ipamGetReport) {
	fmt.Println()
	if len(report.Diagnostics) == 0 {
		fmt.Println("diagnostics: none")
		return
	}
	fmt.Println("diagnostics:")
	for _, diag := range report.Diagnostics {
		fmt.Printf("  %s  %s\n", diag.Code, diag.Detail)
	}
}

func comparePrefixStrings(a, b string) int {
	pa, errA := netip.ParsePrefix(a)
	pb, errB := netip.ParsePrefix(b)
	if errA != nil || errB != nil {
		return strings.Compare(a, b)
	}
	if cmp := strings.Compare(pa.Addr().String(), pb.Addr().String()); cmp != 0 {
		return cmp
	}
	if pa.Bits() < pb.Bits() {
		return -1
	}
	if pa.Bits() > pb.Bits() {
		return 1
	}
	return 0
}

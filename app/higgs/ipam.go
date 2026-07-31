package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
	"github.com/urfave/cli/v3"
)

type ipamMutationRequest struct {
	Operation string        `json:"operation"`
	Zone      zone.ZonePath `json:"zone"`
	Prefix    string        `json:"prefix"`
	Target    zone.ZonePath `json:"target,omitempty"`
	Shared    bool          `json:"shared,omitempty"`
	Tag       string        `json:"tag,omitempty"`
	DryRun    bool          `json:"dry_run,omitempty"`
}

const (
	ipamOperationPoolCreate       = "pool_create"
	ipamOperationPoolRevoke       = "pool_revoke"
	ipamOperationAssignmentCreate = "assignment_create"
	ipamOperationAssignmentRevoke = "assignment_revoke"
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
						UsageText: "higgs route ipam pool create [--direct] <zone> <prefix> --delegated-to <zone>",
						Description: "Delegate authority to assign prefixes from a pool to a sub-zone.\n" +
							"The prefix is canonicalized before storage.",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "delegated-to", Usage: "Zone that receives the pool delegation", Required: true},
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs route ipam pool create <zone> <prefix> --delegated-to <zone>", 1)
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
						UsageText:   "higgs route ipam pool revoke [--direct] <zone> <prefix>",
						Description: "Withdraw a previously created IPAM pool delegation by publishing a higher-version record with active=false.",
						Flags: []cli.Flag{
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs route ipam revoke pool <zone> <prefix>", 1)
							}
							return revokeIPAMPool(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Bool("direct"))
						},
					},
				},
			},
			{
				Name:      "assign",
				Usage:     "Assign a prefix to a zone",
				UsageText: "higgs route ipam assign [--direct] <zone> <prefix> --to <zone> [--shared] [--tag <tag>]",
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
						return cli.Exit("usage: higgs route ipam assign <zone> <prefix> --to <zone> [--shared] [--tag <tag>]", 1)
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
				UsageText: "higgs route ipam revoke assignment|pool <zone> <prefix>",
				Commands: []*cli.Command{
					{
						Name:        "assignment",
						Usage:       "Revoke an IPAM assignment",
						UsageText:   "higgs route ipam revoke assignment [--direct] [--to <zone>] <zone> <prefix>",
						Description: "Withdraw a previously created IPAM assignment by publishing a higher-version record with active=false.",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "to", Usage: "Assigned member Zone; required when a shared prefix has multiple members"},
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs route ipam revoke assignment [--to <zone>] <zone> <prefix>", 1)
							}
							return revokeIPAMAssignmentTo(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), zone.ZonePath(cmd.String("to")), cmd.Bool("direct"))
						},
					},
					{
						Name:        "pool",
						Usage:       "Revoke an IPAM pool delegation",
						UsageText:   "higgs route ipam revoke pool [--direct] <zone> <prefix>",
						Description: "Withdraw a previously created IPAM pool delegation by publishing a higher-version record with active=false.",
						Flags: []cli.Flag{
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs route ipam revoke pool <zone> <prefix>", 1)
							}
							return revokeIPAMPool(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Bool("direct"))
						},
					},
				},
			},
			{
				Name:      "assigned",
				Usage:     "List authorized IPAM assignments",
				UsageText: "higgs route ipam assigned [--zone <zone>]",
				Description: "Print authorized IPAM assignments as a table.\n" +
					"If --zone is given, only assignments whose source or assigned_to matches are shown.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "zone", Usage: "Filter by source or assigned zone"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs route ipam assigned [--zone <zone>]", 1)
					}
					return listIPAMAssignments(zone.ZonePath(cmd.String("zone")))
				},
			},
			{
				Name:        "mine",
				Usage:       "Show IPAM prefixes and pools for the local managed zone",
				UsageText:   "higgs route ipam mine [--json]",
				Description: "Print the local managed zone's authorized IPAM assignments and owned pools as tables.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "json", Usage: "Print structured JSON output", Value: false},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs route ipam mine [--json]", 1)
					}
					return showLocalIPAM(cmd.Bool("json"))
				},
			},
			{
				Name:      "get",
				Usage:     "Explain IPAM ownership and assignment for an address or prefix",
				UsageText: "higgs route ipam get <addr-or-prefix> [--json]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "json", Usage: "Print structured JSON output", Value: false},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs route ipam get <addr-or-prefix> [--json]", 1)
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
	return submitIPAMMutation(rt, ipamMutationRequest{
		Operation: ipamOperationPoolCreate,
		Zone:      path, Prefix: prefix, Target: delegatedTo,
	}, "created")
}

func assignIPAM(path zone.ZonePath, prefix string, assignedTo zone.ZonePath, shared bool, tag string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return assignIPAMWithRuntimeTag(rt, path, prefix, assignedTo, shared, tag)
}

func assignIPAMWithRuntimeTag(rt *Runtime, path zone.ZonePath, prefix string, assignedTo zone.ZonePath, shared bool, tag string) error {
	return submitIPAMMutation(rt, ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      path, Prefix: prefix, Target: assignedTo, Shared: shared, Tag: tag,
	}, "assigned")
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
	return submitIPAMMutation(rt, ipamMutationRequest{
		Operation: ipamOperationPoolRevoke,
		Zone:      path, Prefix: prefix,
	}, "revoked")
}

func revokeIPAMAssignmentTo(path zone.ZonePath, prefix string, assignedTo zone.ZonePath, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return revokeIPAMAssignmentWithRuntimeTo(rt, path, prefix, assignedTo)
}

func revokeIPAMAssignmentWithRuntimeTo(rt *Runtime, path zone.ZonePath, prefix string, target zone.ZonePath) error {
	return submitIPAMMutation(rt, ipamMutationRequest{
		Operation: ipamOperationAssignmentRevoke,
		Zone:      path, Prefix: prefix, Target: target,
	}, "revoked")
}

func submitIPAMMutation(rt *Runtime, request ipamMutationRequest, operation string) error {
	if version, ok, err := mutateIPAMViaControl(rt, request); ok {
		if err != nil {
			return err
		}
		fmt.Printf("%s IPAM %s version %d via daemon\n", operation, request.Prefix, version)
		return nil
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	result, err := applyIPAMMutation(state, request, rt.Now())
	if err != nil {
		return err
	}
	if !result.DryRun {
		if err := rt.SaveState(state); err != nil {
			return err
		}
	}
	fmt.Printf("%s %s/%s version %d\n", operation, result.Zone, result.Key, result.Version)
	return nil
}

func applyIPAMMutation(state *stateFile, request ipamMutationRequest, now time.Time) (*recordMutationResult, error) {
	if state == nil || state.Network == nil {
		return nil, errors.New("state is nil")
	}
	if !request.Zone.Valid() {
		return nil, fmt.Errorf("invalid IPAM zone: %s", request.Zone)
	}

	var canonical, key, recordType string
	var value []byte
	var err error
	switch request.Operation {
	case ipamOperationPoolCreate:
		if !request.Target.Valid() {
			return nil, fmt.Errorf("invalid delegated zone: %s", request.Target)
		}
		canonical, key, value, err = prepareIPAMPoolRecord(request.Prefix, request.Target, true)
		recordType = routing.RecordTypeIPAMPool
	case ipamOperationPoolRevoke:
		var delegatedTo zone.ZonePath
		canonical, key, delegatedTo, err = currentIPAMPoolInfoInState(state, request.Zone, request.Prefix)
		if err == nil {
			value, err = marshalIPAMPoolRecord(canonical, delegatedTo, false)
		}
		recordType = routing.RecordTypeIPAMPool
	case ipamOperationAssignmentCreate:
		if !request.Target.Valid() {
			return nil, fmt.Errorf("invalid assigned zone: %s", request.Target)
		}
		canonical, key, value, err = prepareIPAMAssignmentRecordTag(request.Prefix, request.Target, true, request.Shared, request.Tag)
		recordType = routing.RecordTypeIPAMAssignment
	case ipamOperationAssignmentRevoke:
		var assignedTo zone.ZonePath
		var shared bool
		var tag string
		canonical, key, assignedTo, shared, tag, err = currentIPAMAssignmentInfoInState(state, request.Zone, request.Prefix, request.Target)
		if err == nil {
			value, err = marshalIPAMAssignmentRecordTag(canonical, assignedTo, false, shared, tag)
		}
		recordType = routing.RecordTypeIPAMAssignment
	default:
		return nil, fmt.Errorf("unsupported IPAM operation %q", request.Operation)
	}
	if err != nil {
		return nil, err
	}
	if err := checkIPAMWriteCapability(state, request.Zone, key); err != nil {
		return nil, err
	}
	if strings.HasSuffix(request.Operation, "_create") {
		rejectCodes := []string{"ipam_assignment_pool_mismatch", "ipam_assignment_overlap"}
		if recordType == routing.RecordTypeIPAMPool {
			rejectCodes = []string{"ipam_pool_owner_mismatch", "ipam_pool_overlap"}
		}
		if err := validateIPAMCandidate(state, request.Zone, key, value, recordType, canonical, now, rejectCodes...); err != nil {
			return nil, err
		}
	} else if err := checkIPAMRevokeAllowed(state, request.Zone, key, canonical, recordType); err != nil {
		return nil, err
	}

	record, err := buildSignedRecordAt(state, request.Zone, key, value, recordType, now)
	if err != nil {
		return nil, err
	}
	result := &recordMutationResult{Zone: request.Zone, Key: key, Version: record.Version, DryRun: request.DryRun}
	if request.DryRun {
		return result, nil
	}
	if err := state.Network.Put(record); err != nil {
		return nil, err
	}
	return result, nil
}

func validateIPAMCandidate(state *stateFile, path zone.ZonePath, key string, value []byte, recordType, canonical string, now time.Time, rejectCodes ...string) error {
	ns := cloneNetworkStateForCandidateValidation(state.Network, path)
	zs := ns.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	zs.Records[key] = &zone.Record{Zone: path, Key: key, Type: recordType, Value: append([]byte(nil), value...)}
	ars, err := routing.BuildAuthorizedRouteSet(ns, now)
	if err != nil {
		return err
	}
	reject := make(map[string]bool, len(rejectCodes))
	for _, code := range rejectCodes {
		reject[code] = true
	}
	for _, authErr := range ars.Errors {
		if authErr.Zone == path && authErr.Prefix.String() == canonical && reject[authErr.Code] {
			return fmt.Errorf("%s: %s", authErr.Code, authErr.Detail)
		}
	}
	return nil
}

func currentIPAMPoolInfoInState(state *stateFile, path zone.ZonePath, prefix string) (canonical, key string, delegatedTo zone.ZonePath, err error) {
	canonical, err = routing.CanonicalizePrefix(prefix)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	key, err = routing.NormalizeIPAMPoolKey(prefix)
	if err != nil {
		return "", "", "", fmt.Errorf("normalize pool key for %q: %w", prefix, err)
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

func currentIPAMAssignmentInfoInState(state *stateFile, path zone.ZonePath, prefix string, target zone.ZonePath) (canonical, key string, assignedTo zone.ZonePath, shared bool, tag string, err error) {
	canonical, err = routing.CanonicalizePrefix(prefix)
	if err != nil {
		return "", "", "", false, "", fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	baseKey, err := routing.NormalizeIPAMAssignmentKey(prefix)
	if err != nil {
		return "", "", "", false, "", fmt.Errorf("normalize assignment key for %q: %w", prefix, err)
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
		if parseErr != nil || assignment.Prefix != canonical || (target.Valid() && assignment.AssignedTo != target) {
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
			if slices.Contains(capability.Permissions, zone.PermAllocateIP) {
				return nil
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
	return listIPAMAssignmentsWithRuntimeTo(os.Stdout, rt, filterZone)
}

type ipamAssignmentRow struct {
	Prefix     string
	Source     string
	AssignedTo string
	Shared     bool
	Tag        string
}

func listIPAMAssignmentsWithRuntimeTo(w io.Writer, rt *Runtime, filterZone zone.ZonePath) error {
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		return err
	}

	rows := make([]ipamAssignmentRow, 0, len(ars.AllAssignments))
	filter := string(filterZone)
	for _, entry := range ars.AllAssignments {
		if filter != "" && string(entry.Source) != filter && string(entry.AssignedTo) != filter {
			continue
		}
		rows = append(rows, ipamAssignmentRow{
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
	return writeIPAMAssignments(w, rows)
}

func writeIPAMAssignments(w io.Writer, rows []ipamAssignmentRow) error {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "assignments: %d\n", len(rows))
	fmt.Fprintln(table, "PREFIX\tSOURCE\tASSIGNED_TO\tMODE\tTAG")
	for _, row := range rows {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n",
			row.Prefix,
			row.Source,
			row.AssignedTo,
			ipamAssignmentMode(row.Shared),
			dash(row.Tag),
		)
	}
	return table.Flush()
}

func showLocalIPAM(jsonOut bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return showLocalIPAMWithRuntime(rt, jsonOut)
}

func showLocalIPAMWithRuntime(rt *Runtime, jsonOut bool) error {
	report, err := buildIPAMMineReport(rt)
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
	return writeIPAMMineReport(os.Stdout, report)
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

func writeIPAMMineReport(w io.Writer, report *ipamMineReport) error {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "managed_zone: %s\n", report.ManagedZone)
	fmt.Fprintf(table, "assignments: %d\n", len(report.Assignments))
	fmt.Fprintln(table, "PREFIX\tSOURCE\tMODE\tTAG")
	for _, row := range report.Assignments {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n",
			row.Prefix,
			row.Source,
			ipamAssignmentMode(row.Shared),
			dash(row.Tag),
		)
	}
	fmt.Fprintln(table)
	fmt.Fprintf(table, "pools: %d\n", len(report.Pools))
	fmt.Fprintln(table, "PREFIX\tSOURCE\tDELEGATED_TO\tRELATION")
	for _, row := range report.Pools {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n",
			row.Prefix,
			row.Source,
			row.DelegatedTo,
			dash(strings.Join(row.Relation, ",")),
		)
	}
	return table.Flush()
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
	return writeIPAMGetReport(os.Stdout, report)
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

func writeIPAMGetReport(w io.Writer, report *ipamGetReport) error {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "query: %s\n", report.Query)

	fmt.Fprintf(table, "pools: %d\n", len(report.PoolChain))
	fmt.Fprintln(table, "PREFIX\tSOURCE\tDELEGATED_TO\tRELATION\tBEST")
	for i, pool := range report.PoolChain {
		best := "-"
		if i == len(report.PoolChain)-1 {
			best = "yes"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n",
			pool.Prefix,
			pool.Source,
			pool.DelegatedTo,
			dash(pool.Relation),
			best,
		)
	}

	fmt.Fprintln(table)
	fmt.Fprintf(table, "assignments: %d\n", len(report.Assignments))
	fmt.Fprintln(table, "PREFIX\tSOURCE\tASSIGNED_TO\tMODE\tTAG")
	for _, assignment := range report.Assignments {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n",
			assignment.Prefix,
			assignment.Source,
			assignment.AssignedTo,
			ipamAssignmentMode(assignment.Shared),
			dash(assignment.Tag),
		)
	}

	fmt.Fprintln(table)
	fmt.Fprintf(table, "routes: %d\n", len(report.Routes))
	fmt.Fprintln(table, "PREFIX\tSOURCE")
	for _, route := range report.Routes {
		fmt.Fprintf(table, "%s\t%s\n", route.Prefix, route.Source)
	}

	fmt.Fprintln(table)
	fmt.Fprintf(table, "diagnostics: %d\n", len(report.Diagnostics))
	fmt.Fprintln(table, "CODE\tDETAIL")
	for _, diag := range report.Diagnostics {
		fmt.Fprintf(table, "%s\t%s\n", diag.Code, strings.ReplaceAll(diag.Detail, "\n", "\\n"))
	}
	return table.Flush()
}

func ipamAssignmentMode(shared bool) string {
	if shared {
		return "shared"
	}
	return "exclusive"
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

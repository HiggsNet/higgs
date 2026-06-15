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
						UsageText: "higgs ipam pool create <zone> <prefix> --delegated-to <zone>",
						Description: "Delegate authority to assign prefixes from a pool to a sub-zone.\n" +
							"The prefix is canonicalized before storage.",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "delegated-to", Usage: "Zone that receives the pool delegation", Required: true},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs ipam pool create <zone> <prefix> --delegated-to <zone>", 1)
							}
							return createIPAMPool(
								zone.ZonePath(cmd.Args().Get(0)),
								cmd.Args().Get(1),
								zone.ZonePath(cmd.String("delegated-to")),
							)
						},
					},
					{
						Name:        "revoke",
						Usage:       "Revoke an IPAM pool delegation",
						UsageText:   "higgs ipam revoke pool <zone> <prefix>",
						Description: "Withdraw a previously created IPAM pool delegation by publishing a higher-version record with active=false.",
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs ipam revoke pool <zone> <prefix>", 1)
							}
							return revokeIPAMPool(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1))
						},
					},
				},
			},
			{
				Name:      "assign",
				Usage:     "Assign a prefix to a zone",
				UsageText: "higgs ipam assign <zone> <prefix> --to <zone>",
				Description: "Assign a CIDR prefix to a zone so it may announce routes within it.\n" +
					"The prefix is canonicalized before storage.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "to", Usage: "Zone that receives the assignment", Required: true},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: higgs ipam assign <zone> <prefix> --to <zone>", 1)
					}
					return assignIPAM(
						zone.ZonePath(cmd.Args().Get(0)),
						cmd.Args().Get(1),
						zone.ZonePath(cmd.String("to")),
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
						UsageText:   "higgs ipam revoke assignment <zone> <prefix>",
						Description: "Withdraw a previously created IPAM assignment by publishing a higher-version record with active=false.",
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs ipam revoke assignment <zone> <prefix>", 1)
							}
							return revokeIPAMAssignment(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1))
						},
					},
					{
						Name:        "pool",
						Usage:       "Revoke an IPAM pool delegation",
						UsageText:   "higgs ipam revoke pool <zone> <prefix>",
						Description: "Withdraw a previously created IPAM pool delegation by publishing a higher-version record with active=false.",
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: higgs ipam revoke pool <zone> <prefix>", 1)
							}
							return revokeIPAMPool(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1))
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
		},
	}
}

func createIPAMPool(path zone.ZonePath, prefix string, delegatedTo zone.ZonePath) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return createIPAMPoolWithRuntime(rt, path, prefix, delegatedTo)
}

func createIPAMPoolWithRuntime(rt *Runtime, path zone.ZonePath, prefix string, delegatedTo zone.ZonePath) error {
	canonical, key, value, err := prepareIPAMPoolRecord(prefix, delegatedTo, true)
	if err != nil {
		return err
	}
	return submitIPAMRecord(rt, path, key, value, canonical, routing.RecordTypeIPAMPool, true, "created")
}

func assignIPAM(path zone.ZonePath, prefix string, assignedTo zone.ZonePath) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return assignIPAMWithRuntime(rt, path, prefix, assignedTo)
}

func assignIPAMWithRuntime(rt *Runtime, path zone.ZonePath, prefix string, assignedTo zone.ZonePath) error {
	canonical, key, value, err := prepareIPAMAssignmentRecord(prefix, assignedTo, true)
	if err != nil {
		return err
	}
	return submitIPAMRecord(rt, path, key, value, canonical, routing.RecordTypeIPAMAssignment, true, "assigned")
}

func revokeIPAMPool(path zone.ZonePath, prefix string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
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

func revokeIPAMAssignment(path zone.ZonePath, prefix string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return revokeIPAMAssignmentWithRuntime(rt, path, prefix)
}

func revokeIPAMAssignmentWithRuntime(rt *Runtime, path zone.ZonePath, prefix string) error {
	canonical, key, assignedTo, err := currentIPAMAssignmentInfo(rt, path, prefix)
	if err != nil {
		return err
	}
	value, err := marshalIPAMAssignmentRecord(canonical, assignedTo, false)
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

func prepareIPAMAssignmentRecord(prefix string, assignedTo zone.ZonePath, active bool) (canonical, key string, value []byte, err error) {
	canonical, err = routing.CanonicalizePrefix(prefix)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	key, err = routing.NormalizeIPAMAssignmentKey(prefix)
	if err != nil {
		return "", "", nil, fmt.Errorf("normalize assignment key for %q: %w", prefix, err)
	}
	value, err = marshalIPAMAssignmentRecord(canonical, assignedTo, active)
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

func marshalIPAMAssignmentRecord(canonical string, assignedTo zone.ZonePath, active bool) ([]byte, error) {
	record := routing.IPAMAssignmentRecord{Version: 1, Prefix: canonical, AssignedTo: assignedTo, Active: active}
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

func currentIPAMAssignmentInfo(rt *Runtime, path zone.ZonePath, prefix string) (canonical, key string, assignedTo zone.ZonePath, err error) {
	canonical, err = routing.CanonicalizePrefix(prefix)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	key, err = routing.NormalizeIPAMAssignmentKey(prefix)
	if err != nil {
		return "", "", "", fmt.Errorf("normalize assignment key for %q: %w", prefix, err)
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
		return "", "", "", fmt.Errorf("no active ipam.assignment for %s in %s", canonical, path)
	}
	assignment, err := routing.ParseIPAMAssignmentRecord(current)
	if err != nil {
		return "", "", "", fmt.Errorf("current assignment record for %s is invalid: %w", canonical, err)
	}
	if !assignment.Active {
		return "", "", "", fmt.Errorf("assignment %s in %s is already revoked", canonical, path)
	}
	return canonical, key, assignment.AssignedTo, nil
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
	logControlFallback("ipam_submit")
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
	}
	rows := make([]assignmentRow, 0, len(ars.Assignments))
	filter := string(filterZone)
	for _, entry := range ars.Assignments {
		if filter != "" && string(entry.Source) != filter && string(entry.AssignedTo) != filter {
			continue
		}
		rows = append(rows, assignmentRow{
			Prefix:     entry.Prefix.String(),
			Source:     string(entry.Source),
			AssignedTo: string(entry.AssignedTo),
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

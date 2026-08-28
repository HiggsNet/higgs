package inspect

// RouteShowReport is the canonical read model for published route records.
type RouteShowReport struct {
	ManagedZone   string         `json:"managed_zone"`
	Announcements []RouteShowRow `json:"announcements"`
}

type RouteShowRow struct {
	Zone       string `json:"zone"`
	Prefix     string `json:"prefix"`
	Tag        string `json:"tag,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
	Active     bool   `json:"active"`
	Controller string `json:"controller,omitempty"`
	Authorized bool   `json:"authorized"`
	Version    uint64 `json:"version"`
	Key        string `json:"key"`
}

type IPAMAssignmentRow struct {
	Prefix     string `json:"prefix"`
	Source     string `json:"source"`
	AssignedTo string `json:"assigned_to"`
	Shared     bool   `json:"shared,omitempty"`
	Tag        string `json:"tag,omitempty"`
}

type IPAMMineReport struct {
	ManagedZone string                  `json:"managed_zone"`
	Assignments []IPAMMineAssignmentRow `json:"assignments"`
	Pools       []IPAMMinePoolRow       `json:"pools"`
}

type IPAMMineAssignmentRow struct {
	Prefix string `json:"prefix"`
	Source string `json:"source"`
	Shared bool   `json:"shared,omitempty"`
	Tag    string `json:"tag,omitempty"`
}

type IPAMMinePoolRow struct {
	Prefix      string   `json:"prefix"`
	Source      string   `json:"source"`
	DelegatedTo string   `json:"delegated_to"`
	Relation    []string `json:"relation"`
}

type IPAMGetReport struct {
	Query       string                 `json:"query"`
	PoolChain   []IPAMGetPoolRow       `json:"pool_chain"`
	BestPool    *IPAMGetPoolRow        `json:"best_pool"`
	Assignments []IPAMGetAssignmentRow `json:"assignments"`
	AssignedTo  *string                `json:"assigned_to"`
	Routes      []IPAMGetRouteRow      `json:"routes"`
	Diagnostics []IPAMGetDiagnosticRow `json:"diagnostics"`
}

type IPAMGetPoolRow struct {
	Prefix      string `json:"prefix"`
	Source      string `json:"source"`
	DelegatedTo string `json:"delegated_to"`
	Relation    string `json:"relation,omitempty"`
}

type IPAMGetAssignmentRow struct {
	Prefix     string `json:"prefix"`
	Source     string `json:"source"`
	AssignedTo string `json:"assigned_to"`
	Shared     bool   `json:"shared,omitempty"`
	Tag        string `json:"tag,omitempty"`
}

type IPAMGetRouteRow struct {
	Prefix string `json:"prefix"`
	Source string `json:"source"`
}

type IPAMGetDiagnosticRow struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

package text

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteHealthDebug(w io.Writer, view inspect.HealthDebugView) error {
	view = inspect.BuildHealthDebugView(view)
	if w == nil {
		return nil
	}
	targets := view.Targets
	if len(targets) == 0 {
		out := newLineWriter(w)
		out.Println("No link instances to probe.")
		return out.Err()
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	liveByProbe := make(map[string]inspect.HealthLiveView, len(view.Live))
	for _, live := range view.Live {
		key := firstNonEmpty(live.ProbeID, live.InstanceID)
		liveByProbe[key] = live
	}
	out.Linef("Link health (%d links):", len(targets))
	out.Println("LINK\tPROBE ID\tPEER\tOVERLAY\tROLE\tFAMILY\tINTERFACE\tLOCAL->PEER\tLINK STATE\tHEALTH\tPROBE\tPACKETS\tLOSS\tRTT (LAST/EWMA/P50/P95/P99)\tJITTER\tFAILS\tCUTOVER\tERROR")
	for _, t := range targets {
		probeID := firstNonEmpty(t.ProbeID, t.InstanceID)
		live, hasLive := liveByProbe[probeID]
		out.Linef("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s",
			t.InstanceID,
			probeID,
			dash(t.PeerZone),
			dash(t.Overlay),
			firstNonEmpty(t.ProbeRole, "active"),
			dash(t.UnderlayFamily),
			dash(t.InterfaceName),
			formatHealthTunnel(t.LocalTunnelAddr, t.PeerTunnelAddr),
			dash(t.State),
			healthLiveState(live, hasLive),
			dash(live.ProbeType),
			healthPackets(live, hasLive),
			healthLoss(live, hasLive),
			healthRTT(live, hasLive),
			healthMillis(live.JitterMs, hasLive),
			healthFailures(live, hasLive),
			healthCutover(live, hasLive, t.Staged || t.ProbeRole == "staged"),
			escapeTableCell(dash(live.LastError)),
		)
	}
	if err := out.Err(); err != nil {
		return err
	}
	return table.Flush()
}

func formatHealthTunnel(local, peer string) string {
	if local == "" && peer == "" {
		return "-"
	}
	return dash(local) + "->" + dash(peer)
}

func healthLiveState(live inspect.HealthLiveView, ok bool) string {
	if !ok {
		return "-"
	}
	return dash(live.State)
}

func healthPackets(live inspect.HealthLiveView, ok bool) string {
	if !ok || live.Sent == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d/%d", live.Sent, live.Received, live.Lost)
}

func healthLoss(live inspect.HealthLiveView, ok bool) string {
	if !ok || live.Sent == 0 {
		return "-"
	}
	return fmt.Sprintf("%d%%", live.LossRatio)
}

func healthRTT(live inspect.HealthLiveView, ok bool) string {
	if !ok || (live.LastRTTMs == 0 && live.EWMARTTMs == 0 && live.P95RTTMs == 0) {
		return "-"
	}
	return fmt.Sprintf("%d/%d/%d/%d/%dms", live.LastRTTMs, live.EWMARTTMs, live.P50RTTMs, live.P95RTTMs, live.P99RTTMs)
}

func healthMillis(value int64, ok bool) string {
	if !ok || value == 0 {
		return "-"
	}
	return fmt.Sprintf("%dms", value)
}

func healthFailures(live inspect.HealthLiveView, ok bool) string {
	if !ok {
		return "-"
	}
	return fmt.Sprintf("%d", live.ConsecutiveFail)
}

func healthCutover(live inspect.HealthLiveView, ok, staged bool) string {
	if !ok {
		return "-"
	}
	if live.CutoverBlocking {
		return "blocked"
	}
	if staged {
		return "ready"
	}
	return "-"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

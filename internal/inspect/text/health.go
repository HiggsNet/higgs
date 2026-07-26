package text

import (
	"io"

	"github.com/Catofes/higgs/internal/inspect"
)

func WriteHealthDebug(w io.Writer, view inspect.HealthDebugView) error {
	view = inspect.BuildHealthDebugView(view)
	if w == nil {
		return nil
	}
	out := newLineWriter(w)
	targets := view.Targets
	if len(targets) == 0 {
		out.Println("No link instances to probe.")
		return out.Err()
	}
	out.Linef("Link health (%d links):", len(targets))
	for _, t := range targets {
		out.Linef("  %s", t.InstanceID)
		out.Linef("    peer=%s overlay=%s", t.PeerZone, t.Overlay)
		out.Linef("    probe_id=%s role=%s underlay=%s interface=%s local=%s peer_addr=%s",
			t.ProbeID, firstNonEmpty(t.ProbeRole, "active"), dash(t.UnderlayFamily), t.InterfaceName, t.LocalTunnelAddr, t.PeerTunnelAddr)
		out.Linef("    state=%s staged=%v", t.State, t.Staged)
	}
	if view.Live != nil {
		out.Println("\nLive health state:")
		if err := out.Err(); err != nil {
			return err
		}
		for _, l := range view.Live {
			if err := writeHealthLive(w, l); err != nil {
				return err
			}
		}
	}
	return out.Err()
}

func writeHealthLive(w io.Writer, l inspect.HealthLiveView) error {
	out := newLineWriter(w)
	out.Linef("  %s: state=%s role=%s probe=%s", firstNonEmpty(l.ProbeID, l.InstanceID), l.State, firstNonEmpty(l.ProbeRole, "active"), l.ProbeType)
	out.LineIf(l.Sent > 0, "    sent=%d received=%d lost=%d loss=%d%%", l.Sent, l.Received, l.Lost, l.LossRatio)
	out.LineIf(l.LastRTTMs > 0, "    rtt last=%dms ewma=%dms p50=%dms p95=%dms p99=%dms jitter=%dms",
		l.LastRTTMs, l.EWMARTTMs, l.P50RTTMs, l.P95RTTMs, l.P99RTTMs, l.JitterMs)
	out.LineIf(l.LastError != "", "    last_error=%s consecutive_fail=%d", l.LastError, l.ConsecutiveFail)
	out.LineIf(l.CutoverBlocking, "    cutover_blocking=true")
	return out.Err()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

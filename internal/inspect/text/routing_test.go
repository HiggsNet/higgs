package text

import (
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestWriteBirdDump(t *testing.T) {
	dump := &inspect.BirdDumpResponse{Instances: map[string]inspect.BirdDumpInstance{
		"z": {
			NetNS:         "z",
			InstanceID:    "main",
			ControlSocket: "/run/bird.ctl",
			Raw: map[string]string{
				"show route": "10.0.0.0/24 unicast\n",
			},
		},
	}}
	var buf strings.Builder
	if err := WriteBirdDump(&buf, dump); err != nil {
		t.Fatalf("WriteBirdDump: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"netns z",
		"instance_id: main",
		"control_socket: /run/bird.ctl",
		"command: show route",
		"10.0.0.0/24 unicast",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestWriteBabelDebug(t *testing.T) {
	view := inspect.BabelDebugView{
		LastReconcileError: "reload failed",
		Instances: []inspect.BabelInstanceView{
			{
				NetNS:          "higgstesth2",
				InstanceID:     "main",
				Mode:           "managed",
				ShutdownPolicy: "persist",
				Enabled:        true,
				RouterID:       12345,
				ControlSocket:  "/run/higgs/bird/bird-main.ctl",
				ConfigPath:     "/run/higgs/bird/bird-main.conf",
				PIDFile:        "/run/higgs/bird/bird-main.pid",
				LastConfigHash: "deadbeef1234567890abcdef",
				Overlays:       []string{"main"},
				State:          "running",
				HasState:       true,
			},
			{
				NetNS:      "disabled",
				InstanceID: "off",
				Mode:       "disabled",
				Enabled:    false,
			},
		},
	}
	var buf strings.Builder
	if err := WriteBabelDebug(&buf, view); err != nil {
		t.Fatalf("WriteBabelDebug: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"last_reconcile_error: reload failed",
		"netns higgstesth2",
		"shutdown_policy: persist",
		"router_id: 12345",
		"last_config_hash: deadbeef1234",
		"overlays: main",
		"state: running",
		"netns disabled",
		"state: disabled",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

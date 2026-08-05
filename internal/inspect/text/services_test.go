package text

import (
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestWriteServicesShowsPublishedAndLocalServices(t *testing.T) {
	view := inspect.ServiceInspection{
		ManagedZone: "node-a.catofes.",
		Services: []inspect.ServiceView{
			{
				ID: "socks5", Type: "socks5", Owner: "node-a.catofes.", Local: true, Status: "active",
				Version: 2, UpdatedUnix: 1700000000, RecordKey: "services/socks5",
				Endpoints: []inspect.ServiceEndpointView{{Region: "local", Address: "fd42:1::20", Port: 3128}},
			},
			{
				ID: "socks5", Type: "socks5", Owner: "node-b.catofes.", Status: "active",
				Endpoints: []inspect.ServiceEndpointView{{Region: "cn", Address: "198.51.100.20", Port: 1080}},
			},
			{
				ID: "socks5", Type: "socks5", Owner: "node-c.catofes.", Status: "withdrawn",
				Endpoints: []inspect.ServiceEndpointView{{Region: "us", Address: "203.0.113.20", Port: 1080}},
			},
		},
	}

	var output strings.Builder
	if err := WriteServices(&output, view, "", false, false, false); err != nil {
		t.Fatalf("WriteServices: %v", err)
	}
	for _, want := range []string{
		"managed_zone: node-a.catofes.", "services: 2", "SERVICE", "OWNER", "SCOPE", "REGION", "ENDPOINT", "STATUS",
		"node-a.catofes.", "local", "[fd42:1::20]:3128", "node-b.catofes.", "remote", "198.51.100.20:1080",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "node-c.catofes.") {
		t.Fatalf("withdrawn service shown without --all:\n%s", output.String())
	}

	output.Reset()
	if err := WriteServices(&output, view, "", true, true, true); err != nil {
		t.Fatalf("WriteServices local verbose: %v", err)
	}
	for _, want := range []string{"services: 1", "VERSION", "UPDATED", "RECORD", "services/socks5", "2023-11-14T22:13:20Z"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("local verbose output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "node-b.catofes.") || strings.Contains(output.String(), "node-c.catofes.") {
		t.Fatalf("local filter leaked remote services:\n%s", output.String())
	}
}

package observer

import (
	"io/fs"
	"strings"
	"testing"
)

func webSubFSForTest() fs.FS {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil
	}
	return sub
}

func readWebFile(t *testing.T, webFS fs.FS, name string) string {
	t.Helper()
	data, err := fs.ReadFile(webFS, name)
	if err != nil {
		t.Fatalf("read %s error: %v", name, err)
	}
	return string(data)
}

func TestWebSubFS(t *testing.T) {
	webFS := webSubFSForTest()
	if webFS == nil {
		t.Fatal("WebSubFS should not be nil")
	}
	data, err := fs.ReadFile(webFS, "index.html")
	if err != nil {
		t.Fatalf("read index.html error: %v", err)
	}
	if len(data) == 0 {
		t.Error("index.html should not be empty")
	}
}

func TestWebModulesExist(t *testing.T) {
	webFS := webSubFSForTest()
	if webFS == nil {
		t.Fatal("WebSubFS should not be nil")
	}
	for _, name := range []string{
		"style/tokens.css",
		"style/base.css",
		"style/pages.css",
		"src/main.js",
		"src/api.js",
		"src/store.js",
		"src/events.js",
		"src/router.js",
		"src/format.js",
		"src/components/badge.js",
		"src/components/card.js",
		"src/components/table.js",
		"src/components/kv.js",
		"src/components/jsonview.js",
		"src/components/chart.js",
		"src/pages/overview.js",
		"src/pages/gossip.js",
		"src/pages/zones.js",
		"src/pages/overlay.js",
		"src/pages/health.js",
		"src/pages/health_history.js",
		"src/pages/routes.js",
		"src/pages/bird.js",
		"src/pages/timeline.js",
	} {
		if _, err := fs.Stat(webFS, name); err != nil {
			t.Errorf("web module %s missing: %v", name, err)
		}
	}
}

func TestIndexHTMLModuleShell(t *testing.T) {
	webFS := webSubFSForTest()
	if webFS == nil {
		t.Fatal("WebSubFS should not be nil")
	}
	body := readWebFile(t, webFS, "index.html")
	for _, token := range []string{
		`type="module" src="/src/main.js"`,
		`/style/tokens.css`,
		`/style/base.css`,
		`/style/pages.css`,
		`id="connection-status"`,
	} {
		if !strings.Contains(body, token) {
			t.Errorf("index.html missing token %q", token)
		}
	}
}

func TestFormatEscapesHTML(t *testing.T) {
	webFS := webSubFSForTest()
	if webFS == nil {
		t.Fatal("WebSubFS should not be nil")
	}
	body := readWebFile(t, webFS, "src/format.js")
	for _, token := range []string{"export function esc", "&amp;", "&lt;", "&gt;", "&quot;", "&#39;"} {
		if !strings.Contains(body, token) {
			t.Fatalf("src/format.js esc() missing HTML escape token %q", token)
		}
	}
}

func TestStoreModule(t *testing.T) {
	webFS := webSubFSForTest()
	if webFS == nil {
		t.Fatal("WebSubFS should not be nil")
	}
	body := readWebFile(t, webFS, "src/store.js")
	for _, token := range []string{
		"const cache = new Map()",
		"const inflight = new Map()",
		"export function subscribe",
		"export function fetch",
		"export function invalidate",
		"export function refreshWatched",
	} {
		if !strings.Contains(body, token) {
			t.Errorf("src/store.js missing token %q", token)
		}
	}
}

func TestEventsModuleInvalidationMap(t *testing.T) {
	webFS := webSubFSForTest()
	if webFS == nil {
		t.Fatal("WebSubFS should not be nil")
	}
	body := readWebFile(t, webFS, "src/events.js")
	for _, token := range []string{
		"EventSource",
		"state_changed",
		"peer_updated",
		"link_updated",
		"health_updated",
		"route_changed",
		"bird_updated",
		"'/links'",
		"'/peers'",
		"'/health'",
		"refreshWatched",
	} {
		if !strings.Contains(body, token) {
			t.Errorf("src/events.js missing token %q", token)
		}
	}
}

// The old foldState patch is gone; re-renders must preserve scroll
// position, the active input and open <details> elements instead.
func TestRouterPreservesUIState(t *testing.T) {
	webFS := webSubFSForTest()
	if webFS == nil {
		t.Fatal("WebSubFS should not be nil")
	}
	body := readWebFile(t, webFS, "src/router.js")
	for _, token := range []string{
		"export function parseHash",
		"export function navigate",
		"export function handleHashChange",
		"export function captureUIState",
		"export function restoreUIState",
		"scrollTop",
		"details",
	} {
		if !strings.Contains(body, token) {
			t.Errorf("src/router.js missing token %q", token)
		}
	}
	for _, file := range []string{"src/router.js", "src/main.js"} {
		if strings.Contains(readWebFile(t, webFS, file), "foldState") {
			t.Errorf("%s still references the removed foldState patch", file)
		}
	}
}

func TestPagesExportRenderAndDeps(t *testing.T) {
	webFS := webSubFSForTest()
	if webFS == nil {
		t.Fatal("WebSubFS should not be nil")
	}
	for _, page := range []string{"overview", "gossip", "zones", "overlay", "health", "routes", "bird", "timeline"} {
		body := readWebFile(t, webFS, "src/pages/"+page+".js")
		if !strings.Contains(body, "export function render") {
			t.Errorf("src/pages/%s.js missing render export", page)
		}
		if !strings.Contains(body, "export const deps") {
			t.Errorf("src/pages/%s.js missing deps export", page)
		}
	}
}

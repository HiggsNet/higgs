package main

import (
	"io/fs"
	"strings"
	"testing"
)

func TestWebSubFS(t *testing.T) {
	webFS := webSubFS()
	if webFS == nil {
		t.Fatal("webSubFS should not be nil")
	}
	data, err := fs.ReadFile(webFS, "index.html")
	if err != nil {
		t.Fatalf("read index.html error: %v", err)
	}
	if len(data) == 0 {
		t.Error("index.html should not be empty")
	}
}

func TestWebAppEscapesHTML(t *testing.T) {
	webFS := webSubFS()
	if webFS == nil {
		t.Fatal("webSubFS should not be nil")
	}
	data, err := fs.ReadFile(webFS, "app.js")
	if err != nil {
		t.Fatalf("read app.js error: %v", err)
	}
	body := string(data)
	for _, token := range []string{"&amp;", "&lt;", "&gt;", "&quot;", "&#39;"} {
		if !strings.Contains(body, token) {
			t.Fatalf("app.js esc() missing HTML escape token %q", token)
		}
	}
}

func TestWebAppPreservesFoldState(t *testing.T) {
	webFS := webSubFS()
	if webFS == nil {
		t.Fatal("webSubFS should not be nil")
	}
	data, err := fs.ReadFile(webFS, "app.js")
	if err != nil {
		t.Fatalf("read app.js error: %v", err)
	}
	body := string(data)
	for _, token := range []string{
		"const foldState = new Map()",
		"function rememberFoldState",
		"function restoreFoldState",
		"details[data-fold-key]",
		"data-fold-key",
		"restoreFoldState(content)",
		"restoreFoldState(el)",
	} {
		if !strings.Contains(body, token) {
			t.Fatalf("app.js fold-state support missing token %q", token)
		}
	}
}

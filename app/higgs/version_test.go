package main

import (
	"strings"
	"testing"
)

func TestWriteVersionIncludesBuildFields(t *testing.T) {
	var b strings.Builder
	if err := writeVersion(&b); err != nil {
		t.Fatalf("writeVersion: %v", err)
	}
	out := b.String()
	for _, want := range []string{"higgs ", "commit:", "dirty:", "built_at:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("version output missing %q:\n%s", want, out)
		}
	}
}

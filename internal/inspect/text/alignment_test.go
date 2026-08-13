package text

import (
	"strings"
	"testing"
)

func TestWriteAlignedRowsRightAlignsOnlySelectedColumn(t *testing.T) {
	rows := [][]string{
		{"PREFIX", "ZONE", "STATE"},
		{"10.0.0.0/24", ".", "active"},
		{"10.0.1.0/24", "node-a.catofes.", "active"},
	}
	var out strings.Builder
	if err := WriteAlignedRows(&out, rows, 1); err != nil {
		t.Fatalf("WriteAlignedRows: %v", err)
	}
	want := "PREFIX\t           ZONE\tSTATE\n" +
		"10.0.0.0/24\t              .\tactive\n" +
		"10.0.1.0/24\tnode-a.catofes.\tactive\n"
	if got := out.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

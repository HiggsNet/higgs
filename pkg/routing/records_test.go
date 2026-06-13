package routing

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestCanonicalizePrefix(t *testing.T) {
	tests := []struct {
		input    string
		want     string
		wantErr  bool
		errMatch string
	}{
		{"10.0.1.0/24", "10.0.1.0/24", false, ""},
		{"10.0.1.1/24", "10.0.1.0/24", false, ""},
		{"2001:db8::/32", "2001:db8::/32", false, ""},
		{"2001:db8::1/32", "2001:db8::/32", false, ""},
		{"192.168.0.0/16", "192.168.0.0/16", false, ""},
		{"0.0.0.0/0", "0.0.0.0/0", false, ""},
		{"::/0", "::/0", false, ""},
		{"not-a-prefix", "", true, "no '/'"},
		{"10.0.0.0/33", "", true, "prefix length out of range"},
		{"", "", true, "no '/'"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := CanonicalizePrefix(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CanonicalizePrefix(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				if tt.errMatch != "" && (err == nil || !strings.Contains(err.Error(), tt.errMatch)) {
					t.Fatalf("CanonicalizePrefix(%q) error %v should contain %q", tt.input, err, tt.errMatch)
				}
				return
			}
			if got != tt.want {
				t.Fatalf("CanonicalizePrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeRouteAnnouncementKey(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"10.0.1.0/24", "routes/announcements/10.0.1.0_24", false},
		{"10.0.1.1/24", "routes/announcements/10.0.1.0_24", false},
		{"2001:db8::/32", "routes/announcements/2001:db8::_32", false},
		{"not-a-prefix", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := NormalizeRouteAnnouncementKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeRouteAnnouncementKey(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("NormalizeRouteAnnouncementKey(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeIPAMPoolKey(t *testing.T) {
	got, err := NormalizeIPAMPoolKey("10.0.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "ipam/pools/10.0.1.0_24"
	if got != want {
		t.Fatalf("NormalizeIPAMPoolKey = %q, want %q", got, want)
	}
}

func TestNormalizeIPAMAssignmentKey(t *testing.T) {
	got, err := NormalizeIPAMAssignmentKey("2001:db8::/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "ipam/assignments/2001:db8::_32"
	if got != want {
		t.Fatalf("NormalizeIPAMAssignmentKey = %q, want %q", got, want)
	}
}

func TestParseRouteAnnouncementRecord(t *testing.T) {
	value, err := json.Marshal(RouteAnnouncementRecord{
		Version: 1,
		Prefix:  "10.0.1.1/24",
		Active:  true,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	record := &zone.Record{
		Zone:  "pek.catofes.",
		Key:   "routes/announcements/10.0.1.0_24",
		Type:  RecordTypeRouteAnnouncement,
		Value: value,
	}

	ann, err := ParseRouteAnnouncementRecord(record)
	if err != nil {
		t.Fatalf("ParseRouteAnnouncementRecord failed: %v", err)
	}
	if ann.Version != 1 {
		t.Fatalf("Version = %d, want 1", ann.Version)
	}
	if ann.Prefix != "10.0.1.0/24" {
		t.Fatalf("Prefix = %q, want 10.0.1.0/24", ann.Prefix)
	}
	if !ann.Active {
		t.Fatal("Active = false, want true")
	}

	t.Run("nil record", func(t *testing.T) {
		if _, err := ParseRouteAnnouncementRecord(nil); err == nil {
			t.Fatal("expected error for nil record")
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		bad := *record
		bad.Type = "ipsec.profile.v1"
		if _, err := ParseRouteAnnouncementRecord(&bad); err == nil {
			t.Fatal("expected error for wrong record type")
		}
	})

	t.Run("key mismatch", func(t *testing.T) {
		bad := *record
		bad.Key = "routes/announcements/10.0.2.0_24"
		if _, err := ParseRouteAnnouncementRecord(&bad); err == nil {
			t.Fatal("expected error for key mismatch")
		} else if !strings.Contains(err.Error(), "route_announcement_key_mismatch") {
			t.Fatalf("error should mention route_announcement_key_mismatch: %v", err)
		}
	})

	t.Run("invalid prefix", func(t *testing.T) {
		value, _ := json.Marshal(RouteAnnouncementRecord{
			Version: 1,
			Prefix:  "bad",
			Active:  true,
		})
		bad := *record
		bad.Value = value
		if _, err := ParseRouteAnnouncementRecord(&bad); err == nil {
			t.Fatal("expected error for invalid prefix")
		}
	})

	t.Run("empty prefix", func(t *testing.T) {
		value, _ := json.Marshal(RouteAnnouncementRecord{
			Version: 1,
			Prefix:  "",
			Active:  true,
		})
		bad := *record
		bad.Value = value
		if _, err := ParseRouteAnnouncementRecord(&bad); err == nil {
			t.Fatal("expected error for empty prefix")
		}
	})

	t.Run("unsupported version", func(t *testing.T) {
		value, _ := json.Marshal(RouteAnnouncementRecord{
			Version: 2,
			Prefix:  "10.0.1.0/24",
			Active:  true,
		})
		bad := *record
		bad.Value = value
		if _, err := ParseRouteAnnouncementRecord(&bad); err == nil {
			t.Fatal("expected error for unsupported version")
		}
	})
}

func TestValidateRouteAnnouncementAgainstHistory(t *testing.T) {
	makeRecord := func(prefix string) *zone.Record {
		value, _ := json.Marshal(RouteAnnouncementRecord{
			Version: 1,
			Prefix:  prefix,
			Active:  true,
		})
		return &zone.Record{
			Zone:  "pek.catofes.",
			Key:   "routes/announcements/10.0.1.0_24",
			Type:  RecordTypeRouteAnnouncement,
			Value: value,
		}
	}

	current := makeRecord("10.0.1.0/24")
	ann := &RouteAnnouncementRecord{Version: 1, Prefix: "10.0.1.0/24", Active: true}

	if err := ValidateRouteAnnouncementAgainstHistory(ann, current); err != nil {
		t.Fatalf("same prefix should pass: %v", err)
	}

	badAnn := &RouteAnnouncementRecord{Version: 1, Prefix: "10.0.2.0/24", Active: true}
	if err := ValidateRouteAnnouncementAgainstHistory(badAnn, current); err == nil {
		t.Fatal("expected prefix change rejection")
	} else if !strings.Contains(err.Error(), "route_announcement_key_mismatch") {
		t.Fatalf("error should mention route_announcement_key_mismatch: %v", err)
	}

	if err := ValidateRouteAnnouncementAgainstHistory(ann, nil); err != nil {
		t.Fatalf("nil current should pass: %v", err)
	}
}

func TestParseIPAMPoolRecord(t *testing.T) {
	value, err := json.Marshal(IPAMPoolRecord{
		Version:     1,
		Prefix:      "10.0.1.0/24",
		DelegatedTo: "pek.catofes.",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	record := &zone.Record{
		Zone:  "catofes.",
		Key:   "ipam/pools/10.0.1.0_24",
		Type:  RecordTypeIPAMPool,
		Value: value,
	}

	pool, err := ParseIPAMPoolRecord(record)
	if err != nil {
		t.Fatalf("ParseIPAMPoolRecord failed: %v", err)
	}
	if pool.Version != 1 {
		t.Fatalf("Version = %d, want 1", pool.Version)
	}
	if pool.Prefix != "10.0.1.0/24" {
		t.Fatalf("Prefix = %q, want 10.0.1.0/24", pool.Prefix)
	}
	if pool.DelegatedTo != "pek.catofes." {
		t.Fatalf("DelegatedTo = %q, want pek.catofes.", pool.DelegatedTo)
	}

	t.Run("wrong type", func(t *testing.T) {
		bad := *record
		bad.Type = RecordTypeIPAMAssignment
		if _, err := ParseIPAMPoolRecord(&bad); err == nil {
			t.Fatal("expected error for wrong record type")
		}
	})

	t.Run("key mismatch", func(t *testing.T) {
		bad := *record
		bad.Key = "ipam/pools/10.0.2.0_24"
		if _, err := ParseIPAMPoolRecord(&bad); err == nil {
			t.Fatal("expected error for key mismatch")
		}
	})

	t.Run("empty delegated_to", func(t *testing.T) {
		value, _ := json.Marshal(IPAMPoolRecord{
			Version:     1,
			Prefix:      "10.0.1.0/24",
			DelegatedTo: "",
		})
		bad := *record
		bad.Value = value
		if _, err := ParseIPAMPoolRecord(&bad); err == nil {
			t.Fatal("expected error for empty delegated_to")
		}
	})
}

func TestParseIPAMAssignmentRecord(t *testing.T) {
	value, err := json.Marshal(IPAMAssignmentRecord{
		Version:    1,
		Prefix:     "10.0.1.1/24",
		AssignedTo: "pek.catofes.",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	record := &zone.Record{
		Zone:  "catofes.",
		Key:   "ipam/assignments/10.0.1.0_24",
		Type:  RecordTypeIPAMAssignment,
		Value: value,
	}

	assignment, err := ParseIPAMAssignmentRecord(record)
	if err != nil {
		t.Fatalf("ParseIPAMAssignmentRecord failed: %v", err)
	}
	if assignment.Version != 1 {
		t.Fatalf("Version = %d, want 1", assignment.Version)
	}
	if assignment.Prefix != "10.0.1.0/24" {
		t.Fatalf("Prefix = %q, want 10.0.1.0/24", assignment.Prefix)
	}
	if assignment.AssignedTo != "pek.catofes." {
		t.Fatalf("AssignedTo = %q, want pek.catofes.", assignment.AssignedTo)
	}

	t.Run("wrong type", func(t *testing.T) {
		bad := *record
		bad.Type = RecordTypeIPAMPool
		if _, err := ParseIPAMAssignmentRecord(&bad); err == nil {
			t.Fatal("expected error for wrong record type")
		}
	})

	t.Run("key mismatch", func(t *testing.T) {
		bad := *record
		bad.Key = "ipam/assignments/10.0.2.0_24"
		if _, err := ParseIPAMAssignmentRecord(&bad); err == nil {
			t.Fatal("expected error for key mismatch")
		}
	})

	t.Run("empty assigned_to", func(t *testing.T) {
		value, _ := json.Marshal(IPAMAssignmentRecord{
			Version:    1,
			Prefix:     "10.0.1.0/24",
			AssignedTo: "",
		})
		bad := *record
		bad.Value = value
		if _, err := ParseIPAMAssignmentRecord(&bad); err == nil {
			t.Fatal("expected error for empty assigned_to")
		}
	})
}

func TestRecordValidationHelpers(t *testing.T) {
	t.Run("RouteAnnouncementRecord.Validate", func(t *testing.T) {
		r := RouteAnnouncementRecord{Version: 1, Prefix: "10.0.1.0/24", Active: true}
		if err := r.Validate("pek.catofes."); err != nil {
			t.Fatalf("valid record failed: %v", err)
		}
		r.Version = 2
		if err := r.Validate("pek.catofes."); err == nil {
			t.Fatal("expected error for bad version")
		}
		r.Version = 1
		r.Prefix = "bad"
		if err := r.Validate("pek.catofes."); err == nil {
			t.Fatal("expected error for bad prefix")
		}
	})

	t.Run("IPAMPoolRecord.Validate", func(t *testing.T) {
		r := IPAMPoolRecord{Version: 1, Prefix: "10.0.1.0/24", DelegatedTo: "pek.catofes."}
		if err := r.Validate("catofes."); err != nil {
			t.Fatalf("valid record failed: %v", err)
		}
		r.DelegatedTo = ""
		if err := r.Validate("catofes."); err == nil {
			t.Fatal("expected error for empty delegated_to")
		}
	})

	t.Run("IPAMAssignmentRecord.Validate", func(t *testing.T) {
		r := IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "pek.catofes."}
		if err := r.Validate("catofes."); err != nil {
			t.Fatalf("valid record failed: %v", err)
		}
		r.AssignedTo = ""
		if err := r.Validate("catofes."); err == nil {
			t.Fatal("expected error for empty assigned_to")
		}
	})
}

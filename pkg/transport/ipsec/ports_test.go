package ipsec

import (
	"testing"
	"time"
)

func TestPlanPortRecordDefaultsToStandardPorts(t *testing.T) {
	now := time.Unix(1717171717, 0)
	record, err := PlanPortRecord(PortPlanOptions{Now: now, Generation: 7})
	if err != nil {
		t.Fatalf("PlanPortRecord: %v", err)
	}
	if record.Mode != PortModeFixed || record.Range != nil {
		t.Fatalf("record mode = %+v", record)
	}
	if record.Current.Generation != 7 {
		t.Fatalf("generation = %d", record.Current.Generation)
	}
	if record.Current.IKE.Local != DefaultIKEPort || record.Current.IKE.Advertised != DefaultIKEPort {
		t.Fatalf("IKE binding = %+v", record.Current.IKE)
	}
	if record.Current.NATT.Local != DefaultNATTPort || record.Current.NATT.Advertised != DefaultNATTPort {
		t.Fatalf("NATT binding = %+v", record.Current.NATT)
	}
	if record.UpdatedAt != now.Unix() {
		t.Fatalf("UpdatedAt = %d, want %d", record.UpdatedAt, now.Unix())
	}
}

func TestPlanPortRecordRangeIsStableByGeneration(t *testing.T) {
	now := time.Unix(1717171717, 0)
	record, err := PlanPortRecord(PortPlanOptions{
		Mode:       PortModeRange,
		Range:      &PortRange{From: 30000, To: 30003},
		Generation: 5,
		Now:        now,
	})
	if err != nil {
		t.Fatalf("PlanPortRecord: %v", err)
	}
	if record.Range == nil || record.Range.From != 30000 || record.Range.To != 30003 {
		t.Fatalf("range = %+v", record.Range)
	}
	if record.Current.IKE.Local != DefaultIKEPort || record.Current.NATT.Local != DefaultNATTPort {
		t.Fatalf("local ports = %+v, want charon defaults", record.Current)
	}
	if record.Current.IKE.Advertised != 30001 || record.Current.NATT.Advertised != 30002 {
		t.Fatalf("advertised ports = %+v, want selected range ports", record.Current)
	}
	again, err := PlanPortRecord(PortPlanOptions{
		Mode:       PortModeRange,
		Range:      &PortRange{From: 30000, To: 30003},
		Generation: 5,
		Now:        now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("PlanPortRecord(again): %v", err)
	}
	if record.Current.IKE.Advertised != again.Current.IKE.Advertised || record.Current.NATT.Advertised != again.Current.NATT.Advertised {
		t.Fatalf("range selection changed: %+v vs %+v", record.Current, again.Current)
	}
}

func TestPlanPortRecordCarriesPreviousCurrentWithGrace(t *testing.T) {
	now := time.Unix(1717171717, 0)
	previous, err := PlanPortRecord(PortPlanOptions{
		FixedIKE:   30412,
		FixedNATT:  30413,
		Generation: 41,
		Now:        now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("PlanPortRecord(previous): %v", err)
	}
	rotated, err := PlanPortRecord(PortPlanOptions{
		Mode:          PortModeRange,
		Range:         &PortRange{From: 31000, To: 31009},
		Generation:    42,
		Previous:      previous,
		PreviousGrace: 10 * time.Minute,
		Now:           now,
	})
	if err != nil {
		t.Fatalf("PlanPortRecord(rotated): %v", err)
	}
	if len(rotated.Previous) != 1 {
		t.Fatalf("previous len = %d, want 1", len(rotated.Previous))
	}
	if rotated.Previous[0].Generation != 41 || rotated.Previous[0].IKE.Advertised != 30412 {
		t.Fatalf("previous selection = %+v", rotated.Previous[0])
	}
	if rotated.Previous[0].ValidUntil != now.Add(10*time.Minute).Unix() {
		t.Fatalf("ValidUntil = %d", rotated.Previous[0].ValidUntil)
	}
}

func TestPlanPortRecordDropsExpiredPreviousSelections(t *testing.T) {
	now := time.Unix(1717171717, 0)
	previous := &PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 42,
			IKE:        PortBinding{Advertised: 500},
			NATT:       PortBinding{Advertised: 4500},
		},
		Previous: []PortSelection{{
			Generation: 41,
			IKE:        PortBinding{Advertised: 30100},
			NATT:       PortBinding{Advertised: 30101},
			ValidUntil: now.Add(-time.Second).Unix(),
		}},
	}
	record, err := PlanPortRecord(PortPlanOptions{
		FixedIKE:      500,
		FixedNATT:     4500,
		Generation:    42,
		Previous:      previous,
		PreviousGrace: time.Minute,
		Now:           now,
	})
	if err != nil {
		t.Fatalf("PlanPortRecord: %v", err)
	}
	if len(record.Previous) != 0 {
		t.Fatalf("previous = %+v, want empty", record.Previous)
	}
}

func TestPlanPortRecordRejectsTinyRange(t *testing.T) {
	_, err := PlanPortRecord(PortPlanOptions{
		Mode:       PortModeRange,
		Range:      &PortRange{From: 30000, To: 30000},
		Generation: 1,
	})
	if err == nil {
		t.Fatalf("PlanPortRecord should reject one-port range")
	}
}

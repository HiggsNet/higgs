package main

import (
	"github.com/Catofes/higgs/pkg/routing"
	"testing"
	"time"
)

func TestAutoAnnounceAssignedIPsDisabled(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"10.0.0.0/24"}, nil)
	rt.Config.IPAM.AutoAnnounceAssignedIPs = false

	service := newDaemonService(rt, state, &syncConfigFile{}, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if err := service.autoAnnounceAssignedIPs(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}
	snapshot, _ := service.StateStore.Snapshot()
	if len(snapshot.Network.Zones["node-a.catofes."].Records) != 0 {
		t.Fatalf("expected no announcements when disabled, got %d", len(snapshot.Network.Zones["node-a.catofes."].Records))
	}
}

func TestAutoAnnounceAssignedIPsPublishesNew(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"10.0.0.0/24"}, nil)

	service := newDaemonService(rt, state, &syncConfigFile{}, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if err := service.autoAnnounceAssignedIPs(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	snapshot, _ := service.StateStore.Snapshot()
	rec := snapshot.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected announcement record for %s", key)
	}
	ann, err := routing.ParseRouteAnnouncementRecord(rec)
	if err != nil {
		t.Fatalf("ParseRouteAnnouncementRecord: %v", err)
	}
	if !ann.Active {
		t.Fatalf("expected active announcement, got active=false")
	}
	if ann.Prefix != "10.0.0.0/24" {
		t.Fatalf("expected prefix 10.0.0.0/24, got %s", ann.Prefix)
	}
}

func TestAutoAnnounceAssignedIPsWithdrawsStale(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", nil, map[string]bool{"10.0.0.0/24": true})

	service := newDaemonService(rt, state, &syncConfigFile{}, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if err := service.autoAnnounceAssignedIPs(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	snapshot, _ := service.StateStore.Snapshot()
	rec := snapshot.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected withdrawal record for %s", key)
	}
	ann, err := routing.ParseRouteAnnouncementRecord(rec)
	if err != nil {
		t.Fatalf("ParseRouteAnnouncementRecord: %v", err)
	}
	if ann.Active {
		t.Fatalf("expected withdrawn announcement, got active=true")
	}
}

func TestAutoAnnounceAssignedIPsSkipsExisting(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"10.0.0.0/24"}, map[string]bool{"10.0.0.0/24": true})

	service := newDaemonService(rt, state, &syncConfigFile{}, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if err := service.autoAnnounceAssignedIPs(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	snapshot, _ := service.StateStore.Snapshot()
	rec := snapshot.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected announcement record for %s", key)
	}
	if rec.Version != 1 {
		t.Fatalf("expected no rewrite, version=%d", rec.Version)
	}
}

func TestAutoAnnounceAssignedIPsSkipsInvalidAssignment(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"192.168.0.0/24"}, nil)

	service := newDaemonService(rt, state, &syncConfigFile{}, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) == 0 {
		t.Fatalf("expected authorization errors for un-pooled assignment")
	}
	if err := service.autoAnnounceAssignedIPs(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("192.168.0.0/24")
	snapshot, _ := service.StateStore.Snapshot()
	if snapshot.Network.Zones["node-a.catofes."].Records[key] != nil {
		t.Fatalf("expected no announcement for invalid assignment")
	}
}

package main

import (
	"context"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

func TestCommonControlIntentAdaptersAreTypedAndDetached(t *testing.T) {
	pool, err := commonIPAMIntent(ipamMutationRequest{
		Operation: ipamOperationPoolCreate, Zone: "catofes.", Prefix: "10.0.0.1/16", Target: "pek.catofes.",
	})
	if err != nil {
		t.Fatalf("commonIPAMIntent(pool): %v", err)
	}
	if typed, ok := pool.(corestate.PutIPAMPoolIntent); !ok || typed.Zone != "catofes." || typed.DelegatedTo != "pek.catofes." {
		t.Fatalf("pool intent = %#v", pool)
	}
	assignment, err := commonIPAMIntent(ipamMutationRequest{
		Operation: ipamOperationAssignmentRevoke, Zone: "catofes.", Prefix: "10.0.1.0/24", Target: "node.pek.catofes.",
	})
	if err != nil {
		t.Fatalf("commonIPAMIntent(assignment): %v", err)
	}
	if typed, ok := assignment.(corestate.RevokeIPAMAssignmentIntent); !ok || typed.AssignedTo != "node.pek.catofes." {
		t.Fatalf("assignment intent = %#v", assignment)
	}
	if _, ok := commonRouteIntent(routeMutationRequest{Zone: "node.pek.catofes.", Prefix: "10.0.1.0/24", Active: true}).(corestate.AnnounceRouteIntent); !ok {
		t.Fatal("active route request did not map to AnnounceRouteIntent")
	}
	if _, ok := commonRouteIntent(routeMutationRequest{Zone: "node.pek.catofes.", Prefix: "10.0.1.0/24"}).(corestate.WithdrawRouteIntent); !ok {
		t.Fatal("inactive route request did not map to WithdrawRouteIntent")
	}

	request := serviceMutationRequest{Operation: serviceOperationPublish, Endpoints: []photonservice.SOCKS5Endpoint{{
		Region: "cn", Address: "10.0.1.1", Port: 1080,
	}}}
	service, err := commonServiceIntent(request)
	if err != nil {
		t.Fatalf("commonServiceIntent: %v", err)
	}
	typed, ok := service.(corestate.PublishSOCKS5Intent)
	if !ok || len(typed.Endpoints) != 1 {
		t.Fatalf("service intent = %#v", service)
	}
	request.Endpoints[0].Address = "mutated"
	if typed.Endpoints[0].Address != "10.0.1.1" {
		t.Fatal("service intent retained control request endpoints")
	}
}

func TestApplyCommonLocalIntentPreviewAndCommit(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	legacy, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	candidate, _, err := projectLegacyCommonState(legacy, rt.Config.TrustedRootPublicKey)
	if err != nil {
		t.Fatalf("projectLegacyCommonState: %v", err)
	}
	store := corestate.NewStoreWithCheckpoint(candidate.Verified, candidate.Gossip, nil)
	intent := corestate.PutRecordIntent{
		Zone: managed, Key: "apps/adapter", Type: "application.test", Value: []byte("value"),
	}
	preview, err := applyCommonLocalIntent(context.Background(), store, intent, true, time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("applyCommonLocalIntent(preview): %v", err)
	}
	if !preview.DryRun || preview.Version != 1 || store.ReadView().Revision != 0 {
		t.Fatalf("preview/revision = %+v/%d", preview, store.ReadView().Revision)
	}
	committed, err := applyCommonLocalIntent(context.Background(), store, intent, false, time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("applyCommonLocalIntent(commit): %v", err)
	}
	if committed.DryRun || committed.Version != 1 || store.ReadView().Revision != 1 || committed.Zone != zone.ZonePath(managed) {
		t.Fatalf("commit/revision = %+v/%d", committed, store.ReadView().Revision)
	}
}

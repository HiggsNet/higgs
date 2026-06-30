package main

import (
	"errors"
	"testing"
)

func TestShouldIgnorePartialReplan(t *testing.T) {
	reconcile := &ipsecReconcileState{
		DesiredLinks: 4,
		Desired:      []desiredLinkState{{InstanceID: "a"}, {InstanceID: "b"}, {InstanceID: "c"}, {InstanceID: "d"}},
	}
	if !shouldIgnorePartialReplan(reconcile, 1, nil) {
		t.Fatal("partial replan was not ignored")
	}
	if shouldIgnorePartialReplan(reconcile, 4, nil) {
		t.Fatal("complete replan was ignored")
	}
	if shouldIgnorePartialReplan(nil, 1, nil) {
		t.Fatal("replan without a last reconcile snapshot was ignored")
	}
	if !shouldIgnorePartialReplan(reconcile, 0, errors.New("planner failed")) {
		t.Fatal("planner error was not ignored")
	}
}

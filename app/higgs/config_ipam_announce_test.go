package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseIPAMAnnounceSelectors(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML(`
ipam:
  announce:
    - non-shared
    - tag:edge.c
    - assignment:10.0.1.7/24
`, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	want := []string{"non-shared", "tag:edge.c", "assignment:10.0.1.0/24"}
	if !reflect.DeepEqual(config.IPAM.Announce, want) {
		t.Fatalf("announce = %#v, want %#v", config.IPAM.Announce, want)
	}
	if config.IPAM.AutoAnnounceAssignedIPs {
		t.Fatal("legacy auto announce unexpectedly enabled")
	}
}

func TestParseIPAMAnnounceRejectsLegacyConflictAndInvalidSelector(t *testing.T) {
	for _, input := range []string{
		"ipam:\n  auto_announce_assigned_ips: true\n  announce: [non-shared]\n",
		"ipam:\n  announce: [tag:BadTag]\n",
		"ipam:\n  announce: [unknown]\n",
	} {
		config := defaultAppConfig()
		if err := parseConfigYAML(input, config); err == nil || !strings.Contains(err.Error(), "ipam") {
			t.Fatalf("parseConfigYAML(%q) error = %v", input, err)
		}
	}
}

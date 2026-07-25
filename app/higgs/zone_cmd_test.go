package main

import (
	"testing"

	"github.com/urfave/cli/v3"
)

func TestHumanZoneAndRecordCommandsOwnOperatorViews(t *testing.T) {
	root := rootCommand()
	if commandByName(root.Commands, "records") != nil {
		t.Fatal("root command unexpectedly exposes plural records")
	}
	if commandByName(root.Commands, "db") != nil {
		t.Fatal("root command unexpectedly exposes low-level db")
	}

	zoneCommand := commandByName(root.Commands, "zone")
	show := commandByName(zoneCommand.Commands, "show")
	requireCommandFlags(t, show, "filter", "verbose")
	if commandFlagByName(show, "history") != nil {
		t.Fatal("zone show still exposes diagnostic history")
	}

	recordCommand := commandByName(root.Commands, "record")
	list := commandByName(recordCommand.Commands, "list")
	requireCommandFlags(t, list, "filter", "verbose")
	get := commandByName(recordCommand.Commands, "get")
	requireCommandFlags(t, get, "verbose")
	if commandFlagByName(get, "history") != nil {
		t.Fatal("record get still exposes diagnostic history")
	}

	debug := commandByName(root.Commands, "debug")
	debugZone := commandByName(debug.Commands, "zone")
	requireCommandFlags(t, debugZone, "json", "history")
	debugRecord := commandByName(debug.Commands, "record")
	requireCommandFlags(t, debugRecord, "history")
	if commandByName(debug.Commands, "db") == nil {
		t.Fatal("debug command does not expose db")
	}
}

func commandFlagByName(command *cli.Command, name string) cli.Flag {
	if command == nil {
		return nil
	}
	for _, flag := range command.Flags {
		for _, flagName := range flag.Names() {
			if flagName == name {
				return flag
			}
		}
	}
	return nil
}

func requireCommandFlags(t *testing.T, command *cli.Command, names ...string) {
	t.Helper()
	if command == nil {
		t.Fatal("command is nil")
	}
	for _, name := range names {
		if commandFlagByName(command, name) == nil {
			t.Errorf("command %s missing flag %s", command.Name, name)
		}
	}
}

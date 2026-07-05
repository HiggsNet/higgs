package main

import (
	"fmt"
	"io"
)

var (
	buildCommit   = "unknown"
	buildDescribe = "unknown"
	buildDirty    = "unknown"
	buildTime     = "unknown"
)

func buildInfoFields() map[string]any {
	return map[string]any{
		"build_commit":   buildCommit,
		"build_describe": buildDescribe,
		"build_dirty":    buildDirty,
		"build_time":     buildTime,
	}
}

func writeVersion(w io.Writer) error {
	_, err := fmt.Fprintf(w, "higgs %s\ncommit: %s\ndirty: %s\nbuilt_at: %s\n", buildDescribe, buildCommit, buildDirty, buildTime)
	return err
}

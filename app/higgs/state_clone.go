package main

import (
	"encoding/json"
	"fmt"
)

func cloneStateFile(s *stateFile) *stateFile {
	if s == nil {
		return nil
	}
	// Callers must already own the appropriate state lock, or pass an immutable
	// snapshot/workspace that cannot be mutated concurrently.
	data, err := json.Marshal(s)
	if err != nil {
		panic(fmt.Sprintf("clone state file marshal: %v", err))
	}
	var out stateFile
	if err := json.Unmarshal(data, &out); err != nil {
		panic(fmt.Sprintf("clone state file unmarshal: %v", err))
	}
	if out.Network != nil {
		configureValidation(out.Network)
	}
	return &out
}

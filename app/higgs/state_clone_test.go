package main

import "encoding/json"

func cloneStateFile(s *stateFile) *stateFile {
	if s == nil {
		return nil
	}
	data, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	var out stateFile
	if err := json.Unmarshal(data, &out); err != nil {
		panic(err)
	}
	return &out
}

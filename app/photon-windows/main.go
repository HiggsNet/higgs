package main

import (
	"fmt"
	"io"
	"os"
)

var (
	buildCommit   = "unknown"
	buildDescribe = "unknown"
	buildDirty    = "unknown"
	buildTime     = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "photon-windows version accepts no arguments")
			return 2
		}
		fmt.Fprintf(stdout, "photon-windows %s\ncommit: %s\ndirty: %s\nbuilt_at: %s\n", buildDescribe, buildCommit, buildDirty, buildTime)
		return 0
	case "help", "--help", "-h":
		writeUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown photon-windows command %q\n", args[0])
		writeUsage(stderr)
		return 2
	}
}

func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: photon-windows <command>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  version  Show build information")
	fmt.Fprintln(w, "  help     Show this help")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "The Wintun/service runtime is being implemented and is not advertised as ready yet.")
}

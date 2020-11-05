package main

import (
	"fmt"
	"os"
	"runtime"
)

// CompileTime constants
var version = "undefined"
var date = "undefined"
var commit = "undefined"

func init() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("Version %q (%s-%s) build at %s\n", version, commit, runtime.Version(), date)
		os.Exit(0)
	}
}

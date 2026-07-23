package main

import (
	"runtime/debug"
	"strings"
)

// Version is the extension's released version. Precedence mirrors
// cmd/beagle (which this module cannot import):
//
//  1. -ldflags "-X main.Version=..." set at build time (goreleaser).
//  2. The module version recorded in the binary's build info.
//  3. The compiled-in default, which tracks the repo's VERSION file.
var Version = ""

func currentVersion() string {
	const fileDefault = "0.1.1"
	if v := strings.TrimSpace(Version); v != "" {
		return v
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return fileDefault
	}
	v := strings.TrimSpace(bi.Main.Version)
	if v == "" || v == "(devel)" {
		return fileDefault
	}
	return v
}

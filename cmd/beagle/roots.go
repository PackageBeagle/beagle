// Profile-aware scan root resolution — delegates to internal/roots.
package main

import (
	"os"
	"strings"

	"github.com/packagebeagle/beagle/internal/roots"
	"github.com/packagebeagle/beagle/internal/scanner"
)

// rootsOpts groups the scoping inputs to resolveRoots.
type rootsOpts struct {
	AllUsers bool
}

func resolveRoots(profile string, explicit []string, opts rootsOpts) ([]scanner.Root, []string, error) {
	return roots.Resolve(profile, explicit, roots.Opts{
		AllUsers:         opts.AllUsers,
		UsersDirOverride: usersDirOverride(),
	})
}

func usersDirOverride() string {
	return strings.TrimSpace(os.Getenv("BEAGLE_USERS_DIR"))
}

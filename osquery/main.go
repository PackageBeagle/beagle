// Command beagle.ext is the beagle osquery extension. It registers the
// beagle_packages table; each query runs (or serves from cache) one
// scan of the constrained profile/roots.
//
// osquery controls the extension's argv when it loads extensions: it
// passes --socket, --timeout, --interval, and --verbose (when osquery
// itself runs verbose) — nothing else. All four are defined here
// because stdlib flag exits on unknown flags. Beagle-specific knobs
// therefore travel as BEAGLE_* environment variables (design decision
// D4), set on the process that launches osqueryd.
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/osquery/osquery-go"
	osqtable "github.com/osquery/osquery-go/plugin/table"

	"github.com/packagebeagle/beagle/internal/roots"
	beagletable "github.com/packagebeagle/beagle/osquery/table"
)

type knobs struct {
	CacheTTL time.Duration // BEAGLE_CACHE_TTL, default 60s; 0 disables caching
	// MaxDurationOverride is BEAGLE_MAX_DURATION. Default 0 ("unset"):
	// scanBudget applies the per-profile default (baseline 30s, project
	// 60s, deep 120s) instead. When set, it overrides every profile.
	MaxDurationOverride time.Duration
	AllUsers            bool   // BEAGLE_ALL_USERS
	UsersDir            string // BEAGLE_USERS_DIR
	DeviceIDEnv         string // BEAGLE_DEVICE_ID_ENV: name of the env var holding the device id
}

func knobsFromEnv(lookup func(string) (string, bool)) (knobs, error) {
	k := knobs{
		CacheTTL: 60 * time.Second,
	}
	if raw, ok := lookup("BEAGLE_CACHE_TTL"); ok {
		d, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil || d < 0 {
			return knobs{}, fmt.Errorf("BEAGLE_CACHE_TTL=%q is not a valid duration (want e.g. \"60s\", \"5m\", or \"0\" to disable caching)", raw)
		}
		k.CacheTTL = d
	}
	if raw, ok := lookup("BEAGLE_MAX_DURATION"); ok {
		d, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil || d <= 0 {
			return knobs{}, fmt.Errorf("BEAGLE_MAX_DURATION=%q is not a valid positive duration (want e.g. \"30s\", \"2m\")", raw)
		}
		k.MaxDurationOverride = d
	}
	if raw, ok := lookup("BEAGLE_ALL_USERS"); ok {
		b, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return knobs{}, fmt.Errorf("BEAGLE_ALL_USERS=%q is not a valid boolean (want \"1\"/\"true\" or \"0\"/\"false\")", raw)
		}
		k.AllUsers = b
	}
	if raw, ok := lookup("BEAGLE_USERS_DIR"); ok {
		k.UsersDir = strings.TrimSpace(raw)
	}
	if raw, ok := lookup("BEAGLE_DEVICE_ID_ENV"); ok {
		k.DeviceIDEnv = strings.TrimSpace(raw)
	}
	return k, nil
}

// resolveDeviceID mirrors the CLI's --device-id-env behavior: the knob
// names an env var, never carries a literal id. Missing/empty values
// warn and proceed rather than fail — externally-supplied attributes
// can lag behind deployment, and dying here would cost every other
// signal the table carries.
func resolveDeviceID(envName string) (id, warning string) {
	if envName == "" {
		return "", ""
	}
	raw, ok := os.LookupEnv(envName)
	if !ok {
		return "", fmt.Sprintf("BEAGLE_DEVICE_ID_ENV=%q is not set in the environment; proceeding without endpoint.device_id", envName)
	}
	id = strings.TrimSpace(raw)
	if id == "" {
		return "", fmt.Sprintf("BEAGLE_DEVICE_ID_ENV=%q is set but empty/whitespace; proceeding without endpoint.device_id", envName)
	}
	return id, ""
}

func main() {
	socket := flag.String("socket", "", "path to the osquery extensions socket")
	timeout := flag.Int("timeout", 3, "seconds to wait for the extensions socket")
	interval := flag.Int("interval", 3, "seconds between osquery connectivity checks")
	flag.Bool("verbose", false, "accepted for osquery compatibility; diagnostics always go to stderr")
	flag.Parse()

	if *socket == "" {
		fmt.Fprintln(os.Stderr, "beagle.ext: --socket is required (osquery passes it when loading the extension)")
		os.Exit(2)
	}

	k, err := knobsFromEnv(os.LookupEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "beagle.ext: %v\n", err)
		os.Exit(2)
	}
	deviceID, warn := resolveDeviceID(k.DeviceIDEnv)
	if warn != "" {
		fmt.Fprintf(os.Stderr, "beagle.ext: %s\n", warn)
	}

	bridge := newScanBridge(bridgeConfig{
		RootsOpts:           roots.Opts{AllUsers: k.AllUsers, UsersDirOverride: k.UsersDir},
		DeviceID:            deviceID,
		MaxDurationOverride: k.MaxDurationOverride,
		CacheTTL:            k.CacheTTL,
		Diags:               os.Stderr,
	})

	server, err := osquery.NewExtensionManagerServer(
		"beagle",
		*socket,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
		osquery.ServerPingInterval(time.Duration(*interval)*time.Second),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "beagle.ext: create extension server: %v\n", err)
		os.Exit(1)
	}
	server.RegisterPlugin(osqtable.NewPlugin("beagle_packages", beagletable.Columns(), beagletable.Generate(bridge.Scan)))
	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "beagle.ext: %v\n", err)
		os.Exit(1)
	}
}

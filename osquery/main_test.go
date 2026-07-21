package main

import (
	"strings"
	"testing"
	"time"
)

func lookupFrom(m map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := m[key]
		return v, ok
	}
}

func TestKnobsFromEnvDefaults(t *testing.T) {
	k, err := knobsFromEnv(lookupFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := knobs{CacheTTL: 60 * time.Second}
	if k != want {
		t.Fatalf("knobs = %+v, want %+v", k, want)
	}
}

func TestKnobsFromEnvEachKnobParsed(t *testing.T) {
	k, err := knobsFromEnv(lookupFrom(map[string]string{
		"BEAGLE_CACHE_TTL":     "5m",
		"BEAGLE_MAX_DURATION":  "45s",
		"BEAGLE_ALL_USERS":     "true",
		"BEAGLE_USERS_DIR":     "/x/users",
		"BEAGLE_DEVICE_ID_ENV": "MY_DEVICE_ID",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := knobs{
		CacheTTL:            5 * time.Minute,
		MaxDurationOverride: 45 * time.Second,
		AllUsers:            true,
		UsersDir:            "/x/users",
		DeviceIDEnv:         "MY_DEVICE_ID",
	}
	if k != want {
		t.Fatalf("knobs = %+v, want %+v", k, want)
	}
}

func TestKnobsFromEnvInvalidValues(t *testing.T) {
	cases := []struct {
		name   string
		env    map[string]string
		wantIn string
	}{
		{"bad cache ttl", map[string]string{"BEAGLE_CACHE_TTL": "not-a-duration"}, "BEAGLE_CACHE_TTL"},
		{"negative cache ttl", map[string]string{"BEAGLE_CACHE_TTL": "-1s"}, "BEAGLE_CACHE_TTL"},
		{"bad max duration", map[string]string{"BEAGLE_MAX_DURATION": "not-a-duration"}, "BEAGLE_MAX_DURATION"},
		{"zero max duration", map[string]string{"BEAGLE_MAX_DURATION": "0s"}, "BEAGLE_MAX_DURATION"},
		{"negative max duration", map[string]string{"BEAGLE_MAX_DURATION": "-5s"}, "BEAGLE_MAX_DURATION"},
		{"bad all users bool", map[string]string{"BEAGLE_ALL_USERS": "not-a-bool"}, "BEAGLE_ALL_USERS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := knobsFromEnv(lookupFrom(c.env))
			if err == nil || !strings.Contains(err.Error(), c.wantIn) {
				t.Fatalf("err = %v, want error mentioning %q", err, c.wantIn)
			}
		})
	}
}

func TestResolveDeviceIDUnset(t *testing.T) {
	id, warn := resolveDeviceID("")
	if id != "" || warn != "" {
		t.Fatalf("id=%q warn=%q, want both empty", id, warn)
	}
}

func TestResolveDeviceIDEnvMissing(t *testing.T) {
	const envName = "BEAGLE_TEST_DEVICE_ID_ENV_DOES_NOT_EXIST"
	id, warn := resolveDeviceID(envName)
	if id != "" {
		t.Fatalf("id = %q, want empty", id)
	}
	if warn == "" || !strings.Contains(warn, envName) {
		t.Fatalf("warn = %q, want warning mentioning %q", warn, envName)
	}
}

func TestResolveDeviceIDTrimmed(t *testing.T) {
	const envName = "BEAGLE_TEST_DEVICE_ID_ENV"
	t.Setenv(envName, "  abc123  ")
	id, warn := resolveDeviceID(envName)
	if id != "abc123" {
		t.Fatalf("id = %q, want trimmed \"abc123\"", id)
	}
	if warn != "" {
		t.Fatalf("warn = %q, want empty", warn)
	}
}

func TestResolveDeviceIDEnvEmpty(t *testing.T) {
	const envName = "BEAGLE_TEST_DEVICE_ID_ENV_EMPTY"
	t.Setenv(envName, "   ")
	id, warn := resolveDeviceID(envName)
	if id != "" {
		t.Fatalf("id = %q, want empty", id)
	}
	if warn == "" || !strings.Contains(warn, envName) {
		t.Fatalf("warn = %q, want warning mentioning %q", warn, envName)
	}
}

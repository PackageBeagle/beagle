package endpoint

import (
	"runtime"
	"testing"
)

func TestCurrentPopulatesDeviceID(t *testing.T) {
	ep := Current("dev-1234")
	if ep.DeviceID != "dev-1234" {
		t.Fatalf("DeviceID = %q, want %q", ep.DeviceID, "dev-1234")
	}
	if ep.OS != runtime.GOOS {
		t.Fatalf("OS = %q, want %q", ep.OS, runtime.GOOS)
	}
	if ep.Arch != runtime.GOARCH {
		t.Fatalf("Arch = %q, want %q", ep.Arch, runtime.GOARCH)
	}
}

func TestCurrentEmptyDeviceID(t *testing.T) {
	ep := Current("")
	if ep.DeviceID != "" {
		t.Fatalf("DeviceID = %q, want empty", ep.DeviceID)
	}
}

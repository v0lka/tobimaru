package version

import (
	"strings"
	"testing"
)

func TestStringDefault(t *testing.T) {
	// Reset to defaults (in case ldflags injected values in test build).
	SetVersion("dev", "unknown", "unknown")

	s := String()
	if !strings.Contains(s, "Tobimaru vdev") {
		t.Errorf("got %s, want string containing 'Tobimaru vdev'", s)
	}
	if !strings.Contains(s, "commit: unknown") {
		t.Errorf("got %s, want string containing 'commit: unknown'", s)
	}
	if !strings.Contains(s, "built: unknown") {
		t.Errorf("got %s, want string containing 'built: unknown'", s)
	}
}

func TestStringRelease(t *testing.T) {
	SetVersion("1.0.0", "abc1234", "2026-05-27T10:00:00Z")

	s := String()
	expected := "Tobimaru v1.0.0 (commit: abc1234, built: 2026-05-27T10:00:00Z)"
	if s != expected {
		t.Errorf("got %q, want %q", s, expected)
	}

	// Reset for other tests.
	SetVersion("dev", "unknown", "unknown")
}

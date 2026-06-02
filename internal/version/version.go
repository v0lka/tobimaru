// Package version provides build version information injected via ldflags.
package version

import (
	"fmt"
	"sync"
)

// Build information, injected at build time via ldflags.
var (
	mu      sync.Mutex
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// SetVersion sets the build version info. Safe for concurrent use in tests.
func SetVersion(v, c, d string) {
	mu.Lock()
	defer mu.Unlock()
	Version, Commit, Date = v, c, d
}

// String returns a formatted version string.
func String() string {
	mu.Lock()
	defer mu.Unlock()
	return fmt.Sprintf("Tobimaru v%s (commit: %s, built: %s)", Version, Commit, Date)
}

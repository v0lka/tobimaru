// Package version provides build version information injected via ldflags.
package version

import "fmt"

// Build information, injected at build time via ldflags.
// These variables are set once at process startup via -X linker flags and
// MUST NOT be modified afterwards. The API server reads them concurrently
// in buildStatusResponse; any mutation after startup is a data race.
// SetVersion exists for tests only and is NOT safe for concurrent use.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// SetVersion sets the build version info. Test-only — not safe for concurrent
// use. Production code should rely on ldflags injection at link time.
func SetVersion(v, c, d string) {
	Version, Commit, Date = v, c, d
}

// String returns a formatted version string.
func String() string {
	return fmt.Sprintf("Tobimaru v%s (commit: %s, built: %s)", Version, Commit, Date)
}

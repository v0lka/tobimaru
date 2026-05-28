// Package version provides build version information injected via ldflags.
package version

import "fmt"

// Build information, injected at build time via ldflags.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a formatted version string.
func String() string {
	return fmt.Sprintf("Tobimaru v%s (commit: %s, built: %s)", Version, Commit, Date)
}

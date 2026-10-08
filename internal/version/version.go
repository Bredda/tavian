// Package version exposes the build version.
package version

import "runtime/debug"

// Version and Commit are set at build time:
//
//	go build -ldflags "-X github.com/bredda/tavian/internal/version.Version=1.2.3"
var (
	Version = "dev"
	Commit  = ""
)

// String returns the version, falling back to Go build info when no ldflags
// were provided (e.g. `go install`).
func String() string {
	v, c := Version, Commit
	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
		if c == "" {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" && len(s.Value) >= 7 {
					c = s.Value[:7]
				}
			}
		}
	}
	if c != "" {
		return v + " (" + c + ")"
	}
	return v
}

package version

import (
	"fmt"
	"runtime"
)

// These variables are meant to be overridden at build time via -ldflags, e.g.:
//
//	-X obfuskit/internal/version.Version=v1.2.3 \
//	-X obfuskit/internal/version.BuildDate=2025-08-09T00:00:00Z \
//	-X obfuskit/internal/version.GitCommit=abcdef1
var (
	Version   = "dev"
	BuildDate = "unknown"
	GitCommit = "unknown"
)

// BuildInfo contains version and build information
type BuildInfo struct {
	Version   string `json:"version"`
	BuildDate string `json:"build_date"`
	GitCommit string `json:"git_commit"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
	Compiler  string `json:"compiler"`
}

// GetBuildInfo returns comprehensive build information
func GetBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   Version,
		BuildDate: BuildDate,
		GitCommit: GitCommit,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Compiler:  runtime.Compiler,
	}
}

// GetVersionString returns a formatted version string
func GetVersionString() string {
	return fmt.Sprintf("ObfusKit v%s (built %s)", Version, BuildDate)
}

// GetDetailedVersionString returns comprehensive version information
func GetDetailedVersionString() string {
	info := GetBuildInfo()
	return fmt.Sprintf(`ObfusKit - Enterprise WAF Testing Platform
Version: %s
Build Date: %s
Git Commit: %s
Go Version: %s
Platform: %s
Compiler: %s`,
		info.Version,
		info.BuildDate,
		info.GitCommit,
		info.GoVersion,
		info.Platform,
		info.Compiler,
	)
}

// GetStartupBanner returns the application startup banner
func GetStartupBanner() string {
	return fmt.Sprintf(`
╔═══════════════════════════════════════════════════════════╗
║                    🛡️  OBFUSKIT v%s                     ║
║              Enterprise WAF Testing Platform              ║
║                                                           ║
║  🎯 Multi-Attack Testing    🚀 Parallel Processing       ║
║  🧠 WAF Intelligence       📊 Advanced Analytics         ║
║  🔧 Batch Operations       ⚡ 10x Performance Boost      ║
╚═══════════════════════════════════════════════════════════╝
`, Version)
}

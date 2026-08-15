package detect

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ionsec/trace/go/internal/catalog"
	"github.com/ionsec/trace/go/internal/model"
)

// categoryRisk is the baseline risk of a platform category, used when the
// platform has no entry in the curated shadow-AI table. Agents and dev tools
// hold terminal and network reach, so they outrank passive inference runtimes.
var categoryRisk = map[string]string{
	"agent":     "high",
	"devtool":   "high",
	"inference": "medium",
	"cloud":     "medium",
	"network":   "medium",
	"code":      "low",
}

// expandPath resolves the ~ prefix and Windows %VAR% references in a catalog
// path against the given home directory, returning "" when a referenced
// variable is unset.
func expandPath(raw, home string) string {
	p := raw
	if strings.HasPrefix(p, "~") {
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	for strings.Contains(p, "%") {
		start := strings.Index(p, "%")
		end := strings.Index(p[start+1:], "%")
		if end < 0 {
			break
		}
		name := p[start+1 : start+1+end]
		value := os.Getenv(name)
		if value == "" {
			switch strings.ToUpper(name) {
			case "USERPROFILE":
				value = home
			case "LOCALAPPDATA":
				value = filepath.Join(home, "AppData", "Local")
			case "APPDATA":
				value = filepath.Join(home, "AppData", "Roaming")
			default:
				return ""
			}
		}
		p = p[:start] + value + p[start+1+end+1:]
	}
	p = strings.TrimRight(p, "/\\")
	return filepath.Clean(p)
}

// osPaths returns the catalog paths that apply to the running OS.
func osPaths(p catalog.Platform) []string {
	switch runtime.GOOS {
	case "darwin":
		return p.MacOS
	case "windows":
		return p.Windows
	default:
		return p.Linux
	}
}

// platformRoots returns every existing artifact root for a catalog platform,
// across all user home directories on the endpoint.
func platformRoots(p catalog.Platform) []string {
	var roots []string
	seen := map[string]bool{}
	for _, home := range userHomes() {
		for _, raw := range osPaths(p) {
			cand := expandPath(raw, home)
			if cand == "" || seen[cand] {
				continue
			}
			if _, err := os.Stat(cand); err == nil {
				seen[cand] = true
				roots = append(roots, cand)
			}
		}
	}
	return roots
}

// secondaryRoots returns the platform's shared roots that exist on this host.
func secondaryRoots(p catalog.Platform) []string {
	var roots []string
	seen := map[string]bool{}
	for _, home := range userHomes() {
		for _, raw := range p.Secondary {
			cand := expandPath(raw, home)
			if cand == "" || seen[cand] {
				continue
			}
			if _, err := os.Stat(cand); err == nil {
				seen[cand] = true
				roots = append(roots, cand)
			}
		}
	}
	return roots
}

// userHomes returns every user home directory readable on this endpoint: the
// current user first, then any sibling homes under the platform's user root.
func userHomes() []string {
	var homes []string
	seen := map[string]bool{}
	add := func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		homes = append(homes, h)
	}

	if h, err := os.UserHomeDir(); err == nil {
		add(h)
	}

	var base string
	switch runtime.GOOS {
	case "darwin":
		base = "/Users"
	case "windows":
		base = filepath.Join(os.Getenv("SystemDrive"), "\\Users")
	default:
		base = "/home"
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return homes
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		switch e.Name() {
		case "Public", "Default", "Default User", "All Users", "Shared":
			continue
		}
		add(filepath.Join(base, e.Name()))
	}
	return homes
}

// discoverPlatforms detects every catalogued AI platform present on the
// endpoint by artifact root, process name or binary on PATH — the Go
// counterpart of the Python collectors' discover() methods.
func discoverPlatforms() []model.Detection {
	var found []model.Detection
	for _, p := range catalog.Platforms {
		// Presence is decided by artifact roots only, as in the Python
		// collectors: a process name like "chat" is far too generic to treat a
		// binary on PATH as evidence of the platform.
		roots := platformRoots(p)
		if len(roots) == 0 {
			continue
		}
		// Shared roots join the collection set only now that the platform is
		// confirmed present, so they never manufacture a detection.
		roots = append(roots, secondaryRoots(p)...)
		binary := findBinary(p.Processes)
		risk, ok := categoryRisk[p.Category]
		if !ok {
			risk = "low"
		}
		cfg := ""
		if len(roots) > 0 {
			cfg = roots[0]
		}
		found = append(found, model.Detection{
			Tool:       p.Name,
			Installed:  true,
			ConfigPath: cfg,
			Roots:      roots,
			Binary:     binary,
			Risk:       risk,
			Note:       platformNote(p),
			Category:   p.Category,
		})
	}
	return found
}

// platformNote describes what was found for a platform, including the service
// ports it is known to expose.
func platformNote(p catalog.Platform) string {
	note := p.Category + " platform artifacts present"
	if len(p.Ports) > 0 {
		ports := make([]string, 0, len(p.Ports))
		for _, port := range p.Ports {
			ports = append(ports, itoa(port))
		}
		note += " (service port " + strings.Join(ports, ", ") + ")"
	}
	return note
}

// itoa converts a small non-negative int to its decimal string.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

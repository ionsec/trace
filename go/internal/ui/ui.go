// Package ui provides terminal styling for the TRACE CLI.
//
// It is intentionally stdlib-only (no external deps) so the binary keeps
// cross-compiling cleanly for macOS, Linux, and Windows. All styling is
// ANSI SGR escape codes; it auto-disables itself when stdout is not a TTY.
package ui

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// ANSI SGR helpers
// ---------------------------------------------------------------------------

type Color struct{ code string }

var (
	// TRACE brand palette
	Red    = Color{"38;5;196"} // crimson base  #e63946 ~ 196
	RedBr  = Color{"38;5;203"} // bright crimson
	Orange = Color{"38;5;208"} // amber
	Yellow = Color{"38;5;220"} // warm yellow
	Green  = Color{"38;5;82"}  // live green
	GreenD = Color{"38;5;78"}  // dim green
	Cyan   = Color{"38;5;117"} // info blue
	Blue   = Color{"38;5;69"}  // agentic blue
	Purple = Color{"38;5;141"} // accent
	White  = Color{"38;5;231"} // bright white
	Gray   = Color{"38;5;244"} // dim text
	Dim    = Color{"38;5;240"} // muted
)

var (
	Bold      = "\x1b[1m"
	Underline = "\x1b[4m"
	Italic    = "\x1b[3m"
	Reset     = "\x1b[0m"
)

// C returns a colorized string (auto-disabled when not a TTY).
func (c Color) S(s string) string {
	if !IsTTY() {
		return s
	}
	return "\x1b[" + c.code + "m" + s + Reset
}

// Style applies a foreground color + bold together.
func Style(c Color, s string) string {
	if !IsTTY() {
		return s
	}
	return "\x1b[1m\x1b[" + c.code + "m" + s + Reset
}

// IsTTY reports whether stdout is an interactive terminal.
func IsTTY() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// ---------------------------------------------------------------------------
// Severity color mapping
// ---------------------------------------------------------------------------

// RiskColor maps a risk/severity string to a UI color.
func RiskColor(risk string) Color {
	switch risk {
	case "critical":
		return Red
	case "high":
		return Orange
	case "medium":
		return Yellow
	case "low":
		return Green
	default:
		return Gray
	}
}

// RiskGlyph returns a glyph for a risk level.
func RiskGlyph(risk string) string {
	switch risk {
	case "critical":
		return "!!"
	case "high":
		return "▲"
	case "medium":
		return "●"
	case "low":
		return "·"
	default:
		return "·"
	}
}

// ---------------------------------------------------------------------------
// System info
// ---------------------------------------------------------------------------

// OSName returns a friendly OS name for the current platform.
func OSName() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	default:
		return runtime.GOOS
	}
}

// Arch returns the CPU architecture string.
func Arch() string {
	switch runtime.GOARCH {
	case "arm64":
		return "arm64"
	case "amd64":
		return "x86_64"
	default:
		return runtime.GOARCH
	}
}

// Hostname returns the machine hostname (or "unknown").
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}

// Username returns the current user's username (or "unknown").
func Username() string {
	u, err := user.Current()
	if err != nil || u.Username == "" {
		return "unknown"
	}
	return u.Username
}

// Timestamp returns the current local time formatted for display.
func Timestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// SystemBanner prints a compact system-info block.
func SystemBanner() {
	fmt.Printf("  %s %s\n", Style(Cyan, "host:"), Gray.S(Hostname()))
	fmt.Printf("  %s %s\n", Style(Cyan, "user:"), Gray.S(Username()))
	fmt.Printf("  %s %s\n", Style(Cyan, "os:  "), Gray.S(OSName()+" ("+Arch()+")"))
	fmt.Printf("  %s %s\n", Style(Cyan, "time:"), Gray.S(Timestamp()+" local"))
}

// ---------------------------------------------------------------------------
// Boxes & separators
// ---------------------------------------------------------------------------

// Line prints a horizontal rule of the given width and color.
func Line(c Color, width int) {
	fmt.Println(c.S(strings.Repeat("─", width)))
}

// Header prints a centered header band.
func Header(title string, width int) {
	if width <= 0 {
		width = 68
	}
	pad := (width - 2 - len(title)) / 2
	if pad < 1 {
		pad = 1
	}
	top := "╭" + strings.Repeat("─", width-2) + "╮"
	mid := "│" + strings.Repeat(" ", pad) + Style(Red, title) + strings.Repeat(" ", width-2-pad-len(title)) + "│"
	bot := "╰" + strings.Repeat("─", width-2) + "╯"
	fmt.Println(Red.S(top))
	fmt.Println(Red.S(mid))
	fmt.Println(Red.S(bot))
}

// ---------------------------------------------------------------------------
// Spinner
// ---------------------------------------------------------------------------

// Spinner is a simple frame-animated spinner that prints to stderr so it
// doesn't pollute piped stdout. Call Stop() to clear the line.
type Spinner struct {
	frames []string
	idx    int
	msg    string
	stop   chan struct{}
	done   chan struct{}
}

// NewSpinner starts a spinner with the given message.
func NewSpinner(msg string) *Spinner {
	s := &Spinner{
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		msg:    msg,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go s.run()
	return s
}

func (s *Spinner) run() {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			return
		default:
			if IsTTY() {
				frame := s.frames[s.idx%len(s.frames)]
				fmt.Fprintf(os.Stderr, "\r\033[K%s %s %s", Cyan.S(frame), s.msg, Gray.S("..."))
				s.idx++
			}
			time.Sleep(90 * time.Millisecond)
		}
	}
}

// Stop clears the spinner line.
func (s *Spinner) Stop() {
	close(s.stop)
	<-s.done
	if IsTTY() {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
}

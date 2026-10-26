package ui

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestColorPassthroughWhenNotTTY(t *testing.T) {
	if IsTTY() {
		t.Skip("stdout is a TTY; passthrough assertion does not apply")
	}
	if got := Red.S("risk"); got != "risk" {
		t.Errorf("Red.S() = %q, want %q (no ANSI when not a TTY)", got, "risk")
	}
	if got := Style(Red, "risk"); got != "risk" {
		t.Errorf("Style() = %q, want %q (no ANSI when not a TTY)", got, "risk")
	}
}

func TestRiskColorMapping(t *testing.T) {
	cases := map[string]Color{
		"critical": Red,
		"high":     Orange,
		"medium":   Yellow,
		"low":      Green,
		"unknown":  Gray,
	}
	for in, want := range cases {
		if got := RiskColor(in); got != want {
			t.Errorf("RiskColor(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestRiskGlyphMapping(t *testing.T) {
	cases := map[string]string{
		"critical": "!!",
		"high":     "▲",
		"medium":   "●",
		"low":      "·",
		"unknown":  "·",
	}
	for in, want := range cases {
		if got := RiskGlyph(in); got != want {
			t.Errorf("RiskGlyph(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSystemIdentityHelpers(t *testing.T) {
	if OSName() == "" || Arch() == "" || Hostname() == "" || Username() == "" {
		t.Error("OSName/Arch/Hostname/Username must all be non-empty")
	}
	if OSName() == "darwin" || OSName() == "linux" || OSName() == "windows" {
		t.Errorf("OSName() should return a friendly name, got %q", OSName())
	}
}

func TestTimestampFormat(t *testing.T) {
	ts := Timestamp()
	if _, err := time.Parse("2006-01-02 15:04:05", ts); err != nil {
		t.Errorf("Timestamp() = %q does not match documented layout: %v", ts, err)
	}
}

func TestPrintHelpers(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	Line(Gray, 10)
	Header("TRACE", 24)
	SystemBanner()
	w.Close()
	os.Stdout = old
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, want := range []string{"─", "TRACE", "host:"} {
		if !strings.Contains(out, want) {
			t.Errorf("printed output missing %q:\n%s", want, out)
		}
	}
}

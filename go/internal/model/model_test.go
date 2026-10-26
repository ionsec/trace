package model

import "testing"

func TestRedactedShort(t *testing.T) {
	if got := (IOC{Value: "sk-abc123"}).Redacted(); got != "sk-abc123" {
		t.Errorf("Redacted() = %q, want %q", got, "sk-abc123")
	}
}

func TestRedactedAtLimit(t *testing.T) {
	v := "0123456789abcdefghijklmn" // exactly 24 chars
	if got := (IOC{Value: v}).Redacted(); got != v {
		t.Errorf("24-char value changed: %q", got)
	}
}

func TestRedactedLong(t *testing.T) {
	v := "0123456789abcdefghijklmnopqrstuvwxyz" // 36 chars
	got := (IOC{Value: v}).Redacted()
	want := "0123456789abcdefghij" + "..."
	if got != want {
		t.Errorf("Redacted() = %q, want %q", got, want)
	}
	if len(got) != 23 {
		t.Errorf("Redacted() length = %d, want 23", len(got))
	}
}

func TestCorrelationsNilTolerated(t *testing.T) {
	if got := (Analysis{}).Correlations(); got != nil {
		t.Errorf("Correlations() on zero Analysis = %v, want nil", got)
	}
}

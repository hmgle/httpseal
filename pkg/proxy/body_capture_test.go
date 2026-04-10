package proxy

import (
	"io"
	"strings"
	"testing"
)

func TestSpoolBodyCapturesPrefixAndReplaysFullBody(t *testing.T) {
	capture, err := spoolBody(io.NopCloser(strings.NewReader("abcdef")), 3)
	if err != nil {
		t.Fatalf("spool body: %v", err)
	}
	defer capture.Cleanup()

	if capture.size != 6 {
		t.Fatalf("expected full body size 6, got %d", capture.size)
	}
	if string(capture.captured) != "abc" {
		t.Fatalf("expected captured prefix %q, got %q", "abc", string(capture.captured))
	}
	if !capture.truncated {
		t.Fatal("expected capture to be marked truncated")
	}

	replayed, err := io.ReadAll(capture.Reader())
	if err != nil {
		t.Fatalf("read replayed body: %v", err)
	}
	if string(replayed) != "abcdef" {
		t.Fatalf("expected replayed body %q, got %q", "abcdef", string(replayed))
	}
}

func TestSpoolBodyUnlimitedCaptureKeepsWholeBody(t *testing.T) {
	capture, err := spoolBody(io.NopCloser(strings.NewReader("abcdef")), 0)
	if err != nil {
		t.Fatalf("spool body: %v", err)
	}
	defer capture.Cleanup()

	if capture.truncated {
		t.Fatal("expected unlimited capture not to truncate")
	}
	if string(capture.captured) != "abcdef" {
		t.Fatalf("expected complete captured body %q, got %q", "abcdef", string(capture.captured))
	}
}

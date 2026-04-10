package proxy

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpoolBodyKeepsSmallBodiesInMemory(t *testing.T) {
	withBodySpoolTestDir(t)

	capture, err := spoolBody(io.NopCloser(strings.NewReader("abcdef")), 3)
	if err != nil {
		t.Fatalf("spool body: %v", err)
	}
	defer capture.Cleanup()

	if capture.path != "" {
		t.Fatalf("expected small body to stay in memory, got spool file %q", capture.path)
	}
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

func TestSpoolBodySpillsLargeBodiesToDisk(t *testing.T) {
	withBodySpoolTestDir(t)

	largeBody := strings.Repeat("a", bodySpoolMemoryLimit+128)
	capture, err := spoolBody(io.NopCloser(strings.NewReader(largeBody)), 16)
	if err != nil {
		t.Fatalf("spool body: %v", err)
	}

	if capture.path == "" {
		t.Fatal("expected large body to spill to disk")
	}
	if _, err := os.Stat(capture.path); err != nil {
		t.Fatalf("expected spool file to exist: %v", err)
	}

	fullBody, err := capture.ReadAll()
	if err != nil {
		t.Fatalf("read full body: %v", err)
	}
	if string(fullBody) != largeBody {
		t.Fatal("expected spooled body to replay full content")
	}

	path := capture.path
	if err := capture.Cleanup(); err != nil {
		t.Fatalf("cleanup body capture: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected spool file to be removed, stat err=%v", err)
	}
}

func TestSpoolBodyUnlimitedCaptureKeepsWholeBody(t *testing.T) {
	withBodySpoolTestDir(t)

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

func TestCleanupStaleBodySpoolFilesRemovesOnlyExpiredFiles(t *testing.T) {
	dir := withBodySpoolTestDir(t)

	stalePath := filepath.Join(dir, bodySpoolFilePrefix+"stale")
	freshPath := filepath.Join(dir, bodySpoolFilePrefix+"fresh")
	otherPath := filepath.Join(dir, "keep-me")
	for _, path := range []string{stalePath, freshPath, otherPath} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("write test spool file %s: %v", path, err)
		}
	}

	staleTime := time.Now().Add(-bodySpoolCleanupAfter - time.Hour)
	freshTime := time.Now().Add(-time.Hour)
	if err := os.Chtimes(stalePath, staleTime, staleTime); err != nil {
		t.Fatalf("chtimes stale file: %v", err)
	}
	if err := os.Chtimes(freshPath, freshTime, freshTime); err != nil {
		t.Fatalf("chtimes fresh file: %v", err)
	}

	if err := cleanupStaleBodySpoolFiles(dir, time.Now()); err != nil {
		t.Fatalf("cleanup stale spool files: %v", err)
	}

	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Fatalf("expected stale spool file to be removed, stat err=%v", err)
	}
	if _, err := os.Stat(freshPath); err != nil {
		t.Fatalf("expected fresh spool file to remain: %v", err)
	}
	if _, err := os.Stat(otherPath); err != nil {
		t.Fatalf("expected unrelated file to remain: %v", err)
	}
}

func withBodySpoolTestDir(t *testing.T) string {
	t.Helper()

	oldDir := bodySpoolDir
	oldDone := bodySpoolCleanupDone
	oldNow := bodySpoolCleanupNowFunc

	dir := t.TempDir()
	bodySpoolDir = dir
	bodySpoolCleanupDone = false
	bodySpoolCleanupNowFunc = time.Now

	t.Cleanup(func() {
		bodySpoolDir = oldDir
		bodySpoolCleanupDone = oldDone
		bodySpoolCleanupNowFunc = oldNow
	})

	return dir
}

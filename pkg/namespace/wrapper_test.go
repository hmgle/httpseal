package namespace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type noopLogger struct{}

func (noopLogger) Debug(string, ...interface{}) {}
func (noopLogger) Info(string, ...interface{})  {}
func (noopLogger) Warn(string, ...interface{})  {}
func (noopLogger) Error(string, ...interface{}) {}

func TestPrepareEmptyHostsOnlyKeepsLocalhostEntries(t *testing.T) {
	tmpDir := t.TempDir()
	wrapper := &Wrapper{
		tempDir: tmpDir,
		logger:  noopLogger{},
	}

	if err := wrapper.prepareEmptyHosts(); err != nil {
		t.Fatalf("prepare empty hosts: %v", err)
	}

	hostsPath := filepath.Join(tmpDir, "hosts")
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("read hosts file: %v", err)
	}

	hostsText := string(content)
	if strings.Contains(hostsText, "httpbin.org") ||
		strings.Contains(hostsText, "api.github.com") ||
		strings.Contains(hostsText, "example.com") {
		t.Fatalf("hosts file should not contain external domains:\n%s", hostsText)
	}
	if !strings.Contains(hostsText, "127.0.0.1\tlocalhost") {
		t.Fatalf("hosts file should preserve localhost entry:\n%s", hostsText)
	}
}

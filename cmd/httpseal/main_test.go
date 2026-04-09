package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestLoadConfigFileFailsForInvalidDefaultConfig(t *testing.T) {
	oldConfigFile := configFile
	t.Cleanup(func() {
		configFile = oldConfigFile
	})

	configFile = ""

	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "httpseal")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.json")
	if err := os.WriteFile(configPath, []byte("{invalid"), 0644); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	oldXDG := os.Getenv("XDG_CONFIG_HOME")
	if err := os.Setenv("XDG_CONFIG_HOME", tmpDir); err != nil {
		t.Fatalf("set XDG_CONFIG_HOME: %v", err)
	}
	t.Cleanup(func() {
		if oldXDG == "" {
			os.Unsetenv("XDG_CONFIG_HOME")
			return
		}
		os.Setenv("XDG_CONFIG_HOME", oldXDG)
	})

	cmd := &cobra.Command{Use: "httpseal"}
	err := loadConfigFile(cmd)
	if err == nil {
		t.Fatal("expected invalid default config file to return an error")
	}
	if !strings.Contains(err.Error(), configPath) {
		t.Fatalf("expected error to mention config path, got %v", err)
	}
}

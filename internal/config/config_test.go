package config

import "testing"

func TestMergeWithFileConfigHonorsChangedFlags(t *testing.T) {
	cfg := &Config{
		EnableHTTP:         false,
		FileLogLevel:       LogLevelNone,
		DecompressResponse: true,
	}
	fileCfg := &FileConfig{
		EnableHTTP:         boolPtr(true),
		FileLogLevel:       stringPtr("verbose"),
		DecompressResponse: boolPtr(false),
	}

	cfg.MergeWithFileConfig(fileCfg, func(name string) bool {
		return name == "enable-http"
	})

	if cfg.EnableHTTP {
		t.Fatal("expected explicit CLI flag to keep enable_http disabled")
	}
	if cfg.FileLogLevel != LogLevelVerbose {
		t.Fatalf("expected file_log_level to apply, got %q", cfg.FileLogLevel)
	}
	if cfg.DecompressResponse {
		t.Fatal("expected decompress_response from file to disable decompression")
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

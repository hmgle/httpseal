package config

import "testing"

func TestMergeWithFileConfigHonorsChangedFlags(t *testing.T) {
	cfg := &Config{
		EnableHTTP:         false,
		FileLogLevel:       LogLevelNone,
		DecompressResponse: true,
		CaptureOnlyStatus:  204,
	}
	fileCfg := &FileConfig{
		EnableHTTP:         boolPtr(true),
		FileLogLevel:       stringPtr("verbose"),
		DecompressResponse: boolPtr(false),
		CaptureOnly:        boolPtr(true),
		CaptureOnlyStatus:  intPtr(202),
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
	if !cfg.CaptureOnly {
		t.Fatal("expected capture_only from file to enable capture-only mode")
	}
	if cfg.CaptureOnlyStatus != 202 {
		t.Fatalf("expected capture_only_status from file to apply, got %d", cfg.CaptureOnlyStatus)
	}
}

func TestMergeWithFileConfigMapsDeprecatedMaxBodySizeToLogBodyLimit(t *testing.T) {
	cfg := &Config{}
	fileCfg := &FileConfig{
		MaxBodySize: intPtr(512),
	}

	cfg.MergeWithFileConfig(fileCfg, nil)

	if cfg.LogBodyLimit != 512 {
		t.Fatalf("expected deprecated max_body_size to populate log body limit, got %d", cfg.LogBodyLimit)
	}
}

func TestMergeWithFileConfigPrefersExplicitLogBodyLimit(t *testing.T) {
	cfg := &Config{}
	fileCfg := &FileConfig{
		LogBodyLimit: intPtr(2048),
		MaxBodySize:  intPtr(512),
	}

	cfg.MergeWithFileConfig(fileCfg, nil)

	if cfg.LogBodyLimit != 2048 {
		t.Fatalf("expected log_body_limit to win over deprecated max_body_size, got %d", cfg.LogBodyLimit)
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

func intPtr(v int) *int {
	return &v
}

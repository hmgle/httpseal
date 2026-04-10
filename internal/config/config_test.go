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

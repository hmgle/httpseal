package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// OutputFormat represents different output formats
type OutputFormat string

const (
	FormatText OutputFormat = "text"
	FormatJSON OutputFormat = "json"
	FormatCSV  OutputFormat = "csv"
	FormatHAR  OutputFormat = "har"
)

// LogLevel represents different logging verbosity levels
type LogLevel string

const (
	LogLevelNone    LogLevel = "none"    // No traffic logging
	LogLevelMinimal LogLevel = "minimal" // Only basic request/response info
	LogLevelNormal  LogLevel = "normal"  // Headers and summary
	LogLevelVerbose LogLevel = "verbose" // Everything including full bodies
)

// Config holds the application configuration
type Config struct {
	// Network settings
	Verbose   bool
	DNSIP     string
	DNSPort   int
	ProxyPort int
	CADir     string
	KeepCA    bool // Keep CA directory after exit

	// HTTP traffic interception
	EnableHTTP bool // Enable HTTP traffic interception on port 80
	HTTPPort   int  // HTTP proxy port (default 80)

	// Connection settings
	ConnectionTimeout int // Client connection idle timeout in seconds (default 30)

	// SOCKS5 proxy settings
	SOCKS5Enabled  bool   // Enable SOCKS5 proxy for upstream connections
	SOCKS5Address  string // SOCKS5 proxy address (e.g., "127.0.0.1:1080")
	SOCKS5Username string // SOCKS5 username (optional)
	SOCKS5Password string // SOCKS5 password (optional)

	// Command execution
	Command     string
	CommandArgs []string

	// Traffic logging and output
	OutputFile          string       // File to save traffic logs
	OutputFormat        OutputFormat // Output format (text, json, csv)
	LogLevel            LogLevel     // Console traffic logging verbosity
	FileLogLevel        LogLevel     // File traffic logging verbosity (can be different from console)
	LogFile             string       // File to save system logs (separate from traffic)
	Quiet               bool         // Suppress console output
	MaxBodySize         int          // Maximum body size to log (bytes), 0 = unlimited
	FilterDomains       []string     // Only log these domains (empty = all)
	ExcludeContentTypes []string     // Exclude these content types

	// Wireshark integration
	EnableMirror bool // Enable HTTP mirror server for Wireshark analysis
	MirrorPort   int  // HTTP mirror server port
}

// FileConfig represents the configuration file structure with JSON tags
type FileConfig struct {
	// Network settings
	Verbose   *bool   `json:"verbose,omitempty"`
	DNSIP     *string `json:"dns_ip,omitempty"`
	DNSPort   *int    `json:"dns_port,omitempty"`
	ProxyPort *int    `json:"proxy_port,omitempty"`
	CADir     *string `json:"ca_dir,omitempty"`
	KeepCA    *bool   `json:"keep_ca,omitempty"`

	// HTTP traffic interception
	EnableHTTP *bool `json:"enable_http,omitempty"`
	HTTPPort   *int  `json:"http_port,omitempty"`

	// Connection settings
	ConnectionTimeout *int `json:"connection_timeout,omitempty"`

	// SOCKS5 proxy settings
	SOCKS5Enabled  *bool   `json:"socks5_enabled,omitempty"`
	SOCKS5Address  *string `json:"socks5_address,omitempty"`
	SOCKS5Username *string `json:"socks5_username,omitempty"`
	SOCKS5Password *string `json:"socks5_password,omitempty"`

	// Traffic logging and output
	OutputFile          *string    `json:"output_file,omitempty"`
	OutputFormat        *string    `json:"output_format,omitempty"`
	LogLevel            *string    `json:"log_level,omitempty"`
	FileLogLevel        *string    `json:"file_log_level,omitempty"`
	LogFile             *string    `json:"log_file,omitempty"`
	Quiet               *bool      `json:"quiet,omitempty"`
	MaxBodySize         *int       `json:"max_body_size,omitempty"`
	FilterDomains       *[]string  `json:"filter_domains,omitempty"`
	ExcludeContentTypes *[]string  `json:"exclude_content_types,omitempty"`

	// Wireshark integration
	EnableMirror *bool `json:"enable_mirror,omitempty"`
	MirrorPort   *int  `json:"mirror_port,omitempty"`
}

// GetConfigDir returns the configuration directory following XDG spec
func GetConfigDir() string {
	// Check XDG_CONFIG_HOME first
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "httpseal")
	}
	
	// Fallback to ~/.config/httpseal
	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, ".config", "httpseal")
	}
	
	// Final fallback to current directory
	return ".httpseal"
}

// GetDefaultConfigPath returns the default configuration file path
func GetDefaultConfigPath() string {
	return filepath.Join(GetConfigDir(), "config.json")
}

// LoadConfigFile loads configuration from a JSON file
func LoadConfigFile(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &FileConfig{}, nil // Return empty config if file doesn't exist
		}
		return nil, err
	}

	var config FileConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// MergeWithFileConfig merges file configuration with CLI configuration
// CLI parameters take precedence over file configuration
func (c *Config) MergeWithFileConfig(fileConfig *FileConfig) {
	// Network settings
	if fileConfig.Verbose != nil && !c.Verbose {
		c.Verbose = *fileConfig.Verbose
	}
	if fileConfig.DNSIP != nil && c.DNSIP == "127.0.53.1" {
		c.DNSIP = *fileConfig.DNSIP
	}
	if fileConfig.DNSPort != nil && c.DNSPort == 53 {
		c.DNSPort = *fileConfig.DNSPort
	}
	if fileConfig.ProxyPort != nil && c.ProxyPort == 443 {
		c.ProxyPort = *fileConfig.ProxyPort
	}
	if fileConfig.CADir != nil && c.CADir == "" {
		c.CADir = *fileConfig.CADir
	}
	if fileConfig.KeepCA != nil && !c.KeepCA {
		c.KeepCA = *fileConfig.KeepCA
	}

	// HTTP traffic interception
	if fileConfig.EnableHTTP != nil && !c.EnableHTTP {
		c.EnableHTTP = *fileConfig.EnableHTTP
	}
	if fileConfig.HTTPPort != nil && c.HTTPPort == 80 {
		c.HTTPPort = *fileConfig.HTTPPort
	}

	// Connection settings
	if fileConfig.ConnectionTimeout != nil && c.ConnectionTimeout == 30 {
		c.ConnectionTimeout = *fileConfig.ConnectionTimeout
	}

	// SOCKS5 proxy settings
	if fileConfig.SOCKS5Enabled != nil && !c.SOCKS5Enabled {
		c.SOCKS5Enabled = *fileConfig.SOCKS5Enabled
	}
	if fileConfig.SOCKS5Address != nil && c.SOCKS5Address == "127.0.0.1:1080" {
		c.SOCKS5Address = *fileConfig.SOCKS5Address
	}
	if fileConfig.SOCKS5Username != nil && c.SOCKS5Username == "" {
		c.SOCKS5Username = *fileConfig.SOCKS5Username
	}
	if fileConfig.SOCKS5Password != nil && c.SOCKS5Password == "" {
		c.SOCKS5Password = *fileConfig.SOCKS5Password
	}

	// Traffic logging and output
	if fileConfig.OutputFile != nil && c.OutputFile == "" {
		c.OutputFile = *fileConfig.OutputFile
	}
	if fileConfig.OutputFormat != nil && c.OutputFormat == FormatText {
		c.OutputFormat = OutputFormat(*fileConfig.OutputFormat)
	}
	if fileConfig.LogLevel != nil && c.LogLevel == LogLevelNormal {
		c.LogLevel = LogLevel(*fileConfig.LogLevel)
	}
	if fileConfig.FileLogLevel != nil && c.FileLogLevel == LogLevelNone {
		c.FileLogLevel = LogLevel(*fileConfig.FileLogLevel)
	}
	if fileConfig.LogFile != nil && c.LogFile == "" {
		c.LogFile = *fileConfig.LogFile
	}
	if fileConfig.Quiet != nil && !c.Quiet {
		c.Quiet = *fileConfig.Quiet
	}
	if fileConfig.MaxBodySize != nil && c.MaxBodySize == 0 {
		c.MaxBodySize = *fileConfig.MaxBodySize
	}
	if fileConfig.FilterDomains != nil && len(c.FilterDomains) == 0 {
		c.FilterDomains = *fileConfig.FilterDomains
	}
	if fileConfig.ExcludeContentTypes != nil && len(c.ExcludeContentTypes) == 0 {
		c.ExcludeContentTypes = *fileConfig.ExcludeContentTypes
	}

	// Wireshark integration
	if fileConfig.EnableMirror != nil && !c.EnableMirror {
		c.EnableMirror = *fileConfig.EnableMirror
	}
	if fileConfig.MirrorPort != nil && c.MirrorPort == 8080 {
		c.MirrorPort = *fileConfig.MirrorPort
	}
}

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
	LogLevelNone         LogLevel = "none"          // No traffic logging
	LogLevelMinimal      LogLevel = "minimal"       // Only basic request/response info
	LogLevelNormal       LogLevel = "normal"        // Headers and summary
	LogLevelVerbose      LogLevel = "verbose"       // Everything including text bodies
	LogLevelExtraVerbose LogLevel = "extra-verbose" // Everything including all bodies (text and binary)
)

// Config holds the application configuration
type Config struct {
	// Network settings
	Verbose      bool
	ExtraVerbose bool // Extra verbose mode (-vv)
	DNSIP        string
	DNSPort      int
	UpstreamDNS  string
	ProxyPort    int
	CADir        string
	KeepCA       bool // Keep CA directory after exit

	// HTTP traffic interception
	EnableHTTP bool // Enable HTTP traffic interception on port 80
	HTTPPort   int  // HTTP proxy port (default 80)

	// Connection settings
	ConnectionTimeout int // Client connection idle timeout in seconds (default 30)

	// SOCKS5 proxy settings
	SOCKS5Enabled              bool   // Enable SOCKS5 proxy for upstream connections
	SOCKS5Address              string // SOCKS5 proxy address (e.g., "127.0.0.1:1080")
	SOCKS5Username             string // SOCKS5 username (optional)
	SOCKS5Password             string // SOCKS5 password (optional)
	UpstreamCAFile             string // Additional CA bundle used when TLS to the upstream is verified
	UpstreamClientCert         string // Client certificate used for upstream mTLS
	UpstreamClientKey          string // Client private key used for upstream mTLS
	UpstreamServerName         string // Optional SNI/hostname override for upstream TLS
	UpstreamInsecureSkipVerify bool   // Skip upstream certificate verification

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
	CaptureBodyLimit    int          // Maximum body bytes to capture per message, 0 = unlimited
	LogBodyLimit        int          // Maximum captured body bytes to print/write, 0 = full captured body
	FilterDomains       []string     // Only log these domains (empty = all)
	ExcludeContentTypes []string     // Exclude these content types
	DecompressResponse  bool         // Decompress compressed response bodies for logging (default: true)

	// Wireshark integration
	EnableMirror bool // Enable HTTP mirror server for Wireshark analysis
	MirrorPort   int  // HTTP mirror server port
}

// FileConfig represents the configuration file structure with JSON tags
type FileConfig struct {
	// Network settings
	Verbose      *bool   `json:"verbose,omitempty"`
	ExtraVerbose *bool   `json:"extra_verbose,omitempty"`
	DNSIP        *string `json:"dns_ip,omitempty"`
	DNSPort      *int    `json:"dns_port,omitempty"`
	UpstreamDNS  *string `json:"upstream_dns,omitempty"`
	ProxyPort    *int    `json:"proxy_port,omitempty"`
	CADir        *string `json:"ca_dir,omitempty"`
	KeepCA       *bool   `json:"keep_ca,omitempty"`

	// HTTP traffic interception
	EnableHTTP *bool `json:"enable_http,omitempty"`
	HTTPPort   *int  `json:"http_port,omitempty"`

	// Connection settings
	ConnectionTimeout *int `json:"connection_timeout,omitempty"`

	// SOCKS5 proxy settings
	SOCKS5Enabled              *bool   `json:"socks5_enabled,omitempty"`
	SOCKS5Address              *string `json:"socks5_address,omitempty"`
	SOCKS5Username             *string `json:"socks5_username,omitempty"`
	SOCKS5Password             *string `json:"socks5_password,omitempty"`
	UpstreamCAFile             *string `json:"upstream_ca_file,omitempty"`
	UpstreamClientCert         *string `json:"upstream_client_cert,omitempty"`
	UpstreamClientKey          *string `json:"upstream_client_key,omitempty"`
	UpstreamServerName         *string `json:"upstream_server_name,omitempty"`
	UpstreamInsecureSkipVerify *bool   `json:"upstream_insecure_skip_verify,omitempty"`

	// Traffic logging and output
	OutputFile          *string   `json:"output_file,omitempty"`
	OutputFormat        *string   `json:"output_format,omitempty"`
	LogLevel            *string   `json:"log_level,omitempty"`
	FileLogLevel        *string   `json:"file_log_level,omitempty"`
	LogFile             *string   `json:"log_file,omitempty"`
	Quiet               *bool     `json:"quiet,omitempty"`
	CaptureBodyLimit    *int      `json:"capture_body_limit,omitempty"`
	LogBodyLimit        *int      `json:"log_body_limit,omitempty"`
	MaxBodySize         *int      `json:"max_body_size,omitempty"` // Deprecated alias for log_body_limit
	FilterDomains       *[]string `json:"filter_domains,omitempty"`
	ExcludeContentTypes *[]string `json:"exclude_content_types,omitempty"`
	DecompressResponse  *bool     `json:"decompress_response,omitempty"`

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

// GetDefaultCADir returns the default CA directory path following XDG spec
func GetDefaultCADir() string {
	return filepath.Join(GetConfigDir(), "ca")
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

// MergeWithFileConfig merges file configuration into Config.
// Explicitly changed CLI flags take precedence over file values.
func (c *Config) MergeWithFileConfig(fileConfig *FileConfig, isFlagChanged func(string) bool) {
	if fileConfig == nil {
		return
	}
	if isFlagChanged == nil {
		isFlagChanged = func(string) bool { return false }
	}

	applyBool := func(flagName string, src *bool, dst *bool) {
		if src != nil && !isFlagChanged(flagName) {
			*dst = *src
		}
	}
	applyInt := func(flagName string, src *int, dst *int) {
		if src != nil && !isFlagChanged(flagName) {
			*dst = *src
		}
	}
	applyString := func(flagName string, src *string, dst *string) {
		if src != nil && !isFlagChanged(flagName) {
			*dst = *src
		}
	}
	applyStringSlice := func(flagName string, src *[]string, dst *[]string) {
		if src != nil && !isFlagChanged(flagName) {
			*dst = append([]string(nil), (*src)...)
		}
	}

	// Network settings
	applyBool("verbose", fileConfig.Verbose, &c.Verbose)
	applyBool("verbose", fileConfig.ExtraVerbose, &c.ExtraVerbose)
	applyString("dns-ip", fileConfig.DNSIP, &c.DNSIP)
	applyInt("dns-port", fileConfig.DNSPort, &c.DNSPort)
	applyString("upstream-dns", fileConfig.UpstreamDNS, &c.UpstreamDNS)
	applyInt("proxy-port", fileConfig.ProxyPort, &c.ProxyPort)
	applyString("ca-dir", fileConfig.CADir, &c.CADir)
	applyBool("keep-ca", fileConfig.KeepCA, &c.KeepCA)

	// HTTP traffic interception
	applyBool("enable-http", fileConfig.EnableHTTP, &c.EnableHTTP)
	applyInt("http-port", fileConfig.HTTPPort, &c.HTTPPort)

	// Connection settings
	applyInt("connection-timeout", fileConfig.ConnectionTimeout, &c.ConnectionTimeout)

	// SOCKS5 proxy settings
	applyBool("socks5", fileConfig.SOCKS5Enabled, &c.SOCKS5Enabled)
	applyString("socks5-addr", fileConfig.SOCKS5Address, &c.SOCKS5Address)
	applyString("socks5-user", fileConfig.SOCKS5Username, &c.SOCKS5Username)
	applyString("socks5-pass", fileConfig.SOCKS5Password, &c.SOCKS5Password)
	applyString("upstream-ca-file", fileConfig.UpstreamCAFile, &c.UpstreamCAFile)
	applyString("upstream-client-cert", fileConfig.UpstreamClientCert, &c.UpstreamClientCert)
	applyString("upstream-client-key", fileConfig.UpstreamClientKey, &c.UpstreamClientKey)
	applyString("upstream-server-name", fileConfig.UpstreamServerName, &c.UpstreamServerName)
	applyBool("upstream-insecure-skip-verify", fileConfig.UpstreamInsecureSkipVerify, &c.UpstreamInsecureSkipVerify)

	// Traffic logging and output
	applyString("output", fileConfig.OutputFile, &c.OutputFile)
	if fileConfig.OutputFormat != nil && !isFlagChanged("format") {
		c.OutputFormat = OutputFormat(*fileConfig.OutputFormat)
	}
	if fileConfig.LogLevel != nil && !isFlagChanged("log-level") {
		c.LogLevel = LogLevel(*fileConfig.LogLevel)
	}
	if fileConfig.FileLogLevel != nil && !isFlagChanged("file-log-level") {
		c.FileLogLevel = LogLevel(*fileConfig.FileLogLevel)
	}
	applyString("log-file", fileConfig.LogFile, &c.LogFile)
	applyBool("quiet", fileConfig.Quiet, &c.Quiet)
	applyInt("capture-body-limit", fileConfig.CaptureBodyLimit, &c.CaptureBodyLimit)
	if fileConfig.LogBodyLimit != nil && !isFlagChanged("log-body-limit") && !isFlagChanged("max-body-size") {
		c.LogBodyLimit = *fileConfig.LogBodyLimit
	} else {
		applyInt("max-body-size", fileConfig.MaxBodySize, &c.LogBodyLimit)
	}
	applyStringSlice("filter-domain", fileConfig.FilterDomains, &c.FilterDomains)
	applyStringSlice(
		"exclude-content-type",
		fileConfig.ExcludeContentTypes,
		&c.ExcludeContentTypes,
	)
	applyBool(
		"decompress-response",
		fileConfig.DecompressResponse,
		&c.DecompressResponse,
	)

	// Wireshark integration
	applyBool("enable-mirror", fileConfig.EnableMirror, &c.EnableMirror)
	applyInt("mirror-port", fileConfig.MirrorPort, &c.MirrorPort)
}

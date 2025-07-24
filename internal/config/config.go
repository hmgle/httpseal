package config

// OutputFormat represents different output formats
type OutputFormat string

const (
	FormatText OutputFormat = "text"
	FormatJSON OutputFormat = "json"
	FormatCSV  OutputFormat = "csv"
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
	Verbose     bool
	DNSIP       string
	DNSPort     int
	ProxyPort   int
	CADir       string
	KeepCA      bool         // Keep CA directory after exit
	
	// HTTP traffic interception
	EnableHTTP  bool         // Enable HTTP traffic interception on port 80
	HTTPPort    int          // HTTP proxy port (default 80)
	
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
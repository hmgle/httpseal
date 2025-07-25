package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hmgle/httpseal/internal/config"
	"github.com/hmgle/httpseal/pkg/cert"
	"github.com/hmgle/httpseal/pkg/dns"
	"github.com/hmgle/httpseal/pkg/logger"
	"github.com/hmgle/httpseal/pkg/mirror"
	"github.com/hmgle/httpseal/pkg/namespace"
	"github.com/hmgle/httpseal/pkg/proxy"
	"github.com/spf13/cobra"
)

const (
	version = "0.1.0"
)

var (
	// Network settings
	verbose      bool
	extraVerbose bool
	dnsIP     string
	dnsPort   int
	proxyPort int
	caDir     string
	keepCA    bool

	// HTTP traffic interception
	enableHTTP bool
	httpPort   int

	// Connection settings
	connectionTimeout int

	// SOCKS5 proxy settings
	socks5Enabled  bool
	socks5Address  string
	socks5Username string
	socks5Password string

	// Traffic logging and output
	outputFile          string
	outputFormat        string
	logLevel            string
	fileLogLevel        string
	logFile             string
	quiet               bool
	maxBodySize         int
	filterDomains       []string
	excludeContentTypes []string

	// Wireshark integration
	enableMirror bool
	mirrorPort   int

	// Configuration file
	configFile string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "httpseal [flags] -- <command> [args...]",
		Short: "HTTPSeal - Process-specific HTTPS traffic interceptor",
		Long: `HTTPSeal intercepts and analyzes HTTPS traffic from specific processes
using Linux namespaces and DNS hijacking. Unlike global proxy tools,
HTTPSeal only affects processes it launches, providing precise and
isolated traffic monitoring.

HTTPSeal name combines "HTTPS" with "Seal" - representing the secure
encapsulation and isolation of process traffic within a controlled environment.

Examples:
  # Basic usage - show traffic in console
  httpseal -- wget https://api.github.com/users/octocat
  
  # Verbose mode with all traffic details
  httpseal -v -- curl -v https://httpbin.org/get
  
  # Extra verbose mode - shows all response bodies including binary content
  httpseal -V -- curl https://httpbin.org/get
  
  # Save traffic to file with complete data (auto-enables verbose for file)
  httpseal -o traffic.json --format json -- wget https://baidu.com
  
  # Quiet mode - only save to file, no console output
  httpseal -q -o traffic.log -- curl https://api.github.com/repos/golang/go
  
  # Different console and file logging levels
  httpseal --log-level minimal --file-log-level verbose -o detailed.txt -- curl https://httpbin.org/get
  
  # Save system logs to separate file
  httpseal --log-file system.log -o traffic.csv --format csv -- wget https://api.github.com/users/octocat
  
  # Filter specific domains and limit body size
  httpseal --filter-domain api.github.com --max-body-size 1024 -- curl https://api.github.com/users/octocat
  
  # CSV format with complete request/response data
  httpseal -o complete.csv --format csv -- wget https://httpbin.org/json
  
  # HAR format for browser dev tools and performance analysis
  httpseal -o traffic.har --format har -- curl https://api.github.com/users/octocat
  
  # Enable Wireshark integration - mirror HTTPS traffic as HTTP on port 8080
  httpseal --enable-mirror -- curl https://api.github.com/users/octocat
  
  # Custom mirror port for Wireshark analysis
  httpseal --enable-mirror --mirror-port 9090 -- wget https://httpbin.org/get
  
  # Keep CA directory for reuse (avoid regenerating certificates)
  httpseal --keep-ca -o traffic.json -- curl https://api.github.com/users/octocat
  
  # Use custom CA directory (will be preserved if --keep-ca is used)
  httpseal --ca-dir /path/to/ca --keep-ca -- wget https://httpbin.org/get
  
  # Use SOCKS5 proxy for upstream connections (useful in mainland China)
  httpseal --socks5-addr 127.0.0.1:1080 -- curl https://www.google.com
  
  # SOCKS5 proxy with authentication (auto-enabled when address is provided)
  httpseal --socks5-addr 127.0.0.1:1080 --socks5-user myuser --socks5-pass mypass -- wget https://github.com
  
  # Explicit SOCKS5 enable flag (uses default address 127.0.0.1:1080)
  httpseal --socks5 -- curl https://www.google.com`,
		Version: version,
		Args:    cobra.MinimumNArgs(1),
		RunE:    runHTTPSeal,
	}

	// Network settings
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().BoolVarP(&extraVerbose, "extra-verbose", "V", false, "Enable extra verbose output (includes all response bodies)")
	rootCmd.Flags().StringVar(&dnsIP, "dns-ip", "127.0.53.1", "DNS server IP address")
	rootCmd.Flags().IntVar(&dnsPort, "dns-port", 53, "DNS server port")
	rootCmd.Flags().IntVar(&proxyPort, "proxy-port", 443, "HTTPS proxy port")
	rootCmd.Flags().StringVar(&caDir, "ca-dir", "", "Certificate authority directory (default: XDG_CONFIG_HOME/httpseal/ca)")
	rootCmd.Flags().BoolVar(&keepCA, "keep-ca", false, "Keep CA directory after exit (always true for default persistent directory)")

	// HTTP traffic interception
	rootCmd.Flags().BoolVar(&enableHTTP, "enable-http", false, "Enable HTTP traffic interception (default: disabled)")
	rootCmd.Flags().IntVar(&httpPort, "http-port", 80, "HTTP proxy port")

	// Connection settings
	rootCmd.Flags().IntVar(&connectionTimeout, "connection-timeout", 30, "Client connection idle timeout in seconds")

	// SOCKS5 proxy settings
	rootCmd.Flags().BoolVar(&socks5Enabled, "socks5", false, "Enable SOCKS5 proxy with default address (127.0.0.1:1080)")
	rootCmd.Flags().StringVar(&socks5Address, "socks5-addr", "127.0.0.1:1080", "SOCKS5 proxy address (auto-enables SOCKS5 when specified)")
	rootCmd.Flags().StringVar(&socks5Username, "socks5-user", "", "SOCKS5 username for authentication (optional)")
	rootCmd.Flags().StringVar(&socks5Password, "socks5-pass", "", "SOCKS5 password for authentication (optional)")

	// Traffic logging and output
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output traffic to file (automatically uses verbose level for complete data)")
	rootCmd.Flags().StringVar(&outputFormat, "format", "text", "Output format: text, json, csv, har")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "normal", "Console logging level: none, minimal, normal, verbose")
	rootCmd.Flags().StringVar(&fileLogLevel, "file-log-level", "", "File logging level (defaults to verbose when -o is used): none, minimal, normal, verbose")
	rootCmd.Flags().StringVar(&logFile, "log-file", "", "Output system logs to file (separate from traffic data)")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress console output (quiet mode)")
	rootCmd.Flags().IntVar(&maxBodySize, "max-body-size", 0, "Maximum response body size to log (bytes, 0=unlimited)")
	rootCmd.Flags().StringSliceVar(&filterDomains, "filter-domain", []string{}, "Only log traffic for these domains (can be repeated)")
	rootCmd.Flags().StringSliceVar(&excludeContentTypes, "exclude-content-type", []string{}, "Exclude these content types from logging")

	// Wireshark integration
	rootCmd.Flags().BoolVar(&enableMirror, "enable-mirror", false, "Enable HTTP mirror server for Wireshark analysis")
	rootCmd.Flags().IntVar(&mirrorPort, "mirror-port", 8080, "HTTP mirror server port for Wireshark capture")

	// Configuration file
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "Configuration file path (default: XDG_CONFIG_HOME/httpseal/config.json)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runHTTPSeal(cmd *cobra.Command, args []string) error {
	// Handle -vv as shorthand for --extra-verbose
	if cmd.Flags().Changed("verbose") {
		// Count how many times -v was specified by checking if we got multiple calls
		if cmd.Flag("verbose").Value.String() == "true" {
			// Check if user wants double verbose by looking at the command line
			for _, arg := range os.Args {
				if arg == "-vv" || arg == "-vvv" {
					// Enable extra verbose for -vv or -vvv
					extraVerbose = true
					verbose = true
					break
				}
				// Also handle combined flags like -qvv
				if strings.Contains(arg, "vv") && strings.HasPrefix(arg, "-") {
					// Count v's in the flag
					vCount := strings.Count(arg, "v")
					if vCount >= 2 {
						extraVerbose = true
						verbose = true
						break
					}
				}
			}
		}
	}

	// Load configuration file
	if err := loadConfigFile(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Validate parameters
	if err := validateFlags(); err != nil {
		return err
	}

	// Determine effective file log level
	effectiveFileLogLevel := fileLogLevel
	if effectiveFileLogLevel == "" && outputFile != "" {
		// Auto-enable verbose level for file output to ensure complete data
		effectiveFileLogLevel = "verbose"
	}
	if effectiveFileLogLevel == "" {
		effectiveFileLogLevel = logLevel
	}

	// Auto-enable SOCKS5 if any SOCKS5 parameters are provided
	effectiveSocks5Enabled := socks5Enabled
	if !effectiveSocks5Enabled {
		// Check if user provided any SOCKS5-related parameters
		if cmd.Flags().Changed("socks5-addr") || cmd.Flags().Changed("socks5-user") || cmd.Flags().Changed("socks5-pass") {
			effectiveSocks5Enabled = true
		}
	}

	// Auto-upgrade log level if extra-verbose is enabled
	effectiveLogLevel := logLevel
	if extraVerbose && effectiveLogLevel == "normal" {
		effectiveLogLevel = "extra-verbose"
	} else if extraVerbose && effectiveLogLevel == "verbose" {
		effectiveLogLevel = "extra-verbose"
	}

	// Initialize configuration
	cfg := &config.Config{
		// Network settings
		Verbose:      verbose,
		ExtraVerbose: extraVerbose,
		DNSIP:     dnsIP,
		DNSPort:   dnsPort,
		ProxyPort: proxyPort,
		CADir:     caDir, // Will be updated below if temporary
		KeepCA:    keepCA,

		// HTTP traffic interception
		EnableHTTP: enableHTTP,
		HTTPPort:   httpPort,

		// Connection settings
		ConnectionTimeout: connectionTimeout,

		// SOCKS5 proxy settings
		SOCKS5Enabled:  effectiveSocks5Enabled,
		SOCKS5Address:  socks5Address,
		SOCKS5Username: socks5Username,
		SOCKS5Password: socks5Password,

		// Command execution
		Command:     args[0],
		CommandArgs: args[1:],

		// Traffic logging and output
		OutputFile:          outputFile,
		OutputFormat:        config.OutputFormat(outputFormat),
		LogLevel:            config.LogLevel(effectiveLogLevel),
		FileLogLevel:        config.LogLevel(effectiveFileLogLevel),
		LogFile:             logFile,
		Quiet:               quiet,
		MaxBodySize:         maxBodySize,
		FilterDomains:       filterDomains,
		ExcludeContentTypes: excludeContentTypes,

		// Wireshark integration
		EnableMirror: enableMirror,
		MirrorPort:   mirrorPort,
	}

	// Initialize enhanced logger first, as other components need it.
	log, err := logger.NewEnhanced(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer log.Close()

	// --- CA Directory Handling ---
	isTempCADir := false
	if cfg.CADir == "" {
		// Use XDG-compliant default CA directory for certificate persistence
		cfg.CADir = config.GetDefaultCADir()
		
		// Create directory if it doesn't exist
		if err := os.MkdirAll(cfg.CADir, 0755); err != nil {
			// Fallback to temporary directory if XDG path creation fails
			log.Warn("Failed to create default CA directory %s, using temporary directory: %v", cfg.CADir, err)
			tempDir, err := os.MkdirTemp("", "httpseal-ca-*")
			if err != nil {
				return fmt.Errorf("failed to create temporary CA directory: %w", err)
			}
			cfg.CADir = tempDir
			isTempCADir = true
		} else {
			log.Debug("Using persistent CA directory: %s", cfg.CADir)
		}
	}

	// Defer cleanup immediately after potential creation.
	// This ensures cleanup happens even if subsequent initializations fail.
	defer func() {
		if isTempCADir && !cfg.KeepCA {
			if err := os.RemoveAll(cfg.CADir); err != nil {
				log.Error("Failed to cleanup temporary CA directory: %v", err)
			} else {
				log.Info("Cleaned up temporary CA directory: %s", cfg.CADir)
			}
		}
	}()
	// --- End CA Directory Handling ---

	if !cfg.Quiet {
		log.Info("Starting HTTPSeal v%s", version)
	}

	// Initialize certificate authority
	ca, err := cert.NewCA(cfg.CADir, log)
	if err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	// Initialize DNS server
	dnsServer := dns.NewServer(cfg.DNSIP, cfg.DNSPort, log)

	// Initialize HTTP mirror server (if enabled)
	var mirrorServer *mirror.Server
	if cfg.EnableMirror {
		mirrorServer = mirror.NewServer(cfg.MirrorPort, log)
		if !cfg.Quiet {
			log.Info("HTTP Mirror Server enabled on port %d for Wireshark analysis", cfg.MirrorPort)
		}
	}

	// Initialize HTTPS proxy
	proxyServer := proxy.NewServer(cfg.ProxyPort, ca, dnsServer, log, mirrorServer, cfg)

	// Initialize HTTP proxy (if enabled)
	var httpProxyServer *proxy.Server
	if cfg.EnableHTTP {
		httpProxyServer = proxy.NewHTTPServer(cfg.HTTPPort, dnsServer, log, mirrorServer, cfg)
		if !cfg.Quiet {
			log.Info("HTTP proxy enabled on port %d", cfg.HTTPPort)
		}
	}

	// Log SOCKS5 proxy status
	if cfg.SOCKS5Enabled && !cfg.Quiet {
		if cfg.SOCKS5Username != "" {
			log.Info("SOCKS5 proxy enabled: %s (with authentication)", cfg.SOCKS5Address)
		} else {
			log.Info("SOCKS5 proxy enabled: %s (no authentication)", cfg.SOCKS5Address)
		}
	}

	// Start DNS server
	if err := dnsServer.Start(); err != nil {
		return fmt.Errorf("failed to start DNS server: %w", err)
	}
	defer dnsServer.Stop()

	// Start HTTP mirror server (if enabled)
	if mirrorServer != nil {
		if err := mirrorServer.Start(); err != nil {
			return fmt.Errorf("failed to start mirror server: %w", err)
		}
		defer mirrorServer.Stop()
	}

	// Start HTTPS proxy
	if err := proxyServer.Start(); err != nil {
		return fmt.Errorf("failed to start HTTPS proxy: %w", err)
	}
	defer proxyServer.Stop()

	// Start HTTP proxy (if enabled)
	if httpProxyServer != nil {
		if err := httpProxyServer.Start(); err != nil {
			return fmt.Errorf("failed to start HTTP proxy: %w", err)
		}
		defer httpProxyServer.Stop()
	}

	if cfg.EnableMirror && cfg.EnableHTTP {
		log.Info("Listening on 0.0.0.0:%d (HTTPS), 0.0.0.0:%d (HTTP), DNS on %s:%d, Mirror on 127.0.0.1:%d", cfg.ProxyPort, cfg.HTTPPort, cfg.DNSIP, cfg.DNSPort, cfg.MirrorPort)
	} else if cfg.EnableMirror {
		log.Info("Listening on 0.0.0.0:%d (HTTPS), DNS on %s:%d, Mirror on 127.0.0.1:%d", cfg.ProxyPort, cfg.DNSIP, cfg.DNSPort, cfg.MirrorPort)
	} else if cfg.EnableHTTP {
		log.Info("Listening on 0.0.0.0:%d (HTTPS), 0.0.0.0:%d (HTTP), DNS on %s:%d", cfg.ProxyPort, cfg.HTTPPort, cfg.DNSIP, cfg.DNSPort)
	} else {
		log.Info("Listening on 0.0.0.0:%d (HTTPS), DNS on %s:%d", cfg.ProxyPort, cfg.DNSIP, cfg.DNSPort)
	}

	// Create namespace wrapper and execute command
	nsWrapper := namespace.NewWrapper(cfg, log)
	processChan := make(chan error, 1)

	go func() {
		processChan <- nsWrapper.Execute()
	}()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for either process completion or signal
	select {
	case err := <-processChan:
		if err != nil {
			log.Error("Process execution failed: %v", err)
			return err
		}
		if !cfg.Quiet {
			log.Info("Process completed successfully")
		}
	case sig := <-sigChan:
		if !cfg.Quiet {
			log.Info("Received signal %v, shutting down...", sig)
		}
		// Signal the process to terminate.
		nsWrapper.Stop()
		// Wait for the process to actually exit. This is crucial.
		// The deferred server shutdowns will happen after this select block.
		<-processChan
		if !cfg.Quiet {
			log.Info("Process terminated, all servers shutting down.")
		}
	}

	return nil
}

// loadConfigFile loads configuration from file and merges with CLI flags
func loadConfigFile() error {
	// Determine config file path
	configPath := configFile
	if configPath == "" {
		configPath = config.GetDefaultConfigPath()
	}

	// Load configuration file
	fileConfig, err := config.LoadConfigFile(configPath)
	if err != nil {
		// Only return error if a specific config file was requested but failed to load
		if configFile != "" {
			return fmt.Errorf("failed to load config file %s: %w", configPath, err)
		}
		// If using default path and file doesn't exist, that's OK
		return nil
	}

	// Create temporary config to merge file settings
	tempConfig := &config.Config{
		// Set CLI values with their current state
		Verbose:             verbose,
		ExtraVerbose:        extraVerbose,
		DNSIP:               dnsIP,
		DNSPort:             dnsPort,
		ProxyPort:           proxyPort,
		CADir:               caDir,
		KeepCA:              keepCA,
		EnableHTTP:          enableHTTP,
		HTTPPort:            httpPort,
		ConnectionTimeout:   connectionTimeout,
		SOCKS5Enabled:       socks5Enabled,
		SOCKS5Address:       socks5Address,
		SOCKS5Username:      socks5Username,
		SOCKS5Password:      socks5Password,
		OutputFile:          outputFile,
		OutputFormat:        config.OutputFormat(outputFormat),
		LogLevel:            config.LogLevel(logLevel),
		FileLogLevel:        config.LogLevel(fileLogLevel),
		LogFile:             logFile,
		Quiet:               quiet,
		MaxBodySize:         maxBodySize,
		FilterDomains:       filterDomains,
		ExcludeContentTypes: excludeContentTypes,
		EnableMirror:        enableMirror,
		MirrorPort:          mirrorPort,
	}

	// Merge file config with CLI config (CLI takes precedence)
	tempConfig.MergeWithFileConfig(fileConfig)

	// Update global variables with merged values
	verbose = tempConfig.Verbose
	extraVerbose = tempConfig.ExtraVerbose
	dnsIP = tempConfig.DNSIP
	dnsPort = tempConfig.DNSPort
	proxyPort = tempConfig.ProxyPort
	caDir = tempConfig.CADir
	keepCA = tempConfig.KeepCA
	enableHTTP = tempConfig.EnableHTTP
	httpPort = tempConfig.HTTPPort
	connectionTimeout = tempConfig.ConnectionTimeout
	socks5Enabled = tempConfig.SOCKS5Enabled
	socks5Address = tempConfig.SOCKS5Address
	socks5Username = tempConfig.SOCKS5Username
	socks5Password = tempConfig.SOCKS5Password
	outputFile = tempConfig.OutputFile
	outputFormat = string(tempConfig.OutputFormat)
	logLevel = string(tempConfig.LogLevel)
	fileLogLevel = string(tempConfig.FileLogLevel)
	logFile = tempConfig.LogFile
	quiet = tempConfig.Quiet
	maxBodySize = tempConfig.MaxBodySize
	filterDomains = tempConfig.FilterDomains
	excludeContentTypes = tempConfig.ExcludeContentTypes
	enableMirror = tempConfig.EnableMirror
	mirrorPort = tempConfig.MirrorPort

	return nil
}

// validateFlags validates command line flags
func validateFlags() error {
	// Auto-enable verbose if extra-verbose is set
	if extraVerbose {
		verbose = true
	}

	// Validate output format
	validFormats := []string{"text", "json", "csv", "har"}
	valid := false
	for _, f := range validFormats {
		if outputFormat == f {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid output format '%s', must be one of: %s", outputFormat, strings.Join(validFormats, ", "))
	}

	// Validate log level
	validLevels := []string{"none", "minimal", "normal", "verbose", "extra-verbose"}
	valid = false
	for _, l := range validLevels {
		if logLevel == l {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid log level '%s', must be one of: %s", logLevel, strings.Join(validLevels, ", "))
	}

	// Validate file log level (if specified)
	if fileLogLevel != "" {
		valid = false
		for _, l := range validLevels {
			if fileLogLevel == l {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid file-log-level '%s', must be one of: %s", fileLogLevel, strings.Join(validLevels, ", "))
		}
	}

	// Validate max body size
	if maxBodySize < 0 {
		return fmt.Errorf("max-body-size must be >= 0")
	}

	// If quiet mode is enabled, require output file
	if quiet && outputFile == "" {
		return fmt.Errorf("quiet mode (-q) requires output file (-o)")
	}

	// Validate mirror port
	if mirrorPort < 1 || mirrorPort > 65535 {
		return fmt.Errorf("mirror-port must be between 1 and 65535")
	}

	// Check for port conflicts
	if enableMirror && mirrorPort == proxyPort {
		return fmt.Errorf("mirror-port cannot be the same as proxy-port")
	}
	if enableMirror && mirrorPort == dnsPort {
		return fmt.Errorf("mirror-port cannot be the same as dns-port")
	}
	if enableHTTP && httpPort == proxyPort {
		return fmt.Errorf("http-port cannot be the same as proxy-port")
	}
	if enableHTTP && httpPort == dnsPort {
		return fmt.Errorf("http-port cannot be the same as dns-port")
	}
	if enableHTTP && enableMirror && httpPort == mirrorPort {
		return fmt.Errorf("http-port cannot be the same as mirror-port")
	}

	return nil
}

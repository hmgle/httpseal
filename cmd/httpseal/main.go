package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/hmgle/httpseal/internal/config"
	"github.com/hmgle/httpseal/pkg/cert"
	"github.com/hmgle/httpseal/pkg/dns"
	"github.com/hmgle/httpseal/pkg/logger"
	"github.com/hmgle/httpseal/pkg/mirror"
	"github.com/hmgle/httpseal/pkg/namespace"
	"github.com/hmgle/httpseal/pkg/proxy"
)

const (
	version = "0.1.0"
)

var (
	// Network settings
	verbose bool
	dnsIP   string
	dnsPort int
	proxyPort int
	caDir   string
	keepCA  bool
	
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
  
  # Enable Wireshark integration - mirror HTTPS traffic as HTTP on port 8080
  httpseal --enable-mirror -- curl https://api.github.com/users/octocat
  
  # Custom mirror port for Wireshark analysis
  httpseal --enable-mirror --mirror-port 9090 -- wget https://httpbin.org/get
  
  # Keep CA directory for reuse (avoid regenerating certificates)
  httpseal --keep-ca --ca-dir ./my-ca -o traffic.json -- curl https://api.github.com/users/octocat
  
  # Use custom CA directory (will be preserved if --keep-ca is used)
  httpseal --ca-dir /path/to/ca --keep-ca -- wget https://httpbin.org/get`,
		Version: version,
		Args:    cobra.MinimumNArgs(1),
		RunE:    runHTTPSeal,
	}

	// Network settings
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().StringVar(&dnsIP, "dns-ip", "127.0.53.1", "DNS server IP address")
	rootCmd.Flags().IntVar(&dnsPort, "dns-port", 53, "DNS server port")
	rootCmd.Flags().IntVar(&proxyPort, "proxy-port", 443, "HTTPS proxy port")
	rootCmd.Flags().StringVar(&caDir, "ca-dir", "", "Certificate authority directory (default: auto-generated temp dir)")
	rootCmd.Flags().BoolVar(&keepCA, "keep-ca", false, "Keep CA directory after exit (useful for debugging or reuse)")
	
	// Traffic logging and output
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output traffic to file (automatically uses verbose level for complete data)")
	rootCmd.Flags().StringVar(&outputFormat, "format", "text", "Output format: text, json, csv")
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

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runHTTPSeal(cmd *cobra.Command, args []string) error {
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

	// Determine CA directory (use temp dir if not specified)
	effectiveCADir := caDir
	if effectiveCADir == "" {
		tempDir, err := os.MkdirTemp("", "httpseal-ca-*")
		if err != nil {
			return fmt.Errorf("failed to create temporary CA directory: %w", err)
		}
		effectiveCADir = tempDir
	}

	// Initialize configuration
	cfg := &config.Config{
		// Network settings
		Verbose:     verbose,
		DNSIP:       dnsIP,
		DNSPort:     dnsPort,
		ProxyPort:   proxyPort,
		CADir:       effectiveCADir,
		KeepCA:      keepCA,
		
		// Command execution
		Command:     args[0],
		CommandArgs: args[1:],
		
		// Traffic logging and output
		OutputFile:          outputFile,
		OutputFormat:        config.OutputFormat(outputFormat),
		LogLevel:            config.LogLevel(logLevel),
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

	// Initialize enhanced logger with traffic logging capabilities
	log, err := logger.NewEnhanced(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer log.Close()
	
	if !cfg.Quiet {
		log.Info("Starting HTTPSeal v%s", version)
	}

	// Initialize certificate authority
	ca, err := cert.NewCA(cfg.CADir)
	if err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}
	
	// Ensure CA cleanup on exit
	defer func() {
		// Always cleanup temp directories, respect --keep-ca for user-specified directories
		shouldCleanup := caDir == "" || !cfg.KeepCA
		if shouldCleanup {
			if cleanupErr := ca.Cleanup(); cleanupErr != nil {
				log.Error("Failed to cleanup CA directory: %v", cleanupErr)
			} else if !cfg.Quiet && caDir == "" {
				log.Info("Cleaned up temporary CA directory: %s", cfg.CADir)
			} else if !cfg.Quiet && caDir != "" {
				log.Info("Cleaned up CA directory: %s", cfg.CADir)
			}
		}
	}()

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
	proxyServer := proxy.NewServer(cfg.ProxyPort, ca, dnsServer, log, mirrorServer)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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

	if cfg.EnableMirror {
		log.Info("Listening on 0.0.0.0:%d (HTTPS), DNS on %s:%d, Mirror on 127.0.0.1:%d", cfg.ProxyPort, cfg.DNSIP, cfg.DNSPort, cfg.MirrorPort)
	} else {
		log.Info("Listening on 0.0.0.0:%d (HTTPS), DNS on %s:%d", cfg.ProxyPort, cfg.DNSIP, cfg.DNSPort)
	}

	// Create namespace wrapper and execute command
	nsWrapper := namespace.NewWrapper(cfg, log)
	processChan := make(chan error, 1)
	
	go func() {
		processChan <- nsWrapper.Execute()
	}()

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
		nsWrapper.Stop()
		
		// Wait for graceful shutdown with timeout
		shutdownDone := make(chan bool, 1)
		go func() {
			// Wait for process to actually exit
			<-processChan
			shutdownDone <- true
		}()
		
		select {
		case <-shutdownDone:
			// Graceful shutdown completed
		case <-time.After(2 * time.Second):
			// Force termination if graceful shutdown takes too long
			if !cfg.Quiet {
				log.Warn("Forced termination after timeout")
			}
		}
	}

	return nil
}

// validateFlags validates command line flags
func validateFlags() error {
	// Validate output format
	validFormats := []string{"text", "json", "csv"}
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
	validLevels := []string{"none", "minimal", "normal", "verbose"}
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
	
	return nil
}
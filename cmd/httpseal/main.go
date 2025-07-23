package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/hmgle/httpseal/internal/config"
	"github.com/hmgle/httpseal/pkg/cert"
	"github.com/hmgle/httpseal/pkg/dns"
	"github.com/hmgle/httpseal/pkg/logger"
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
	
	// Traffic logging and output
	outputFile          string
	outputFormat        string
	logLevel            string
	quiet               bool
	maxBodySize         int
	filterDomains       []string
	excludeContentTypes []string
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
  
  # Save traffic to file in JSON format
  httpseal -o traffic.json --format json -- wget https://baidu.com
  
  # Quiet mode - only save to file, no console output
  httpseal -q -o traffic.log -- curl https://api.github.com/repos/golang/go
  
  # Filter specific domains and limit body size
  httpseal --filter-domain api.github.com --max-body-size 1024 -- curl https://api.github.com/users/octocat
  
  # Minimal logging level
  httpseal --log-level minimal -o summary.txt -- wget https://httpbin.org/json`,
		Version: version,
		Args:    cobra.MinimumNArgs(1),
		RunE:    runHTTPSeal,
	}

	// Network settings
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().StringVar(&dnsIP, "dns-ip", "127.0.53.1", "DNS server IP address")
	rootCmd.Flags().IntVar(&dnsPort, "dns-port", 53, "DNS server port")
	rootCmd.Flags().IntVar(&proxyPort, "proxy-port", 443, "HTTPS proxy port")
	rootCmd.Flags().StringVar(&caDir, "ca-dir", "ca", "Certificate authority directory")
	
	// Traffic logging and output
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output traffic to file")
	rootCmd.Flags().StringVar(&outputFormat, "format", "text", "Output format: text, json, csv")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "normal", "Logging level: none, minimal, normal, verbose")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress console output (quiet mode)")
	rootCmd.Flags().IntVar(&maxBodySize, "max-body-size", 0, "Maximum response body size to log (bytes, 0=unlimited)")
	rootCmd.Flags().StringSliceVar(&filterDomains, "filter-domain", []string{}, "Only log traffic for these domains (can be repeated)")
	rootCmd.Flags().StringSliceVar(&excludeContentTypes, "exclude-content-type", []string{}, "Exclude these content types from logging")

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

	// Initialize configuration
	cfg := &config.Config{
		// Network settings
		Verbose:     verbose,
		DNSIP:       dnsIP,
		DNSPort:     dnsPort,
		ProxyPort:   proxyPort,
		CADir:       caDir,
		
		// Command execution
		Command:     args[0],
		CommandArgs: args[1:],
		
		// Traffic logging and output
		OutputFile:          outputFile,
		OutputFormat:        config.OutputFormat(outputFormat),
		LogLevel:            config.LogLevel(logLevel),
		Quiet:               quiet,
		MaxBodySize:         maxBodySize,
		FilterDomains:       filterDomains,
		ExcludeContentTypes: excludeContentTypes,
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

	// Initialize DNS server
	dnsServer := dns.NewServer(cfg.DNSIP, cfg.DNSPort, log)
	
	// Initialize HTTPS proxy
	proxyServer := proxy.NewServer(cfg.ProxyPort, ca, dnsServer, log)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start DNS server
	if err := dnsServer.Start(); err != nil {
		return fmt.Errorf("failed to start DNS server: %w", err)
	}
	defer dnsServer.Stop()

	// Start HTTPS proxy
	if err := proxyServer.Start(); err != nil {
		return fmt.Errorf("failed to start HTTPS proxy: %w", err)
	}
	defer proxyServer.Stop()

	log.Info("Listening on 0.0.0.0:%d (HTTPS), DNS on %s:%d", cfg.ProxyPort, cfg.DNSIP, cfg.DNSPort)

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
		log.Info("Process completed successfully")
	case sig := <-sigChan:
		log.Info("Received signal %v, shutting down...", sig)
		nsWrapper.Stop()
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
	
	// Validate max body size
	if maxBodySize < 0 {
		return fmt.Errorf("max-body-size must be >= 0")
	}
	
	// If quiet mode is enabled, require output file
	if quiet && outputFile == "" {
		return fmt.Errorf("quiet mode (-q) requires output file (-o)")
	}
	
	return nil
}
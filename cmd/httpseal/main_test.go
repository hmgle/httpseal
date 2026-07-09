package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hmgle/httpseal/internal/config"
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

func TestValidateFlagsRequiresClientCertAndKeyTogether(t *testing.T) {
	oldUpstreamDNS := upstreamDNS
	oldOutputFormat := outputFormat
	oldLogLevel := logLevel
	oldQuiet := quiet
	oldOutputFile := outputFile
	oldCert := upstreamClientCert
	oldKey := upstreamClientKey
	t.Cleanup(func() {
		upstreamDNS = oldUpstreamDNS
		outputFormat = oldOutputFormat
		logLevel = oldLogLevel
		quiet = oldQuiet
		outputFile = oldOutputFile
		upstreamClientCert = oldCert
		upstreamClientKey = oldKey
	})

	upstreamDNS = "8.8.8.8:53"
	outputFormat = "text"
	logLevel = "normal"
	quiet = false
	outputFile = ""
	upstreamClientCert = "client.pem"
	upstreamClientKey = ""

	_, err := validateFlags()
	if err == nil {
		t.Fatal("expected validation to fail when only upstream client cert is set")
	}
	if !strings.Contains(err.Error(), "upstream-client-cert and upstream-client-key") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateFlagsRequiresUpstreamDNSHostPort(t *testing.T) {
	oldUpstreamDNS := upstreamDNS
	oldOutputFormat := outputFormat
	oldLogLevel := logLevel
	oldQuiet := quiet
	oldOutputFile := outputFile
	t.Cleanup(func() {
		upstreamDNS = oldUpstreamDNS
		outputFormat = oldOutputFormat
		logLevel = oldLogLevel
		quiet = oldQuiet
		outputFile = oldOutputFile
	})

	upstreamDNS = "8.8.8.8"
	outputFormat = "text"
	logLevel = "normal"
	quiet = false
	outputFile = ""

	_, err := validateFlags()
	if err == nil {
		t.Fatal("expected validation to fail when upstream DNS omits a port")
	}
	if !strings.Contains(err.Error(), "upstream-dns must be in host:port form") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateFlagsRejectsInvalidCaptureOnlyStatus(t *testing.T) {
	oldUpstreamDNS := upstreamDNS
	oldOutputFormat := outputFormat
	oldLogLevel := logLevel
	oldQuiet := quiet
	oldOutputFile := outputFile
	oldCaptureOnlyStatus := captureOnlyStatus
	t.Cleanup(func() {
		upstreamDNS = oldUpstreamDNS
		outputFormat = oldOutputFormat
		logLevel = oldLogLevel
		quiet = oldQuiet
		outputFile = oldOutputFile
		captureOnlyStatus = oldCaptureOnlyStatus
	})

	upstreamDNS = "8.8.8.8:53"
	outputFormat = "text"
	logLevel = "normal"
	quiet = false
	outputFile = ""
	captureOnlyStatus = 99

	_, err := validateFlags()
	if err == nil {
		t.Fatal("expected validation to fail for invalid capture-only status")
	}
	if !strings.Contains(err.Error(), "capture-only-status") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateFlagsRejectsInvalidCaptureOnlyUpstream(t *testing.T) {
	oldUpstreamDNS := upstreamDNS
	oldOutputFormat := outputFormat
	oldLogLevel := logLevel
	oldQuiet := quiet
	oldOutputFile := outputFile
	oldCaptureOnlyStatus := captureOnlyStatus
	oldCaptureOnlyUpstream := captureOnlyUpstream
	oldCaptureOnlyPreserveHost := captureOnlyPreserveHost
	oldEnableMirror := enableMirror
	oldMirrorPort := mirrorPort
	oldEnableHTTP := enableHTTP
	oldHTTPPort := httpPort
	oldProxyPort := proxyPort
	oldDNSPort := dnsPort
	t.Cleanup(func() {
		upstreamDNS = oldUpstreamDNS
		outputFormat = oldOutputFormat
		logLevel = oldLogLevel
		quiet = oldQuiet
		outputFile = oldOutputFile
		captureOnlyStatus = oldCaptureOnlyStatus
		captureOnlyUpstream = oldCaptureOnlyUpstream
		captureOnlyPreserveHost = oldCaptureOnlyPreserveHost
		enableMirror = oldEnableMirror
		mirrorPort = oldMirrorPort
		enableHTTP = oldEnableHTTP
		httpPort = oldHTTPPort
		proxyPort = oldProxyPort
		dnsPort = oldDNSPort
	})

	upstreamDNS = "8.8.8.8:53"
	dnsPort = 53
	proxyPort = 443
	httpPort = 80
	enableHTTP = false
	enableMirror = false
	mirrorPort = 8080
	outputFormat = "text"
	logLevel = "normal"
	quiet = false
	outputFile = ""
	captureOnlyStatus = 204
	captureOnlyUpstream = "ftp://127.0.0.1:8080"
	captureOnlyPreserveHost = false

	_, err := validateFlags()
	if err == nil {
		t.Fatal("expected validation to fail for invalid capture-only upstream")
	}
	if !strings.Contains(err.Error(), "capture-only-upstream") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateFlagsParsesCaptureOnlyUpstreamMode(t *testing.T) {
	oldUpstreamDNS := upstreamDNS
	oldOutputFormat := outputFormat
	oldLogLevel := logLevel
	oldQuiet := quiet
	oldOutputFile := outputFile
	oldCaptureOnly := captureOnly
	oldCaptureOnlyStatus := captureOnlyStatus
	oldCaptureOnlyUpstream := captureOnlyUpstream
	oldCaptureOnlyPreserveHost := captureOnlyPreserveHost
	oldEnableMirror := enableMirror
	oldMirrorPort := mirrorPort
	oldEnableHTTP := enableHTTP
	oldHTTPPort := httpPort
	oldProxyPort := proxyPort
	oldDNSPort := dnsPort
	t.Cleanup(func() {
		upstreamDNS = oldUpstreamDNS
		outputFormat = oldOutputFormat
		logLevel = oldLogLevel
		quiet = oldQuiet
		outputFile = oldOutputFile
		captureOnly = oldCaptureOnly
		captureOnlyStatus = oldCaptureOnlyStatus
		captureOnlyUpstream = oldCaptureOnlyUpstream
		captureOnlyPreserveHost = oldCaptureOnlyPreserveHost
		enableMirror = oldEnableMirror
		mirrorPort = oldMirrorPort
		enableHTTP = oldEnableHTTP
		httpPort = oldHTTPPort
		proxyPort = oldProxyPort
		dnsPort = oldDNSPort
	})

	upstreamDNS = "8.8.8.8:53"
	dnsPort = 53
	proxyPort = 443
	httpPort = 80
	enableHTTP = false
	enableMirror = false
	mirrorPort = 8080
	outputFormat = "text"
	logLevel = "normal"
	quiet = false
	outputFile = ""
	captureOnly = false
	captureOnlyStatus = 204
	captureOnlyUpstream = "http://127.0.0.1:8080/mock?base=1"
	captureOnlyPreserveHost = true

	validated, err := validateFlags()
	if err != nil {
		t.Fatalf("validate flags: %v", err)
	}
	if validated.captureMode != config.CaptureModeUpstream {
		t.Fatalf("expected upstream capture mode, got %q", validated.captureMode)
	}
	if validated.captureOnlyUpstreamURL == nil {
		t.Fatal("expected parsed capture-only upstream URL")
	}
	if got := validated.captureOnlyUpstreamURL.String(); got != captureOnlyUpstream {
		t.Fatalf("expected parsed upstream URL %q, got %q", captureOnlyUpstream, got)
	}
}

func TestValidateFlagsRequiresUpstreamForCaptureOnlyPreserveHost(t *testing.T) {
	oldUpstreamDNS := upstreamDNS
	oldOutputFormat := outputFormat
	oldLogLevel := logLevel
	oldQuiet := quiet
	oldOutputFile := outputFile
	oldCaptureOnlyStatus := captureOnlyStatus
	oldCaptureOnlyUpstream := captureOnlyUpstream
	oldCaptureOnlyPreserveHost := captureOnlyPreserveHost
	t.Cleanup(func() {
		upstreamDNS = oldUpstreamDNS
		outputFormat = oldOutputFormat
		logLevel = oldLogLevel
		quiet = oldQuiet
		outputFile = oldOutputFile
		captureOnlyStatus = oldCaptureOnlyStatus
		captureOnlyUpstream = oldCaptureOnlyUpstream
		captureOnlyPreserveHost = oldCaptureOnlyPreserveHost
	})

	upstreamDNS = "8.8.8.8:53"
	outputFormat = "text"
	logLevel = "normal"
	quiet = false
	outputFile = ""
	captureOnlyStatus = 204
	captureOnlyUpstream = ""
	captureOnlyPreserveHost = true

	_, err := validateFlags()
	if err == nil {
		t.Fatal("expected validation to fail without capture-only upstream")
	}
	if !strings.Contains(err.Error(), "capture-only-preserve-host") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

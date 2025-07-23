package namespace

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/httpseal/httpseal/internal/config"
	"github.com/httpseal/httpseal/pkg/logger"
)

// Wrapper handles process execution in isolated namespaces
type Wrapper struct {
	config       *config.Config
	logger       logger.Logger
	cmd          *exec.Cmd
	tempDir      string
}

// NewWrapper creates a new namespace wrapper
func NewWrapper(cfg *config.Config, log logger.Logger) *Wrapper {
	return &Wrapper{
		config: cfg,
		logger: log,
	}
}

// Execute runs the target command in an isolated namespace
func (w *Wrapper) Execute() error {
	// Create temporary directory for bind mount preparations
	var err error
	w.tempDir, err = ioutil.TempDir("", "httpseal-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer w.cleanup()

	// Prepare isolated files
	if err := w.prepareIsolatedFiles(); err != nil {
		return fmt.Errorf("failed to prepare isolated files: %w", err)
	}

	// Create mount namespace and execute command
	return w.execInNamespace()
}

// Stop terminates the running process
func (w *Wrapper) Stop() {
	if w.cmd != nil && w.cmd.Process != nil {
		w.cmd.Process.Signal(syscall.SIGTERM)
	}
}

// prepareIsolatedFiles prepares files that need to be isolated via bind mounts
func (w *Wrapper) prepareIsolatedFiles() error {
	// 1. Prepare custom resolv.conf
	if err := w.prepareResolvConf(); err != nil {
		return fmt.Errorf("failed to prepare resolv.conf: %w", err)
	}

	// 2. Prepare custom CA certificate bundle
	if err := w.prepareCACertBundle(); err != nil {
		return fmt.Errorf("failed to prepare CA certificate bundle: %w", err)
	}

	// 3. Prepare custom nsswitch.conf to prioritize DNS
	if err := w.prepareNSSwitch(); err != nil {
		return fmt.Errorf("failed to prepare nsswitch.conf: %w", err)
	}

	// 4. Prepare empty hosts file to prevent local overrides
	if err := w.prepareEmptyHosts(); err != nil {
		return fmt.Errorf("failed to prepare empty hosts file: %w", err)
	}

	return nil
}

// prepareResolvConf creates a custom resolv.conf file
func (w *Wrapper) prepareResolvConf() error {
	resolveContent := fmt.Sprintf("nameserver %s\n", w.config.DNSIP)
	resolveFile := filepath.Join(w.tempDir, "resolv.conf")
	
	if err := os.WriteFile(resolveFile, []byte(resolveContent), 0644); err != nil {
		return fmt.Errorf("failed to write resolv.conf: %w", err)
	}

	w.logger.Debug("Prepared custom resolv.conf: %s", resolveFile)
	return nil
}

// prepareCACertBundle creates a CA certificate bundle with our custom CA
func (w *Wrapper) prepareCACertBundle() error {
	// Read our CA certificate
	caCertPath := filepath.Join(w.config.CADir, "ca.crt")
	caCertContent, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Read existing system CA bundle
	systemCaBundlePath := "/etc/ssl/certs/ca-certificates.crt"
	existingContent := ""
	if data, err := os.ReadFile(systemCaBundlePath); err == nil {
		existingContent = string(data)
	} else {
		// Try alternative locations
		altPaths := []string{
			"/etc/ssl/ca-bundle.pem",
			"/etc/pki/tls/certs/ca-bundle.crt",
			"/usr/share/ca-certificates/ca-certificates.crt",
		}
		for _, altPath := range altPaths {
			if data, err := os.ReadFile(altPath); err == nil {
				existingContent = string(data)
				break
			}
		}
	}

	// Create merged bundle
	caString := string(caCertContent)
	newContent := existingContent + "\n# HTTPSeal CA Certificate\n" + caString + "\n"

	// Write the custom CA bundle
	caBundleFile := filepath.Join(w.tempDir, "ca-certificates.crt")
	if err := os.WriteFile(caBundleFile, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write CA bundle: %w", err)
	}

	w.logger.Debug("Prepared custom CA bundle: %s", caBundleFile)
	return nil
}

// prepareNSSwitch creates a custom nsswitch.conf that prioritizes DNS
func (w *Wrapper) prepareNSSwitch() error {
	// Read the original nsswitch.conf
	originalContent, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return fmt.Errorf("failed to read original nsswitch.conf: %w", err)
	}

	// Replace the hosts line to prioritize DNS
	customContent := string(originalContent)
	// Replace hosts line with DNS-first configuration
	customContent = `# /etc/nsswitch.conf - Modified by HTTPSeal for DNS priority
#
# Configuration modified to prioritize DNS resolution over /etc/hosts
# This ensures domain name resolution goes through HTTPSeal's DNS server

passwd:         compat
group:          compat
shadow:         compat

# Modified: DNS first, then files, no mdns to avoid bypass
hosts:          dns files
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis
`

	// Write the custom nsswitch.conf
	nsSwitchFile := filepath.Join(w.tempDir, "nsswitch.conf")
	if err := os.WriteFile(nsSwitchFile, []byte(customContent), 0644); err != nil {
		return fmt.Errorf("failed to write custom nsswitch.conf: %w", err)
	}

	w.logger.Debug("Prepared custom nsswitch.conf: %s", nsSwitchFile)
	return nil
}

// prepareEmptyHosts creates a hosts file that pre-maps common domains to localhost
func (w *Wrapper) prepareEmptyHosts() error {
	// Create a hosts file with localhost entries and some common test domains
	// This should help bypass nscd for common domains
	hostsContent := `127.0.0.1	localhost
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters

# HTTPSeal: Pre-map common domains to localhost to bypass nscd cache
127.0.0.2	httpbin.org
127.0.0.3	api.github.com
127.0.0.4	google.com
127.0.0.5	baidu.com
127.0.0.6	example.com
127.0.0.7	httpbin.org www.httpbin.org
`

	// Write the hosts file
	hostsFile := filepath.Join(w.tempDir, "hosts")
	if err := os.WriteFile(hostsFile, []byte(hostsContent), 0644); err != nil {
		return fmt.Errorf("failed to write hosts file: %w", err)
	}

	w.logger.Debug("Prepared custom hosts file: %s", hostsFile)
	return nil
}

// createWrapperScript creates a shell script that sets up bind mounts and execs the target command
func (w *Wrapper) createWrapperScript() (string, error) {
	wrapperPath := filepath.Join(w.tempDir, "wrapper.sh")
	
	// Create the wrapper script content
	scriptContent := `#!/bin/bash
set -e

# Set mount propagation to private to prevent mount leaks
mount --make-rprivate / 2>/dev/null || true

# Set up bind mounts for isolated files
# 1. Bind mount custom resolv.conf
if [ -f "$TRACEBIND_TEMP_DIR/resolv.conf" ]; then
    # Ensure target file exists
    [ ! -f /etc/resolv.conf ] && touch /etc/resolv.conf
    mount --bind "$TRACEBIND_TEMP_DIR/resolv.conf" /etc/resolv.conf
    echo "[DEBUG] Mounted resolv.conf, content:"
    cat /etc/resolv.conf
fi

# 2. Bind mount custom CA certificate bundle
if [ -f "$TRACEBIND_TEMP_DIR/ca-certificates.crt" ]; then
    # Ensure target directory and file exist
    mkdir -p /etc/ssl/certs
    [ ! -f /etc/ssl/certs/ca-certificates.crt ] && touch /etc/ssl/certs/ca-certificates.crt
    mount --bind "$TRACEBIND_TEMP_DIR/ca-certificates.crt" /etc/ssl/certs/ca-certificates.crt
fi

# 3. Bind mount custom nsswitch.conf
if [ -f "$TRACEBIND_TEMP_DIR/nsswitch.conf" ]; then
    # Ensure target file exists
    [ ! -f /etc/nsswitch.conf ] && touch /etc/nsswitch.conf
    mount --bind "$TRACEBIND_TEMP_DIR/nsswitch.conf" /etc/nsswitch.conf
    echo "[DEBUG] Mounted custom nsswitch.conf"
fi

# 4. Bind mount empty hosts file
if [ -f "$TRACEBIND_TEMP_DIR/hosts" ]; then
    # Ensure target file exists
    [ ! -f /etc/hosts ] && touch /etc/hosts
    mount --bind "$TRACEBIND_TEMP_DIR/hosts" /etc/hosts
    echo "[DEBUG] Mounted custom hosts file"
    echo "[DEBUG] Hosts file content:"
    head -20 /etc/hosts
fi

# 5. Handle nscd (Name Service Cache Daemon) if present
if pgrep nscd > /dev/null; then
    echo "[DEBUG] Found nscd running, attempting to clear cache..."
    # Try to invalidate hosts cache
    nscd -i hosts 2>/dev/null || echo "[DEBUG] Failed to invalidate nscd hosts cache"
    # Try to stop nscd temporarily
    systemctl stop nscd 2>/dev/null || echo "[DEBUG] Failed to stop nscd service"
    echo "[DEBUG] Testing getent after nscd operations:"
    getent hosts httpbin.org || echo "[DEBUG] getent failed after nscd operations"
fi

# Debug: Check DNS resolution before executing command
echo "[DEBUG] Testing DNS resolution in namespace:"
echo "[DEBUG] nslookup httpbin.org:"
nslookup httpbin.org || echo "[ERROR] nslookup failed"
echo "[DEBUG] host httpbin.org:"
host httpbin.org || echo "[DEBUG] host command not available"
echo "[DEBUG] getent hosts httpbin.org:"
getent hosts httpbin.org || echo "[DEBUG] getent failed"

# Reconstruct original command and arguments
CMD="$TRACEBIND_ORIGINAL_CMD"
ARGS=()
for ((i=0; i<$TRACEBIND_ARG_COUNT; i++)); do
    var_name="TRACEBIND_ARG_$i"
    ARGS+=("${!var_name}")
done

echo "[DEBUG] Executing: $CMD ${ARGS[*]}"
# Execute the original command
exec "$CMD" "${ARGS[@]}"
`

	// Write the script
	if err := os.WriteFile(wrapperPath, []byte(scriptContent), 0755); err != nil {
		return "", fmt.Errorf("failed to write wrapper script: %w", err)
	}

	w.logger.Debug("Created wrapper script: %s", wrapperPath)
	return wrapperPath, nil
}

// execInNamespace creates a new mount namespace and executes the command
func (w *Wrapper) execInNamespace() error {
	// Prepare the command first
	w.cmd = exec.Command(w.config.Command, w.config.CommandArgs...)
	w.cmd.Stdout = os.Stdout
	w.cmd.Stderr = os.Stderr
	w.cmd.Stdin = os.Stdin

	// Set environment variables to use our CA certificate
	w.cmd.Env = append(os.Environ(),
		// OpenSSL/curl environment variables
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"SSL_CERT_DIR=/etc/ssl/certs",
		"CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
		"REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
		// GnuTLS environment variables for wget
		"GNUTLS_SYSTEM_PRIORITY_FILE=/etc/ssl/certs/ca-certificates.crt", 
		"CA_CERTIFICATE_FILE=/etc/ssl/certs/ca-certificates.crt",
		"GNUTLS_SYSTEM_TRUST_FILE=/etc/ssl/certs/ca-certificates.crt",
		// Python requests
		"PYTHONHTTPSVERIFY=1",
		// Node.js
		"NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt",
	)

	// Set up the namespace creation - only mount namespace
	// We don't use user namespace to avoid file permission issues
	w.cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS,
	}

	// Create a wrapper script that will set up bind mounts and then exec the target command
	wrapperScript, err := w.createWrapperScript()
	if err != nil {
		return fmt.Errorf("failed to create wrapper script: %w", err)
	}
	defer os.Remove(wrapperScript)

	// Update command to use the wrapper script
	w.cmd.Args = []string{wrapperScript}
	w.cmd.Path = wrapperScript

	// Pass original command as environment variables
	w.cmd.Env = append(w.cmd.Env,
		fmt.Sprintf("TRACEBIND_ORIGINAL_CMD=%s", w.config.Command),
		fmt.Sprintf("TRACEBIND_TEMP_DIR=%s", w.tempDir),
		// Disable various caching mechanisms
		"HOSTALIASES=", // Disable host aliases
		"RES_OPTIONS=no-check-names", // Disable resolver caching
		"NSCD_DISABLE=1", // Try to disable nscd
	)
	for i, arg := range w.config.CommandArgs {
		w.cmd.Env = append(w.cmd.Env, fmt.Sprintf("TRACEBIND_ARG_%d=%s", i, arg))
	}
	w.cmd.Env = append(w.cmd.Env, fmt.Sprintf("TRACEBIND_ARG_COUNT=%d", len(w.config.CommandArgs)))

	w.logger.Info("Starting process '%s' with isolated namespace...", w.config.Command)

	// Start the process in the new namespace
	if err := w.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process: %w", err)
	}

	w.logger.Info("Process '%s' started with PID %d in isolated namespace", w.config.Command, w.cmd.Process.Pid)

	// Wait for the process to complete
	return w.cmd.Wait()
}



// cleanup removes temporary files
func (w *Wrapper) cleanup() {
	if w.tempDir != "" {
		if err := os.RemoveAll(w.tempDir); err != nil {
			w.logger.Warn("Failed to remove temp directory: %v", err)
		} else {
			w.logger.Debug("Cleaned up temporary directory")
		}
	}
}
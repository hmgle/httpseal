package namespace

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/hmgle/httpseal/internal/config"
	"github.com/hmgle/httpseal/pkg/logger"
)

// Wrapper handles process execution in isolated namespaces
type Wrapper struct {
	config    *config.Config
	logger    logger.Logger
	cmd       *exec.Cmd
	tempDir   string
	useUserNS bool // whether to use user namespace approach
}

// NewWrapper creates a new namespace wrapper
func NewWrapper(cfg *config.Config, log logger.Logger) *Wrapper {
	return &Wrapper{
		config:    cfg,
		logger:    log,
		useUserNS: supportsUserNamespace(),
	}
}

// supportsUserNamespace checks if user namespaces are supported
func supportsUserNamespace() bool {
	// Check if user namespaces are available (Linux 3.8+)
	if runtime.GOOS != "linux" {
		return false
	}

	// Check if user namespace creation is allowed
	if data, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		if string(data)[0] == '0' {
			return false
		}
	}

	return true
}

// Execute runs the target command in an isolated namespace
func (w *Wrapper) Execute() error {
	// Create temporary directory for bind mount preparations
	var err error
	w.tempDir, err = os.MkdirTemp("", "httpseal-*")
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
		// First try graceful termination
		w.cmd.Process.Signal(syscall.SIGTERM)

		// Give it a moment to exit gracefully
		time.Sleep(200 * time.Millisecond)

		// If it's still running, force kill
		if w.cmd.ProcessState == nil {
			w.cmd.Process.Signal(syscall.SIGKILL)
		}
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
		// If the file doesn't exist, we can't safely modify it.
		// However, we can create a minimal one for basic functionality.
		w.logger.Warn("failed to read original /etc/nsswitch.conf: %v. Creating a minimal version.", err)
		originalContent = []byte("passwd: files\ngroup: files\nshadow: files\n")
	}

	contentStr := string(originalContent)
	customContent := ""

	// This regex finds the "hosts:" line. It's multi-line enabled.
	hostsRegex := regexp.MustCompile(`(?m)^\s*hosts:.*`)
	newHostsLine := "hosts:          dns files"

	if hostsRegex.MatchString(contentStr) {
		// If hosts line exists, replace it
		customContent = hostsRegex.ReplaceAllString(contentStr, newHostsLine)
		w.logger.Debug("Replaced hosts line in nsswitch.conf")
	} else {
		// If no hosts line, append it
		customContent = strings.TrimSpace(contentStr) + "\n" + newHostsLine + "\n"
		w.logger.Debug("Appended hosts line to nsswitch.conf")
	}

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

// setupBindMounts sets up bind mounts using Go syscalls (user namespace approach)
func (w *Wrapper) setupBindMounts() error {
	mounts := []struct {
		source string
		target string
		desc   string
	}{
		{filepath.Join(w.tempDir, "resolv.conf"), "/etc/resolv.conf", "DNS configuration"},
		{filepath.Join(w.tempDir, "ca-certificates.crt"), "/etc/ssl/certs/ca-certificates.crt", "CA certificates"},
		{filepath.Join(w.tempDir, "nsswitch.conf"), "/etc/nsswitch.conf", "NSS configuration"},
		{filepath.Join(w.tempDir, "hosts"), "/etc/hosts", "hosts file"},
	}

	// Set mount propagation to private to prevent mount leaks
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		w.logger.Warn("Failed to set mount propagation to private: %v", err)
	}

	for _, mount := range mounts {
		// Check if source file exists
		if _, err := os.Stat(mount.source); err != nil {
			w.logger.Warn("Source file %s does not exist, skipping mount", mount.source)
			continue
		}

		// Ensure target directory exists
		targetDir := filepath.Dir(mount.target)
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
		}

		// Ensure target file exists
		if _, err := os.Stat(mount.target); os.IsNotExist(err) {
			if err := os.WriteFile(mount.target, []byte{}, 0644); err != nil {
				return fmt.Errorf("failed to create target file %s: %w", mount.target, err)
			}
		}

		// Perform bind mount
		if err := syscall.Mount(mount.source, mount.target, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("failed to bind mount %s -> %s (%s): %w", mount.source, mount.target, mount.desc, err)
		}

		w.logger.Debug("Successfully mounted %s -> %s (%s)", mount.source, mount.target, mount.desc)
	}

	return nil
}

// createWrapperScript creates a shell script that sets up bind mounts and execs the target command
func (w *Wrapper) createWrapperScript() (string, error) {
	wrapperPath := filepath.Join(w.tempDir, "wrapper.sh")

	// Determine output redirection based on quiet mode
	var mountOutput, debugRedirect string

	if w.config.Quiet {
		mountOutput = "2>/dev/null"
		debugRedirect = ">/dev/null 2>&1"
	} else if w.config.Verbose {
		mountOutput = ""
		debugRedirect = ""
	} else {
		mountOutput = "2>/dev/null"
		debugRedirect = ">/dev/null 2>&1"
	}

	// Create additional debug commands for capabilities mode
	var debugExtended string
	if w.config.Verbose && !w.config.Quiet {
		debugExtended = `
# 5. Handle nscd (Name Service Cache Daemon) if present
if pgrep nscd >/dev/null 2>&1; then
    echo "[DEBUG] Found nscd running, attempting to clear cache..."
    nscd -i hosts 2>/dev/null || echo "[DEBUG] Failed to invalidate nscd hosts cache"
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
getent hosts httpbin.org || echo "[DEBUG] getent failed"`
	} else {
		debugExtended = `
# Handle nscd quietly
if pgrep nscd >/dev/null 2>&1; then
    nscd -i hosts >/dev/null 2>&1 || true
    systemctl stop nscd >/dev/null 2>&1 || true
fi`
	}

	// Create the wrapper script content
	scriptContent := fmt.Sprintf(`#!/bin/bash
set -e

# Set mount propagation to private to prevent mount leaks
mount --make-rprivate / %s || true

# Set up bind mounts for isolated files
# 1. Bind mount custom resolv.conf
if [ -f "$TRACEBIND_TEMP_DIR/resolv.conf" ]; then
    [ ! -f /etc/resolv.conf ] && touch /etc/resolv.conf %s
    mount --bind "$TRACEBIND_TEMP_DIR/resolv.conf" /etc/resolv.conf %s
    %s
fi

# 2. Bind mount custom CA certificate bundle
if [ -f "$TRACEBIND_TEMP_DIR/ca-certificates.crt" ]; then
    mkdir -p /etc/ssl/certs %s
    [ ! -f /etc/ssl/certs/ca-certificates.crt ] && touch /etc/ssl/certs/ca-certificates.crt %s
    mount --bind "$TRACEBIND_TEMP_DIR/ca-certificates.crt" /etc/ssl/certs/ca-certificates.crt %s
fi

# 3. Bind mount custom nsswitch.conf
if [ -f "$TRACEBIND_TEMP_DIR/nsswitch.conf" ]; then
    [ ! -f /etc/nsswitch.conf ] && touch /etc/nsswitch.conf %s
    mount --bind "$TRACEBIND_TEMP_DIR/nsswitch.conf" /etc/nsswitch.conf %s
    %s
fi

# 4. Bind mount empty hosts file
if [ -f "$TRACEBIND_TEMP_DIR/hosts" ]; then
    [ ! -f /etc/hosts ] && touch /etc/hosts %s
    mount --bind "$TRACEBIND_TEMP_DIR/hosts" /etc/hosts %s
    %s
fi
%s

# Reconstruct original command and arguments with proper quoting
CMD="$TRACEBIND_ORIGINAL_CMD"
declare -a CMDARGS
i=0
while [ $i -lt $TRACEBIND_ARG_COUNT ]; do
    var_name="TRACEBIND_ARG_$i"
    arg="${!var_name}"
    if [ -n "$arg" ]; then
        CMDARGS[$i]="$arg"
    fi
    i=$((i + 1))
done

%s
# Execute the original command with proper argument preservation
exec "$CMD" "${CMDARGS[@]}"
`,
		mountOutput,   // mount --make-rprivate
		debugRedirect, // touch resolv.conf
		mountOutput,   // mount resolv.conf
		func() string {
			if w.config.Verbose && !w.config.Quiet {
				return "echo \"[DEBUG] Mounted resolv.conf, content:\"; cat /etc/resolv.conf"
			}
			return ""
		}(), // debug resolv.conf
		debugRedirect, // mkdir ssl/certs
		debugRedirect, // touch ca-certificates.crt
		mountOutput,   // mount ca-certificates.crt
		debugRedirect, // touch nsswitch.conf
		mountOutput,   // mount nsswitch.conf
		func() string {
			if w.config.Verbose && !w.config.Quiet {
				return "echo \"[DEBUG] Mounted custom nsswitch.conf\""
			}
			return ""
		}(), // debug nsswitch
		debugRedirect, // touch hosts
		mountOutput,   // mount hosts
		func() string {
			if w.config.Verbose && !w.config.Quiet {
				return "echo \"[DEBUG] Mounted custom hosts file\"; echo \"[DEBUG] Hosts file content:\"; head -20 /etc/hosts"
			}
			return ""
		}(), // debug hosts
		debugExtended, // extended debug commands
		func() string {
			if w.config.Verbose && !w.config.Quiet {
				return "echo \"[DEBUG] Executing: $CMD $ARGS\""
			}
			return ""
		}(), // debug exec
	)

	// Write the script
	if err := os.WriteFile(wrapperPath, []byte(scriptContent), 0755); err != nil {
		return "", fmt.Errorf("failed to write wrapper script: %w", err)
	}

	w.logger.Debug("Created wrapper script: %s", wrapperPath)
	return wrapperPath, nil
}

// execInNamespace creates a new mount namespace and executes the command
func (w *Wrapper) execInNamespace() error {
	if w.useUserNS {
		w.logger.Info("Using user namespace approach (no privileges required)")
		return w.execWithUserNamespace()
	} else {
		w.logger.Info("Using capabilities approach (requires CAP_SYS_ADMIN)")
		return w.execWithCapabilities()
	}
}

// execWithUserNamespace executes command using user namespace + UID mapping
func (w *Wrapper) execWithUserNamespace() error {
	// Create a user namespace wrapper script
	wrapperScript, err := w.createUserNamespaceScript()
	if err != nil {
		return fmt.Errorf("failed to create user namespace script: %w", err)
	}
	defer os.Remove(wrapperScript)

	// Prepare the command
	w.cmd = exec.Command(wrapperScript)
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
		// Disable various caching mechanisms
		"HOSTALIASES=",               // Disable host aliases
		"RES_OPTIONS=no-check-names", // Disable resolver caching
		"NSCD_DISABLE=1",             // Try to disable nscd
		// Pass original command as environment variables
		fmt.Sprintf("HTTPSEAL_ORIGINAL_CMD=%s", w.config.Command),
		fmt.Sprintf("HTTPSEAL_TEMP_DIR=%s", w.tempDir),
	)

	// Add command arguments as environment variables
	for i, arg := range w.config.CommandArgs {
		w.cmd.Env = append(w.cmd.Env, fmt.Sprintf("HTTPSEAL_ARG_%d=%s", i, arg))
	}
	w.cmd.Env = append(w.cmd.Env, fmt.Sprintf("HTTPSEAL_ARG_COUNT=%d", len(w.config.CommandArgs)))

	w.logger.Info("Starting process '%s' with user namespace (no privileges required)...", w.config.Command)

	// Start the process
	if err := w.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process in user namespace: %w", err)
	}

	w.logger.Info("Process '%s' started with PID %d in user namespace", w.config.Command, w.cmd.Process.Pid)

	// Wait for the process to complete
	return w.cmd.Wait()
}

// createUserNamespaceScript creates a script for user namespace execution
func (w *Wrapper) createUserNamespaceScript() (string, error) {
	wrapperPath := filepath.Join(w.tempDir, "userns_wrapper.sh")

	// Determine output redirection based on quiet mode
	var mountOutput, debugRedirect string
	if w.config.Quiet {
		mountOutput = "2>/dev/null"
		debugRedirect = ">/dev/null 2>&1"
	} else if w.config.Verbose {
		mountOutput = ""
		debugRedirect = ""
	} else {
		mountOutput = "2>/dev/null"
		debugRedirect = ">/dev/null 2>&1"
	}

	// Create debug output conditionally
	var debugEchos string
	if w.config.Verbose && !w.config.Quiet {
		debugEchos = fmt.Sprintf(`
		echo "[DEBUG] Mounted resolv.conf"
		echo "[DEBUG] Mounted CA certificates" 
		echo "[DEBUG] Mounted nsswitch.conf"
		echo "[DEBUG] Mounted hosts file"
		echo "[DEBUG] Running as UID $(id -u), GID $(id -g) in namespace"
		echo "[DEBUG] Executing: $CMD $ARGS"`)
	}

	scriptContent := fmt.Sprintf(`#!/bin/bash
set -e

# Create user and mount namespaces with UID/GID mapping
unshare --user --mount --map-root-user bash -c '
	# Set mount propagation to private
	mount --make-rprivate / %s || true
	
	# Set up bind mounts (we are now root in the namespace)
	if [ -f "$HTTPSEAL_TEMP_DIR/resolv.conf" ]; then
		[ ! -f /etc/resolv.conf ] && touch /etc/resolv.conf %s
		mount --bind "$HTTPSEAL_TEMP_DIR/resolv.conf" /etc/resolv.conf %s
	fi
	
	if [ -f "$HTTPSEAL_TEMP_DIR/ca-certificates.crt" ]; then
		mkdir -p /etc/ssl/certs %s
		[ ! -f /etc/ssl/certs/ca-certificates.crt ] && touch /etc/ssl/certs/ca-certificates.crt %s
		mount --bind "$HTTPSEAL_TEMP_DIR/ca-certificates.crt" /etc/ssl/certs/ca-certificates.crt %s
	fi
	
	if [ -f "$HTTPSEAL_TEMP_DIR/nsswitch.conf" ]; then
		[ ! -f /etc/nsswitch.conf ] && touch /etc/nsswitch.conf %s
		mount --bind "$HTTPSEAL_TEMP_DIR/nsswitch.conf" /etc/nsswitch.conf %s
	fi
	
	if [ -f "$HTTPSEAL_TEMP_DIR/hosts" ]; then
		[ ! -f /etc/hosts ] && touch /etc/hosts %s
		mount --bind "$HTTPSEAL_TEMP_DIR/hosts" /etc/hosts %s
	fi
	%s
	
	# Reconstruct original command and arguments with proper quoting
	CMD="$HTTPSEAL_ORIGINAL_CMD"
	declare -a CMDARGS
	i=0
	while [ $i -lt $HTTPSEAL_ARG_COUNT ]; do
		var_name="HTTPSEAL_ARG_$i"
		arg="${!var_name}"
		if [ -n "$arg" ]; then
			CMDARGS[$i]="$arg"
		fi
		i=$((i + 1))
	done
	
	# Execute the original command with proper argument preservation
	exec "$CMD" "${CMDARGS[@]}"
'`,
		mountOutput,   // mount --make-rprivate
		debugRedirect, // touch resolv.conf
		mountOutput,   // mount resolv.conf
		debugRedirect, // mkdir ssl/certs
		debugRedirect, // touch ca-certificates.crt
		mountOutput,   // mount ca-certificates.crt
		debugRedirect, // touch nsswitch.conf
		mountOutput,   // mount nsswitch.conf
		debugRedirect, // touch hosts
		mountOutput,   // mount hosts
		debugEchos)

	// Write the script
	if err := os.WriteFile(wrapperPath, []byte(scriptContent), 0755); err != nil {
		return "", fmt.Errorf("failed to write user namespace script: %w", err)
	}

	w.logger.Debug("Created user namespace script: %s", wrapperPath)
	return wrapperPath, nil
}

// execWithCapabilities executes command using original capabilities approach
func (w *Wrapper) execWithCapabilities() error {
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
		"HOSTALIASES=",               // Disable host aliases
		"RES_OPTIONS=no-check-names", // Disable resolver caching
		"NSCD_DISABLE=1",             // Try to disable nscd
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

# HTTPSeal

English | [简体中文](README-zh.md)

HTTPSeal is a Linux command-line tool for intercepting and analyzing HTTPS/HTTP traffic from specific processes using namespace isolation and DNS hijacking.

## Demo

[![asciicast](https://asciinema.org/a/730013.svg)](https://asciinema.org/a/730013)

> **Note**: Any API keys shown in the demo have been removed and invalidated for security purposes.

## About the Name

**HTTPSeal** combines "HTTP/HTTPS" with "Seal" - representing the secure encapsulation and isolation of process traffic within a controlled environment. The name is a playful homage to **Wireshark** 🦈, the legendary network analysis tool. While Wireshark hunts through entire network oceans, HTTPSeal is the specialized marine hunter that focuses precisely on HTTP/HTTPS streams within isolated process territories.

## Key Advantages

🎯 **Unique Process Isolation**: Unlike global proxy tools (mitmproxy, Burp), HTTPSeal only affects processes it launches - no impact on your system or other applications

⚡ **Simple Configuration**: Target applications need no proxy settings or modifications - just run them with HTTPSeal and they're automatically intercepted

🔐 **Advanced Certificate Management**: Fully automatic CA handling with XDG-compliant persistent storage (default: `$XDG_CONFIG_HOME/httpseal/ca/`) - certificates reused between sessions for better performance

🔧 **Linux-Native Architecture**: Built specifically for Linux using namespace isolation, user namespaces, and bind mounts for maximum security and efficiency

🦈 **Wireshark Integration**: HTTP mirror server creates real-time plain HTTP replicas of decrypted HTTPS traffic - analyze TLS 1.3 traffic in Wireshark with minimal setup

📊 **Multiple Output Formats**: Native HAR (HTTP Archive) support for browser dev tools, plus JSON, CSV, and text with dual logging system

🌐 **SOCKS5 Proxy Support**: Built-in SOCKS5 proxy support with authentication for bypassing network restrictions

⚙️ **Configuration-Driven**: XDG-compliant JSON configuration files with CLI override capability and practical defaults

## Architecture

HTTPSeal combines several Linux technologies to create isolated HTTPS/HTTP interception:

1. **Mount Namespace Isolation**: Uses user namespaces with UID mapping (`unshare --map-root-user`) for isolated filesystem views
2. **DNS Hijacking**: Replaces `/etc/resolv.conf` to redirect DNS queries to local server
3. **IP Address Mapping**: Maps domain names to localhost addresses (127.0.0.0/8 range)
4. **HTTPS Proxy**: Intercepts traffic on port 443 and performs MITM decryption
5. **HTTP Proxy**: Intercepts plain HTTP traffic on port 80 (when enabled)
6. **Certificate Authority**: Dynamically generates and caches certificates for target domains (HTTPS only)
7. **Automatic CA Integration**: Merges HTTPSeal CA with system CA bundle in isolated namespace
8. **Environment Configuration**: Sets SSL/TLS environment variables for transparent certificate usage

## Requirements

- **Operating System**: Linux (kernel 3.8+ for user namespace support)
- **Linux Capabilities**:
  - `CAP_NET_BIND_SERVICE`: For binding to privileged ports (80, 443)
  - HTTPSeal uses user namespace UID mapping for mount operations (no `CAP_SYS_ADMIN` required)

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/hmgle/httpseal.git
cd httpseal

# Build the binary
make build

# Install with required capabilities
sudo make install
```

### Manual Installation

```bash
# Build
go build -o httpseal ./cmd/httpseal

# Install binary to any directory in your PATH (examples shown)
sudo cp httpseal /usr/local/bin/          # System-wide installation
# OR
# cp httpseal ~/.local/bin/                 # User-local installation
# OR
# cp httpseal /any/directory/in/your/PATH/  # Custom PATH directory

# IMPORTANT: Set required capability (only CAP_NET_BIND_SERVICE needed)
# Replace the path below with your actual installation directory
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/httpseal
# OR for user-local installation:
# sudo setcap 'cap_net_bind_service=+ep' ~/.local/bin/httpseal
```

## Usage

### Basic Usage

```bash
# Intercept HTTPS traffic
httpseal -vv -- wget https://api.github.com/users/octocat

# Intercept HTTP traffic (requires --enable-http flag)
httpseal -vv --enable-http -- curl http://httpbin.org/get

# Intercept both HTTPS and HTTP traffic
httpseal -vv --enable-http -- curl -v https://httpbin.org/get http://httpbin.org/headers

# Intercept any command with mixed traffic
httpseal -vv --enable-http -- python3 -c "import urllib.request; urllib.request.urlopen('http://example.com')"
```

### Advanced Usage

```bash
# Verbose mode with all traffic details (HTTPS and HTTP)
httpseal -v --enable-http -- curl -v https://httpbin.org/get http://httpbin.org/headers

# Extra verbose mode - shows all response bodies including binary content
httpseal -vv -- curl https://httpbin.org/get

# Use -vv for extra verbose (equivalent to old -V flag)
httpseal -vv --enable-http -- wget https://baidu.com

# Save mixed traffic to file in JSON format
httpseal --enable-http -o traffic.json --format json -- wget http://httpbin.org/get https://api.github.com/users/octocat

# Save traffic in HAR format for browser dev tools analysis
httpseal -o performance.har --format har -- curl https://api.github.com/users/octocat

# Use SOCKS5 proxy to bypass restrictions
httpseal --socks5-addr 127.0.0.1:1080 -- curl https://www.google.com

# Combine HAR output with Wireshark mirroring and SOCKS5
httpseal --socks5-addr 127.0.0.1:1080 --enable-mirror -o traffic.har --format har -- curl https://restricted-api.com

# HTTP-only monitoring with custom port
httpseal --enable-http --http-port 8080 -q -o http-traffic.log -- some-http-app

# Filter specific domains and limit logged body size (works for both protocols)
httpseal --enable-http --filter-domain httpbin.org --log-body-limit 1024 -- curl http://httpbin.org/get https://httpbin.org/json

# Minimal logging level for both HTTP and HTTPS
httpseal --enable-http --log-level minimal -o summary.txt -- wget http://httpbin.org/json

# 🦈 Wireshark Integration - Mirror both HTTPS and HTTP traffic
httpseal --enable-http --enable-mirror -- curl https://api.github.com/users/octocat http://httpbin.org/get

# Custom mirror port for Wireshark analysis of mixed traffic
httpseal --enable-http --enable-mirror --mirror-port 9090 -- wget https://httpbin.org/get http://httpbin.org/headers

# HAR format for browser dev tools and performance analysis
httpseal -o traffic.har --format har -- curl https://api.github.com/users/octocat

# Configuration file with advanced settings
httpseal --config ./my-config.json -- curl https://api.github.com/users/octocat

# Advanced filtering with explicit host/method/status filters and log size limits
httpseal --filter-host-suffix github.com --filter-method GET --filter-status 200 --log-body-limit 2048 --exclude-content-type image/ -o filtered.csv --format csv -- curl https://api.github.com/users/octocat

# SOCKS5 proxy support (useful for bypassing network restrictions)
httpseal --socks5-addr 127.0.0.1:1080 -- curl https://www.google.com

# SOCKS5 with authentication
httpseal --socks5-addr 127.0.0.1:1080 --socks5-user myuser --socks5-pass mypass -- wget https://github.com

# Configuration file usage
httpseal --config ./my-config.json -- curl https://httpbin.org/get

# Dual logging - minimal console, verbose file
httpseal --log-level minimal --file-log-level verbose -o detailed.log -- curl https://api.github.com/users/octocat

# Advanced filtering, DNS override, and connection management
httpseal --filter-domain github.com --upstream-dns 1.1.1.1:53 --connection-timeout 60 --log-body-limit 2048 -- curl https://api.github.com/users/octocat

# Certificate reuse for performance (automatic with persistent CA directory)
httpseal --ca-dir ./my-ca -o traffic.json -- curl https://api.github.com/users/octocat
```

## 🌊 Wireshark Integration (HTTP Mirror)

HTTPSeal features an **HTTP Mirror Server** that creates real-time HTTP replicas of decrypted HTTPS traffic and plain HTTP traffic, enabling Wireshark analysis without complex TLS certificate configuration.

### How It Works

```
Client → HTTPSeal (HTTPS Proxy) → Real Server
             ↓
    HTTP Mirror Server (localhost:8080)
             ↓
        Wireshark Capture
```

1. **HTTPS Interception**: HTTPSeal intercepts and decrypts HTTPS traffic as usual
2. **HTTP Mirroring**: Decrypted traffic is replicated as plain HTTP on a local port
3. **Wireshark Analysis**: Capture the mirror port to see all HTTPS traffic in plain text

### Quick Start with Wireshark

```bash
# Terminal 1: Start Wireshark and capture on loopback interface
wireshark -i lo -f "tcp port 8080"

# Terminal 2: Run HTTPSeal with mirror enabled
httpseal --enable-mirror -- curl https://api.github.com/users/octocat
```

### Mirror Features

- **🔥 Simplified TLS Analysis**: No certificate imports, no key files - just capture HTTP traffic
- **📊 Broad Protocol Support**: Works with all TLS versions (1.2, 1.3, modern cipher suites)
- **🎯 Real-time Streaming**: Traffic appears in Wireshark as it's intercepted
- **🏷️ Preserved Headers**: Original domain info preserved with `X-HTTPSeal-*` headers
- **⚡ Efficient Mirroring**: Minimal overhead, goroutine-based mirroring

### Mirror Options

```bash
# Enable mirror server (default port 8080)
httpseal --enable-mirror -- <command>

# Custom mirror port
httpseal --enable-mirror --mirror-port 9090 -- <command>

# Combine with other options
httpseal --enable-mirror -v --format json -o traffic.json -- <command>
```

### Wireshark Configuration

1. **Start Wireshark**: Capture on loopback interface (`lo`)
2. **Apply Filter**: Use `tcp port 8080` (or your custom mirror port)
3. **Run HTTPSeal**: Use `--enable-mirror` flag
4. **Watch Magic**: See decrypted HTTPS traffic as readable HTTP in Wireshark!

### Why This Approach Works Well

**Traditional Wireshark TLS Decryption**:

- ❌ Requires RSA private keys
- ❌ Only works with RSA key exchange (not modern ECDHE)
- ❌ Complex certificate management
- ❌ Limited TLS 1.3 support

**HTTPSeal Mirror Approach**:

- ✅ Works with ALL TLS versions and cipher suites
- ✅ Minimal certificate configuration
- ✅ Real-time streaming
- ✅ Works well with modern HTTPS (TLS 1.3, ECDHE, etc.)
- ✅ Combines HTTPSeal's process isolation with Wireshark's analysis power

### Example Mirror Headers

The mirrored HTTP traffic includes special headers for traceability:

```http
GET /users/octocat HTTP/1.1
Host: api.github.com
X-HTTPSeal-Original-Host: api.github.com
X-HTTPSeal-Mirror-ID: 12345
X-HTTPSeal-Timestamp: 2024-01-15T10:30:45Z
User-Agent: curl/7.68.0
```

## 📋 Configuration File Support

HTTPSeal supports JSON configuration files following XDG Base Directory specification:

### Default Configuration Location

```bash
# XDG-compliant paths (checked in order)
$XDG_CONFIG_HOME/httpseal/config.json
~/.config/httpseal/config.json
./.httpseal/config.json  # fallback
```

### Configuration File Example

```json
{
  "verbose": true,
  "output_file": "traffic.har",
  "output_format": "har",
  "log_level": "normal",
  "file_log_level": "verbose",
  "enable_http": true,
  "enable_mirror": true,
  "mirror_port": 8080,
  "upstream_dns": "1.1.1.1:53",
  "socks5_enabled": true,
  "socks5_address": "127.0.0.1:1080",
  "socks5_username": "myuser",
  "socks5_password": "mypass",
  "upstream_ca_file": "./certs/upstream-ca.pem",
  "upstream_client_cert": "./certs/client.pem",
  "upstream_client_key": "./certs/client-key.pem",
  "upstream_server_name": "api.internal.test",
  "connection_timeout": 60,
  "no_redact": false,
  "capture_body_limit": 1048576,
  "log_body_limit": 4096,
  "filter_domains": ["api.github.com", "httpbin.org"],
  "filter_host_suffix": ["github.com"],
  "filter_methods": ["GET"],
  "filter_status_codes": [200],
  "filter_paths": ["/users/"],
  "exclude_content_types": ["image/", "application/octet-stream"],
  "ca_dir": "./my-ca",
  "keep_ca": true
}
```

### Usage with Configuration File

```bash
# Use default config location
httpseal -- curl https://api.github.com/users/octocat

# Use custom config file
httpseal --config ./my-config.json -- wget https://httpbin.org/get

# Override config file settings with CLI flags (CLI takes precedence)
httpseal --config ./config.json --verbose --output traffic.json -- curl https://httpbin.org/get
```

### Compatibility and Semantics Notes

- `duration_ms` is now emitted explicitly in JSON, CSV, and HAR output.
- JSON request/response headers now preserve repeated values as arrays. For example, `"Set-Cookie": ["a=1", "b=2"]` instead of a single string.
- `--filter-domain`, `--filter-host-exact`, `--filter-host-suffix`, `--filter-method`, `--filter-status`, and `--filter-path` combine with AND semantics when used together.
- `--capture-body-limit` controls how many bytes are captured into logs per request/response. Small bodies stay in memory; larger bodies spill to a dedicated temp directory.
- `--log-body-limit` limits what gets written to console, text, CSV, JSON, and HAR output. `--max-body-size` is still accepted as a deprecated alias.
- Redaction is enabled by default for sensitive headers, URL query parameters, and text bodies. Use `--no-redact` to disable it.
- `--upstream-server-name` is a global SNI / hostname-verification override for every upstream TLS connection. It is intended for single-upstream or controlled testing scenarios.
- Wireshark mirror traffic keeps the original request and response bodies unredacted and untrimmed so captures reflect the actual exchange.

## 🌐 SOCKS5 Proxy Support

HTTPSeal includes comprehensive SOCKS5 proxy support for upstream connections, useful for bypassing network restrictions or routing traffic through VPNs:

### Basic SOCKS5 Usage

```bash
# Enable SOCKS5 with default address (127.0.0.1:1080)
httpseal --socks5 -- curl https://www.google.com

# Custom SOCKS5 address (auto-enables SOCKS5)
httpseal --socks5-addr 192.168.1.100:1080 -- wget https://github.com

# SOCKS5 with authentication
httpseal --socks5-addr 127.0.0.1:1080 --socks5-user myuser --socks5-pass mypass -- curl https://api.github.com
```

### SOCKS5 Features

- **Auto-enable**: Providing any SOCKS5 parameter automatically enables SOCKS5 mode
- **Authentication support**: Username/password authentication
- **Transparent operation**: Target applications are unaware of SOCKS5 proxy
- **Error handling**: Detailed error messages for SOCKS5 connection failures

### Common Use Cases

```bash
# Bypass GFW restrictions (mainland China)
httpseal --socks5-addr 127.0.0.1:1080 -- curl https://www.google.com

# Route through corporate proxy
httpseal --socks5-addr proxy.company.com:1080 --socks5-user employee --socks5-pass password -- wget https://external-api.com

# Combine with other features
httpseal --socks5-addr 127.0.0.1:1080 --enable-mirror -o traffic.har --format har -- curl https://restricted-site.com
```

## 📊 Output Formats and Logging

HTTPSeal provides multiple output formats with sophisticated logging control:

### Output Formats

#### 1. **HAR (HTTP Archive) Format**

Suitable for browser dev tools and performance analysis:

```bash
httpseal -o traffic.har --format har -- curl https://api.github.com/users/octocat
```

**HAR Features:**

- Full W3C HAR 1.2 specification compliance
- Complete request/response data with timing
- Compatible with browser developer tools
- Supports Chrome DevTools, Firefox, and HAR analysis tools

#### 2. **JSON Format**

Structured data for programmatic analysis:

```bash
httpseal -o traffic.json --format json -- curl https://httpbin.org/get
```

#### 3. **CSV Format**

Spreadsheet-compatible with complete data:

```bash
httpseal -o traffic.csv --format csv -- wget https://api.github.com/users/octocat
```

**CSV Features:**

- Headers and body content included
- Session ID correlation
- Timestamp and duration tracking
- JSON-encoded headers in CSV cells

#### 4. **Text Format**

Human-readable console output:

```bash
httpseal -o traffic.txt --format text -- curl https://httpbin.org/get
```

### Dual Logging System

HTTPSeal separates console and file logging for maximum flexibility:

```bash
# Different levels for console vs file
httpseal --log-level minimal --file-log-level verbose -o detailed.log -- curl https://api.github.com

# Console logging levels: none, minimal, normal, verbose
# File logging levels: none, minimal, normal, verbose

# Auto-verbose: File output automatically uses verbose level when -o is specified
httpseal -o traffic.log -- curl https://api.github.com  # File gets verbose level automatically

# Quiet mode requires output file
httpseal -q -o traffic.json -- curl https://api.github.com  # No console output, only file

# System logs separate from traffic logs
httpseal --log-file system.log -o traffic.json -- curl https://api.github.com
```

### Session Tracking

All traffic includes session IDs for correlation:

```bash
# Session ID format: tb_<unix_timestamp>
# Available in all output formats (JSON, CSV, HAR, text)
httpseal -o traffic.json --format json -- curl https://api.github.com
```

## 🛠️ Complete Command Line Reference

```bash
httpseal [options] -- <command> [args...]

Network Options:
      --dns-ip string           DNS server IP address (default "127.0.53.1")
      --dns-port int           DNS server port (default 53)
      --upstream-dns string    Upstream DNS server used for forwarded non-hijacked queries (default "8.8.8.8:53")
      --proxy-port int         HTTPS proxy port (default 443)
      --connection-timeout int  Client connection idle timeout in seconds (default 30)

Certificate Management:
      --ca-dir string          Certificate authority directory (default: $XDG_CONFIG_HOME/httpseal/ca/)
      --keep-ca                Keep CA directory after exit (legacy flag - default behavior now preserves CA)

HTTP Traffic Interception:
      --enable-http            Enable HTTP traffic interception (default: disabled)
      --http-port int          HTTP proxy port (default 80)

SOCKS5 Proxy Support:
      --socks5                 Enable SOCKS5 proxy with default address (127.0.0.1:1080)
      --socks5-addr string     SOCKS5 proxy address (auto-enables SOCKS5) (default "127.0.0.1:1080")
      --socks5-user string     SOCKS5 username for authentication (optional)
      --socks5-pass string     SOCKS5 password for authentication (optional)
      --upstream-ca-file string              Additional CA bundle used to verify upstream TLS certificates
      --upstream-client-cert string          Client certificate PEM used for upstream mTLS
      --upstream-client-key string           Client private key PEM used for upstream mTLS
      --upstream-server-name string          Globally override the upstream TLS server name for all upstream TLS connections
      --upstream-insecure-skip-verify        Skip upstream TLS certificate verification

Wireshark Integration:
      --enable-mirror          Enable HTTP mirror server for Wireshark analysis
      --mirror-port int        HTTP mirror server port for Wireshark capture (default 8080)

Output Options:
  -o, --output string          Output traffic to file (automatically uses verbose level for complete data)
      --format string          Output format: text, json, csv, har (default "text")
      --log-level string       Console logging level: none, minimal, normal, verbose, extra-verbose (default "normal")
      --file-log-level string  File logging level (defaults to verbose when -o is used): none, minimal, normal, verbose, extra-verbose
      --log-file string        Output system logs to file (separate from traffic data)
  -q, --quiet                  Suppress console output (quiet mode - requires -o)
  -v, --verbose                Enable verbose output (-v for verbose, -vv for extra-verbose)
      --no-redact              Disable default redaction of sensitive headers, URLs, and text bodies

Filtering and Limits:
      --filter-domain strings        Only log traffic for these domains (can be repeated)
      --filter-host-exact strings    Only log traffic for these exact hosts
      --filter-host-suffix strings   Only log traffic for hosts matching these suffixes
      --filter-method strings        Only log traffic for these HTTP methods
      --filter-status ints           Only log traffic for these HTTP status codes
      --filter-path strings          Only log traffic whose request path contains one of these strings
      --exclude-content-type strings Exclude these content types from logging (can be repeated)
      --capture-body-limit int       Maximum request/response body bytes to capture per message (default 1048576)
      --log-body-limit int           Maximum captured body bytes to print/write (bytes, 0=full captured body) (default 0)
      --max-body-size int            Deprecated alias for --log-body-limit

Configuration:
  -c, --config string          Configuration file path (default: XDG_CONFIG_HOME/httpseal/config.json)

Other Options:
  -h, --help                   Show help message
      --version                Show version
```

## Tips & Troubleshooting

### Tools that preserve file ownership

HTTPSeal launches your workload inside a user namespace. Utilities such as `tar` may attempt to restore the original UID/GID from an archive, which fails when those IDs are not mapped inside the namespace. HTTPSeal automatically injects `TAR_OPTIONS=--no-same-owner --no-same-permissions` whenever it detects `tar`, `gtar`, or `bsdtar` so extraction proceeds without the `Cannot change ownership` error. If your workflow needs different flags, override the variable explicitly before invoking HTTPSeal:

```bash
TAR_OPTIONS=--same-owner httpseal -- tar xf backup.tgz
```

### Privilege dropping fallbacks

To drop from namespace root back to the invoking user, HTTPSeal relies on `setpriv` (util-linux) or `runuser`. Some distributions or hardened kernels disallow this combination; in that case HTTPSeal keeps running as namespace root. The fallback warning is muted in normal mode to avoid noisy output—run with `-v` or `-vv` if you want to see detailed diagnostics about the privilege-drop attempt.

### `unshare: failed to execute newuidmap`

Some distributions do not ship `newuidmap`/`newgidmap` by default (often provided by the `uidmap` package). When those helpers are missing, util-linux `unshare` can fail if asked to apply extra UID/GID mappings.

HTTPSeal falls back to `unshare --map-root-user` only (no extra mappings) so the command still runs.

**Recommended**: install the package that provides `newuidmap`/`newgidmap` (Debian/Ubuntu: `sudo apt install uidmap`). This enables the extra UID/GID mappings HTTPSeal uses to drop back to your original user *inside* the namespace.

**Impact if you don’t install it**:
- Your command may appear as UID/GID `0` *inside* the namespace (even though UID 0 is mapped to your host user via `--map-root-user`, so files created on the host are still owned by you).
- Some tools change behavior when they detect “running as root” (config paths, safety checks, refusing to run, etc.).

## Certificate Management

HTTPSeal provides **automated certificate management** with persistent storage for optimal performance:

### Persistent CA Directory (NEW)

HTTPSeal now uses **XDG-compliant persistent CA directories** by default:

- **Default Location**: `$XDG_CONFIG_HOME/httpseal/ca/` (usually `~/.config/httpseal/ca/`)
- **Automatic Creation**: Directory created on first run with proper permissions
- **Certificate Reuse**: Same CA and domain certificates reused between sessions
- **Performance Boost**: Eliminates certificate regeneration for frequently accessed domains
- **Graceful Fallback**: Falls back to temporary directories if persistent path unavailable

```bash
# Default behavior - uses persistent CA directory
httpseal -- curl https://api.github.com/users/octocat

# First run: Creates ~/.config/httpseal/ca/ and generates certificates
# Second run: Reuses existing certificates - much faster startup!

# Custom persistent CA directory
httpseal --ca-dir ./my-ca-store -- curl https://api.github.com
```

### Key Benefits

✅ **Simple Setup**: No need to install CA certificates in your system's trust store

✅ **Complete Isolation**: CA certificates only exist within HTTPSeal's namespace - your system remains untouched

✅ **Automatic Cleanup**: All certificate changes are automatically cleaned up when HTTPSeal exits

✅ **Transparent Operation**: Target applications see the certificates as if they were system-installed

✅ **Performance Optimization**: Certificate reuse eliminates regeneration overhead

### Certificate Directory Behavior

- **Default**: Uses `$XDG_CONFIG_HOME/httpseal/ca/` - automatically preserved between sessions
- **Custom CA** (`--ca-dir path`): Uses specified directory - automatically preserved
- **Temporary Fallback**: If persistent directory creation fails, falls back to temp directory with automatic cleanup
- **Legacy Compatibility**: `--keep-ca` flag still supported for explicit control

## Development

### Project Structure

```
httpseal/
├── cmd/httpseal/           # Main application entry point
├── contrib/completion/     # Shell completion scripts
├── pkg/
│   ├── cert/              # Certificate authority and management
│   ├── dns/               # DNS server component
│   ├── logger/            # Enhanced logging functionality
│   ├── mirror/            # HTTP mirror server for Wireshark integration
│   ├── namespace/         # Process wrapper and namespace handling
│   ├── proxy/             # HTTPS proxy server
│   └── mount/             # OverlayFS mounting operations
└── internal/
    └── config/            # Configuration structures
```

### Development Commands

```bash
# Build development version with race detection
make dev

# Run tests
make test

# Code quality checks
make fmt      # Format code
make vet      # Run go vet
make lint     # Lint code (requires golangci-lint)

# Dependencies and cleanup
make deps     # Install/update dependencies
make clean    # Clean build artifacts

# Utility commands
make run-example  # Run example with wget
make check-caps   # Check installed capabilities
make help         # Show all available targets
```

## Advantages and Limitations

### Key Advantages

✅ **Dual Protocol Support**: Handles both HTTPS (with TLS decryption) and plain HTTP traffic interception

✅ **Process-Specific Isolation**: Only intercepts traffic from processes launched by HTTPSeal - no system-wide impact

✅ **Simple Configuration**: Target applications require no proxy settings or code modifications

✅ **Namespace Security**: Uses Linux mount namespaces for secure isolation without polluting system environment

✅ **Automatic Certificate Handling**: Completely automatic CA certificate management within isolated environment - no manual installation required

✅ **Transparent Interception**: Applications connect normally to domain names without knowing they're monitored

✅ **Advanced Filtering**: Domain filtering, content-type exclusions, body size limits, and session tracking

✅ **Multiple Output Formats**: Text, JSON, CSV, and HAR (HTTP Archive) with flexible logging levels

✅ **Configuration File Support**: JSON configuration with XDG Base Directory compliance and CLI override capability

✅ **SOCKS5 Proxy Support**: Full upstream SOCKS5 proxy with authentication for bypassing network restrictions

✅ **Dual Logging System**: Separate console and file logging levels with automatic verbose file output

✅ **Reduced Privilege Requirements**: Uses user namespace UID mapping to eliminate need for `CAP_SYS_ADMIN`, only requires `CAP_NET_BIND_SERVICE`

### Limitations

❌ **Linux Only**: Completely platform-specific - cannot work on Windows, macOS, or other systems

❌ **DNS Resolution Dependencies**: Applications using hard-coded IPs or custom DNS may bypass interception

❌ **Single Process Scope**: Cannot intercept traffic from processes not launched by HTTPSeal

❌ **Port Monopolization**: Prevents other HTTPS services on localhost:443 during operation (and HTTP services on localhost:80 when HTTP interception is enabled)

❌ **Limited Protocol Support**: Focuses on HTTP/HTTPS - no WebSocket, HTTP/2, or HTTP/3 support

❌ **Application Compatibility**: Some applications may not respect CA environment variables

❌ **No Interactive Manipulation**: Read-only traffic logging - cannot modify requests/responses in real-time

### Best Use Cases

🎯 **Well-Suited For**:

- **Linux development and debugging** with automatic certificate management
- **CLI tool traffic analysis** (`wget`, `curl`, custom applications) with persistent CA storage
- **HAR-based performance analysis** with browser dev tools integration
- **Wireshark-based network analysis** with simplified TLS setup
- **CI/CD pipeline integration** with structured logging and session tracking
- **SOCKS5-enabled environments** requiring proxy bypass for restricted networks
- **API integration testing** with persistent certificates and advanced filtering
- **Security research** requiring process isolation and comprehensive traffic analysis

🚫 **Not Suitable For**:

- Cross-platform development (Linux only)
- Interactive request/response modification
- Production environment monitoring
- High-volume or production traffic analysis
- Web browser traffic (use built-in browser dev tools instead)

## Browser Traffic Analysis

HTTPSeal **does not support browser traffic interception** and there are no plans to add this functionality.

### Why HTTPSeal Cannot Support Browsers

Modern web browsers use **independent certificate trust mechanisms** that bypass HTTPSeal's certificate replacement approach:

#### Chrome & Chromium-based Browsers

- Uses **NSS (Network Security Services)** library for all cryptographic operations
- Maintains independent certificate trust store at `$HOME/.pki/nssdb/`
- **Completely bypasses** system CA bundle (`/etc/ssl/certs/ca-certificates.crt`)
- Does not respect `SSL_CERT_FILE` or similar environment variables

#### Firefox

- Also uses **NSS library** with the same `$HOME/.pki/nssdb/` database
- Shares certificate trust store with Chrome/Chromium
- Independent of system certificate configuration
- Ignores HTTPSeal's namespace-isolated CA modifications

HTTPSeal's current architecture relies on:

1. **System CA bundle manipulation** within namespaces
2. **Environment variable configuration** (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, etc.)
3. **Bind mounting** modified CA certificates to `/etc/ssl/certs/`

Since browsers bypass all these mechanisms and use their own NSS database, HTTPSeal's CA certificates are invisible to browser processes.

### Alternative: Built-in Browser Developer Tools

Modern browsers already provide excellent built-in developer tools for HTTPS traffic analysis, making HTTPSeal support unnecessary.

**HTTPSeal Alternative for Browser-like Traffic:**

```bash
# Simulate browser requests with HTTPSeal
httpseal -- curl -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" https://example.com

# Test APIs that browsers would access
httpseal -- wget --user-agent="Mozilla/5.0 ..." https://api.example.com
```

## Security Considerations

> ⚠️ **Security Notice**: HTTPSeal is designed for development and testing environments. While thoroughly tested, it performs MITM operations and should be used only for authorized testing purposes. Do NOT use in production environments or with sensitive data.

- **Use only for authorized testing**: HTTPSeal performs MITM attacks on network traffic
- **Development environments only**: Designed for development and testing scenarios
- **Capability model**: Only requires `CAP_NET_BIND_SERVICE` for privileged port binding, uses user namespaces to avoid `CAP_SYS_ADMIN`
- **Namespace isolation**: Changes are contained within process namespaces and automatically cleaned up
- **No system modification**: HTTPSeal never modifies your system's certificate store or global network settings

## 📋 Example Outputs

### 1. Standard Mode with Session Tracking

```
[15:30:42] INFO: Starting HTTPSeal v0.1.0
[15:30:42] INFO: Listening on 0.0.0.0:443 (HTTPS), DNS on 127.0.53.1:53
[15:30:42] INFO: Process 'curl' started with PID 12345
----------------------------------------------------
[15:30:43] INFO: >> Request to api.github.com
[15:30:43] INFO: GET /users/octocat HTTP/1.1
[15:30:43] INFO: Host: api.github.com
[15:30:43] INFO: User-Agent: curl/8.5.0-DEV

[15:30:43] INFO: << Response from api.github.com
[15:30:43] INFO: HTTP/1.1 200 OK
[15:30:43] INFO: Content-Type: application/json; charset=utf-8
[15:30:43] INFO: Content-Length: 1234
[15:30:43] INFO: Session: tb_1640445042
----------------------------------------------------
```

### 2. SOCKS5 Proxy Mode

```
[15:30:42] INFO: Starting HTTPSeal v0.1.0
[15:30:42] INFO: SOCKS5 proxy enabled: 127.0.0.1:1080 (with authentication)
[15:30:42] INFO: Listening on 0.0.0.0:443 (HTTPS), DNS on 127.0.53.1:53
[15:30:42] DEBUG: Using SOCKS5 proxy 127.0.0.1:1080 for connection to api.github.com
----------------------------------------------------
```

### 3. HAR Output Example

```json
{
  "log": {
    "version": "1.2",
    "creator": {
      "name": "HTTPSeal",
      "version": "1.0.0",
      "comment": "HTTPS/HTTP traffic interceptor with process isolation"
    },
    "entries": [
      {
        "startedDateTime": "2025-07-25T15:01:19.942229159+08:00",
        "time": 2203,
        "request": {
          "method": "GET",
          "url": "/users/octocat",
          "httpVersion": "1.1",
          "headers": [
            { "name": "User-Agent", "value": "curl/8.5.0-DEV" },
            { "name": "Accept", "value": "*/*" }
          ],
          "queryString": [],
          "headersSize": 41,
          "bodySize": 0
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "1.1",
          "headers": [
            { "name": "Content-Type", "value": "application/json" },
            { "name": "Content-Length", "value": "290" }
          ],
          "content": {
            "size": 290,
            "mimeType": "application/json",
            "text": "{\"login\":\"octocat\",\"id\":1,...}"
          },
          "headersSize": 211,
          "bodySize": 290
        },
        "timings": { "wait": 2203 }
      }
    ]
  }
}
```

### 4. CSV Output with Complete Data

```csv
timestamp,session_id,domain,method,url,status_code,status,content_type,request_size,response_size,duration_ms,request_headers,response_headers,request_body,response_body
2025-07-25T15:01:19+08:00,tb_1640445042,api.github.com,GET,/users/octocat,200,200 OK,application/json,0,290,2203,"{""User-Agent"":[""curl/8.5.0-DEV""],""Accept"":[""*/*""]}","{""Content-Type"":[""application/json""],""Content-Length"":[""290""]}","","{""login"":""octocat"",""id"":1,...}"
```

### 5. Configuration File Usage

```bash
# ~/.config/httpseal/config.json
{
  "output_file": "traffic.har",
  "output_format": "har",
  "enable_mirror": true,
  "upstream_dns": "1.1.1.1:53",
  "socks5_enabled": true,
  "socks5_address": "127.0.0.1:1080",
  "no_redact": false,
  "capture_body_limit": 1048576,
  "log_body_limit": 2048,
  "filter_domains": ["api.github.com"],
  "filter_methods": ["GET"],
  "filter_status_codes": [200],
  "keep_ca": true,
  "ca_dir": "./my-ca"
}

# Console output when using config file
[15:30:42] INFO: Starting HTTPSeal v0.1.0
[15:30:42] INFO: SOCKS5 proxy enabled: 127.0.0.1:1080 (no authentication)
[15:30:42] INFO: HTTP Mirror Server enabled on port 8080 for Wireshark analysis
[15:30:42] INFO: Using CA directory: ./my-ca (will be preserved)
[15:30:42] INFO: Filtering domains: api.github.com
[15:30:42] INFO: Output format: HAR -> traffic.har
```

### 6. Dual Logging System

```bash
# Console (minimal level)
[15:30:43] INFO: >> GET /users/octocat
[15:30:43] INFO: << HTTP/1.1 200 OK

# File (verbose level) - detailed.log
[15:30:43] INFO: >> Request to api.github.com
GET /users/octocat HTTP/1.1
Host: api.github.com
User-Agent: curl/8.5.0-DEV
Accept: */*

[15:30:43] INFO: << Response from api.github.com
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 290
Date: Fri, 25 Jul 2025 07:01:19 GMT

Response body (290 bytes):
{"login":"octocat","id":1,"avatar_url":"https://github.com/images/error/octocat_happy.gif",...}
```

### 7. Advanced Filtering Output

```bash
# Only show GitHub API traffic, exclude images, limit logged body size
httpseal --filter-domain api.github.com --exclude-content-type image/ --log-body-limit 1024 -v

[15:30:42] INFO: Filtering domains: api.github.com
[15:30:42] INFO: Excluding content types: image/
[15:30:42] INFO: Maximum logged body size: 1024 bytes
[15:30:43] INFO: >> Request to api.github.com (passed filters)
[15:30:43] INFO: << Response: application/json (body truncated to 1024 bytes)
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

HTTPSeal is designed for legitimate development, debugging, and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations when using this tool.

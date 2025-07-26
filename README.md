# HTTPSeal

> ⚠️ **Work In Progress (WIP)** ⚠️  
> HTTPSeal is currently under active development and not yet ready for production use. Features may be incomplete, unstable, or subject to breaking changes. Use at your own risk and expect potential issues. Contributions and feedback are welcome!

HTTPSeal is a Linux command-line tool for intercepting and analyzing HTTPS/HTTP traffic from specific processes using namespace isolation and DNS hijacking.

## About the Name

**HTTPSeal** combines two powerful concepts:

- **HTTPS**: The secure web protocol this tool specializes in intercepting and analyzing
- **HTTP**: Plain text web protocol also supported for complete traffic visibility
- **Seal**: Representing the secure **encapsulation** and **isolation** of process traffic within a controlled environment

The name embodies the tool's core philosophy: creating a "sealed" environment where HTTPS/HTTP traffic can be precisely monitored without affecting the broader system—like sealing a process in an isolated chamber for examination.

### A Playful Nod to Wireshark

Yes, we'll admit it—**HTTPSeal** deliberately echoes the naming pattern of **Wireshark**, the legendary network analysis tool! 🦈

Just as Wireshark combines:
- **Wire** (network cables/connections) + **Shark** (a fierce predator that hunts through data)

HTTPSeal playfully follows suit:
- **HTTPS** (secure web protocol) + **Seal** (an agile marine hunter that "seals" its prey)

While Wireshark is the apex predator of the entire network ocean, HTTPSeal is the specialized hunter that focuses precisely on HTTPS/HTTP streams within isolated process territories. Think of it as evolving from a broad-spectrum network shark to a precision-targeted process seal! 🌊

## Features

- **Process-specific interception**: Only captures traffic from processes launched by HTTPSeal
- **Zero-configuration transparency**: Target applications require no proxy configuration
- **HTTPS/TLS decryption**: Performs MITM with dynamic certificate generation for encrypted traffic
- **HTTP plain text handling**: Direct interception and analysis of unencrypted HTTP traffic
- **Non-root execution**: Uses Linux Capabilities instead of full root privileges
- **Real-time traffic display**: Shows HTTP/HTTPS request and response details
- **Multiple output formats**: Text, JSON, CSV, and HAR (HTTP Archive) with configurable verbosity
- **Advanced filtering**: Domain filtering, content-type exclusion, body size limits, session tracking
- **Configuration file support**: JSON configuration with XDG Base Directory compliance
- **SOCKS5 proxy support**: Full upstream SOCKS5 proxy with authentication for bypassing restrictions
- **Dual logging system**: Separate console and file logging levels with intelligent defaults
- **Connection management**: Configurable timeouts, browser detection, smart connection persistence
- **🔥 Wireshark Integration**: HTTP mirror server for real-time Wireshark analysis of decrypted HTTPS and plain HTTP traffic

## Architecture

HTTPSeal combines several Linux technologies to create isolated HTTPS/HTTP interception:

1. **Mount Namespace Isolation**: Uses user namespaces with UID mapping (`unshare --map-root-user`) for isolated filesystem views
2. **DNS Hijacking**: Replaces `/etc/resolv.conf` to redirect DNS queries to local server
3. **IP Address Mapping**: Maps domain names to localhost addresses (127.0.0.0/8 range)
4. **HTTPS Proxy**: Intercepts traffic on port 443 and performs MITM decryption
5. **HTTP Proxy**: Intercepts plain HTTP traffic on port 80 (when enabled)
6. **Certificate Authority**: Dynamically generates and caches certificates for target domains (HTTPS only)
7. **Automatic CA Integration**: Merges HTTPSeal CA with system CA bundle in isolated namespace
8. **Environment Configuration**: Sets SSL/TLS environment variables for seamless certificate usage

## Requirements

- **Operating System**: Linux (kernel 3.8+ for user namespace support)  
- **Go Version**: 1.24.4 or later
- **Linux Capabilities**: 
  - `CAP_NET_BIND_SERVICE`: For binding to privileged ports (80, 443)
  - HTTPSeal uses user namespace UID mapping for mount operations (no `CAP_SYS_ADMIN` required)

## Installation

> ⚠️ **Development Version Notice**: This is a work-in-progress build. Expect potential compilation issues, runtime bugs, and incomplete features. The installation process may change as the project evolves.

### Build from Source

```bash
# Clone the repository
git clone https://github.com/hmgle/httpseal.git
cd httpseal

# Build the binary
make build

# Install with required capabilities
make install
```

### Manual Installation

```bash
# Build
go build -o httpseal ./cmd/httpseal

# Install binary
sudo cp httpseal /usr/local/bin/

# Set required capability (only CAP_NET_BIND_SERVICE needed)
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/httpseal
```

## Usage

### Basic Usage

```bash
# Intercept HTTPS traffic (default behavior)
httpseal -- wget https://api.github.com/users/octocat

# Intercept HTTP traffic (requires --enable-http flag)
httpseal --enable-http -- curl http://httpbin.org/get

# Intercept both HTTPS and HTTP traffic
httpseal --enable-http -- curl -v https://httpbin.org/get http://httpbin.org/headers

# Intercept any command with mixed traffic
httpseal --enable-http -- python3 -c "import urllib.request; urllib.request.urlopen('http://example.com')"
```

### Advanced Usage

```bash
# Verbose mode with all traffic details (HTTPS and HTTP)
httpseal -v --enable-http -- curl -v https://httpbin.org/get http://httpbin.org/headers

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

# Filter specific domains and limit body size (works for both protocols)
httpseal --enable-http --filter-domain httpbin.org --max-body-size 1024 -- curl http://httpbin.org/get https://httpbin.org/json

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

# Advanced filtering with session tracking and size limits
httpseal --filter-domain api.github.com --max-body-size 2048 --exclude-content-type image/ -o filtered.csv --format csv -- curl https://api.github.com/users/octocat

# SOCKS5 proxy support (useful for bypassing network restrictions)
httpseal --socks5-addr 127.0.0.1:1080 -- curl https://www.google.com

# SOCKS5 with authentication
httpseal --socks5-addr 127.0.0.1:1080 --socks5-user myuser --socks5-pass mypass -- wget https://github.com

# Configuration file usage
httpseal --config ./my-config.json -- curl https://httpbin.org/get

# Dual logging - minimal console, verbose file
httpseal --log-level minimal --file-log-level verbose -o detailed.log -- curl https://api.github.com/users/octocat

# Advanced filtering and connection management
httpseal --filter-domain github.com --connection-timeout 60 --max-body-size 2048 -- curl https://api.github.com/users/octocat

# Certificate reuse for performance
httpseal --ca-dir ./my-ca --keep-ca -o traffic.json -- curl https://api.github.com/users/octocat
```

## 🌊 Wireshark Integration (HTTP Mirror)

HTTPSeal features a **revolutionary HTTP Mirror Server** that creates real-time HTTP replicas of decrypted HTTPS traffic and plain HTTP traffic, enabling seamless Wireshark analysis without complex TLS certificate configuration.

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

- **🔥 Zero TLS Complexity**: No certificate imports, no key files - just capture HTTP traffic
- **📊 Perfect Protocol Support**: Works with all TLS versions (1.2, 1.3, modern cipher suites)
- **🎯 Real-time Streaming**: Traffic appears in Wireshark instantly as it's intercepted
- **🏷️ Enhanced Headers**: Original domain info preserved with `X-HTTPSeal-*` headers
- **⚡ High Performance**: Minimal overhead, efficient goroutine-based mirroring

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

### Why This Is Revolutionary

**Traditional Wireshark TLS Decryption**:
- ❌ Requires RSA private keys
- ❌ Only works with RSA key exchange (not modern ECDHE)
- ❌ Complex certificate management
- ❌ Limited TLS 1.3 support

**HTTPSeal Mirror Approach**:
- ✅ Works with ALL TLS versions and cipher suites
- ✅ Zero certificate configuration
- ✅ Real-time streaming
- ✅ Perfect for modern HTTPS (TLS 1.3, ECDHE, etc.)
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
  "socks5_enabled": true,
  "socks5_address": "127.0.0.1:1080",
  "socks5_username": "myuser",
  "socks5_password": "mypass",
  "connection_timeout": 60,
  "max_body_size": 4096,
  "filter_domains": ["api.github.com", "httpbin.org"],
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

## 🌐 SOCKS5 Proxy Support

HTTPSeal includes comprehensive SOCKS5 proxy support for upstream connections, perfect for bypassing network restrictions or routing traffic through VPNs:

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
Perfect for browser dev tools and performance analysis:
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
      --proxy-port int         HTTPS proxy port (default 443)
      --connection-timeout int  Client connection idle timeout in seconds (default 30)

Certificate Management:
      --ca-dir string          Certificate authority directory (default: auto-generated temp)
      --keep-ca                Keep CA directory after exit (useful for debugging/reuse)

HTTP Traffic Interception:
      --enable-http            Enable HTTP traffic interception (default: disabled)
      --http-port int          HTTP proxy port (default 80)

SOCKS5 Proxy Support:
      --socks5                 Enable SOCKS5 proxy with default address (127.0.0.1:1080)
      --socks5-addr string     SOCKS5 proxy address (auto-enables SOCKS5) (default "127.0.0.1:1080")
      --socks5-user string     SOCKS5 username for authentication (optional)
      --socks5-pass string     SOCKS5 password for authentication (optional)

Wireshark Integration:
      --enable-mirror          Enable HTTP mirror server for Wireshark analysis
      --mirror-port int        HTTP mirror server port for Wireshark capture (default 8080)

Output Options:
  -o, --output string          Output traffic to file (automatically uses verbose level for complete data)
      --format string          Output format: text, json, csv, har (default "text")
      --log-level string       Console logging level: none, minimal, normal, verbose (default "normal")
      --file-log-level string  File logging level (defaults to verbose when -o is used): none, minimal, normal, verbose
      --log-file string        Output system logs to file (separate from traffic data)
  -q, --quiet                  Suppress console output (quiet mode - requires -o)
  -v, --verbose                Enable verbose output

Filtering and Limits:
      --filter-domain strings        Only log traffic for these domains (can be repeated)
      --exclude-content-type strings Exclude these content types from logging (can be repeated)  
      --max-body-size int            Maximum response body size to log (bytes, 0=unlimited) (default 0)

Configuration:
  -c, --config string          Configuration file path (default: XDG_CONFIG_HOME/httpseal/config.json)

Other Options:
  -h, --help                   Show help message
      --version                Show version
```

## Certificate Management

HTTPSeal uses **automatic certificate management** - no manual CA installation required:

### Fully Automatic Operation

HTTPSeal **automatically** handles all certificate management when it runs:

1. **CA Generation**: Creates a root CA certificate on first run (stored in `ca/` directory)
2. **Bundle Merging**: Combines HTTPSeal's CA with your system's existing CA certificates  
3. **Namespace Installation**: Uses bind mounts to overlay the merged CA bundle to `/etc/ssl/certs/ca-certificates.crt` **within the isolated namespace only**
4. **Environment Setup**: Configures SSL/TLS environment variables (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, etc.)
5. **Dynamic Certificates**: Generates domain-specific certificates on-demand during interception

### Key Benefits

✅ **Zero Manual Setup**: No need to install CA certificates in your system's trust store

✅ **Complete Isolation**: CA certificates only exist within HTTPSeal's namespace - your system remains untouched

✅ **Automatic Cleanup**: All certificate changes are automatically cleaned up when HTTPSeal exits

✅ **Transparent Operation**: Target applications see the certificates as if they were system-installed

### No System Pollution

Unlike other HTTPS interception tools, HTTPSeal **never modifies your system's certificate store**. All certificate handling happens within the isolated namespace, providing both security and convenience.

### Advanced Certificate Options

```bash
# Use custom CA directory for certificate reuse
httpseal --ca-dir ./my-ca -- curl https://api.github.com/users/octocat

# Keep CA directory after exit (useful for debugging or reuse)
httpseal --keep-ca --ca-dir ./persistent-ca -- curl https://api.github.com/users/octocat

# Reuse existing CA directory for better performance
httpseal --ca-dir ./existing-ca --keep-ca -- curl https://api.github.com/users/octocat
```

### Certificate Directory Behavior

- **Default behavior**: Creates temporary CA directory, automatically cleaned up on exit
- **Custom CA directory** (`--ca-dir`): Uses specified directory, cleaned up unless `--keep-ca` is used
- **Keep CA** (`--keep-ca`): Preserves CA directory after exit for reuse in subsequent runs
- **Performance benefit**: Reusing CA directories avoids regenerating certificates for the same domains

## Development

### Project Structure

```
httpseal/
├── cmd/httpseal/           # Main application entry point
├── pkg/
│   ├── cert/              # Certificate authority and management
│   ├── dns/               # DNS server component
│   ├── logger/            # Enhanced logging functionality
│   ├── mirror/            # HTTP mirror server for Wireshark integration
│   ├── namespace/         # Process wrapper and namespace handling
│   ├── proxy/             # HTTPS proxy server
│   └── mount/             # OverlayFS mounting operations
├── internal/
│   └── config/            # Configuration structures
└── CLAUDE.md              # Project guidance for AI assistants
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

✅ **Zero Configuration**: Target applications require no proxy settings or code modifications

✅ **Namespace Security**: Uses Linux mount namespaces for secure isolation without polluting system environment

✅ **Automatic Certificate Handling**: Completely automatic CA certificate management within isolated environment - no manual installation required

✅ **Transparent Interception**: Applications connect normally to domain names without knowing they're monitored

✅ **Advanced Filtering**: Domain filtering, content-type exclusions, body size limits, and session tracking

✅ **Multiple Output Formats**: Text, JSON, CSV, and HAR (HTTP Archive) with intelligent logging levels

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

### Comparison with Other Tools

| Feature | HTTPSeal | mitmproxy | Burp Suite | Wireshark |
|---------|----------|-----------|-------------|-----------|
| Process Isolation | ✅ Excellent | ❌ Global proxy | ❌ Global proxy | ❌ System-wide |
| Zero Config | ✅ Yes | ❌ Proxy setup required | ❌ Proxy setup required | ❌ Certificate import |
| HTTP/HTTPS Support | ✅ Both protocols | ✅ Both protocols | ✅ Both protocols | ✅ Both protocols |
| HAR Format Support | ✅ **Native** | ✅ Yes | ✅ Yes | ❌ No |
| SOCKS5 Proxy | ✅ **Built-in** | ✅ Yes | ✅ Yes | ❌ No |
| Configuration Files | ✅ **JSON+XDG** | ✅ YAML | ✅ Project files | ❌ No |
| Wireshark Integration | 🔥 **Native Mirror** | ❌ No | ❌ No | ✅ Self |
| Cross-Platform | ❌ Linux only | ✅ Yes | ✅ Yes | ✅ Yes |
| Interactive Editing | ❌ No | ✅ Yes | ✅ Yes | ❌ No |
| CLI Automation | ✅ **Perfect** | ✅ Good | ❌ Limited | ⚠️ Limited |
| TLS 1.3 Support | ✅ Full | ✅ Full | ✅ Full | ❌ Limited |
| Session Tracking | ✅ **Built-in** | ⚠️ Manual | ⚠️ Manual | ❌ No |
| Dual Logging | ✅ **Advanced** | ❌ Basic | ❌ Basic | ❌ No |
| Browser Traffic | ❌ Limited | ✅ Excellent | ✅ Excellent | ✅ Good |

### Best Use Cases

🎯 **Perfect For**:
- **Linux development and debugging environments** with complete traffic visibility
- **CLI tool traffic analysis** (`wget`, `curl`, custom applications) with mixed HTTP/HTTPS traffic
- **HAR-based performance analysis** using browser dev tools and performance monitoring tools
- **Wireshark-powered network analysis** with zero TLS complexity for both protocols
- **CI/CD pipeline integration** with structured logging (JSON, CSV, HAR) and session tracking
- **SOCKS5-enabled environments** requiring proxy bypass for restricted networks
- **Configuration-driven workflows** with JSON config files and XDG compliance
- **Malware analysis in isolated environments** (both encrypted and plain text communications)
- **API integration testing and debugging** across HTTP and HTTPS endpoints with complete session correlation
- **Security research** requiring both process isolation and dual protocol analysis with advanced filtering

🚫 **Not Suitable For**:
- Cross-platform development
- Web browser traffic interception
- Interactive request/response modification
- Production environment monitoring
- High-volume or enterprise traffic analysis

## Security Considerations

> ⚠️ **WIP Security Warning**: As a work-in-progress tool, HTTPSeal may contain security vulnerabilities, incomplete input validation, or unstable certificate handling. Do NOT use in production environments or with sensitive data.

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
            {"name": "User-Agent", "value": "curl/8.5.0-DEV"},
            {"name": "Accept", "value": "*/*"}
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
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Content-Length", "value": "290"}
          ],
          "content": {
            "size": 290,
            "mimeType": "application/json",
            "text": "{\"login\":\"octocat\",\"id\":1,...}"
          },
          "headersSize": 211,
          "bodySize": 290
        },
        "timings": {"wait": 2203}
      }
    ]
  }
}
```

### 4. CSV Output with Complete Data
```csv
timestamp,session_id,domain,method,url,status_code,status,content_type,request_size,response_size,duration_ms,request_headers,response_headers,request_body,response_body
2025-07-25T15:01:19+08:00,tb_1640445042,api.github.com,GET,/users/octocat,200,200 OK,application/json,0,290,2203,"{""User-Agent"":""curl/8.5.0-DEV"",""Accept"":""*/*""}","{""Content-Type"":""application/json"",""Content-Length"":""290""}","","{""login"":""octocat"",""id"":1,...}"
```

### 5. Configuration File Usage
```bash
# ~/.config/httpseal/config.json
{
  "output_file": "traffic.har",
  "output_format": "har",
  "enable_mirror": true,
  "socks5_enabled": true,
  "socks5_address": "127.0.0.1:1080",
  "filter_domains": ["api.github.com"],
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
# Only show GitHub API traffic, exclude images, limit body size
httpseal --filter-domain api.github.com --exclude-content-type image/ --max-body-size 1024 -v

[15:30:42] INFO: Filtering domains: api.github.com
[15:30:42] INFO: Excluding content types: image/
[15:30:42] INFO: Maximum body size: 1024 bytes
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

**WIP Status**: HTTPSeal is currently under active development (Work In Progress). Features may be incomplete, unstable, or contain bugs. This tool is provided "as-is" without any warranties.

HTTPSeal is designed for legitimate development, debugging, and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations when using this tool.
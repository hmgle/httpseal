# HTTPSeal

HTTPSeal is a Linux command-line tool for intercepting and analyzing HTTPS traffic from specific processes using namespace isolation and DNS hijacking.

## About the Name

**HTTPSeal** combines two powerful concepts:

- **HTTPS**: The secure web protocol this tool specializes in intercepting and analyzing
- **Seal**: Representing the secure **encapsulation** and **isolation** of process traffic within a controlled environment

The name embodies the tool's core philosophy: creating a "sealed" environment where HTTPS traffic can be precisely monitored without affecting the broader system—like sealing a process in an isolated chamber for examination.

### A Playful Nod to Wireshark

Yes, we'll admit it—**HTTPSeal** deliberately echoes the naming pattern of **Wireshark**, the legendary network analysis tool! 🦈

Just as Wireshark combines:
- **Wire** (network cables/connections) + **Shark** (a fierce predator that hunts through data)

HTTPSeal playfully follows suit:
- **HTTPS** (secure web protocol) + **Seal** (an agile marine hunter that "seals" its prey)

While Wireshark is the apex predator of the entire network ocean, HTTPSeal is the specialized hunter that focuses precisely on HTTPS streams within isolated process territories. Think of it as evolving from a broad-spectrum network shark to a precision-targeted process seal! 🌊

## Features

- **Process-specific interception**: Only captures traffic from processes launched by HTTPSeal
- **Zero-configuration transparency**: Target applications require no proxy configuration
- **HTTPS/TLS decryption**: Performs MITM with dynamic certificate generation
- **Non-root execution**: Uses Linux Capabilities instead of full root privileges
- **Real-time traffic display**: Shows HTTP/HTTPS request and response details
- **Multiple output formats**: Text, JSON, and CSV with configurable verbosity
- **Advanced filtering**: Domain filtering, content-type exclusion, body size limits

## Architecture

HTTPSeal combines several Linux technologies:

1. **Mount Namespace Isolation**: Creates isolated filesystem views using `unshare(CLONE_NEWNS)`
2. **DNS Hijacking**: Replaces `/etc/resolv.conf` to redirect DNS queries to local server
3. **IP Address Mapping**: Maps domain names to localhost addresses (127.0.0.0/8 range)
4. **HTTPS Proxy**: Intercepts traffic on port 443 and performs MITM decryption
5. **Certificate Authority**: Dynamically generates certificates for target domains

## Requirements

- **Operating System**: Linux
- **Go Version**: 1.24.4 or later
- **Linux Capabilities**: 
  - `CAP_SYS_ADMIN`: For creating mount namespaces
  - `CAP_NET_BIND_SERVICE`: For binding to privileged ports

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/httpseal/httpseal.git
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

# Set required capabilities
sudo setcap 'cap_net_bind_service,cap_sys_admin=+ep' /usr/local/bin/httpseal
```

## Usage

### Basic Usage

```bash
# Intercept wget traffic
httpseal -- wget https://api.github.com/users/octocat

# Intercept curl traffic
httpseal -- curl -v https://httpbin.org/get

# Intercept any command
httpseal -- python3 -c "import urllib.request; urllib.request.urlopen('https://example.com')"
```

### Advanced Usage

```bash
# Verbose mode with all traffic details
httpseal -v -- curl -v https://httpbin.org/get

# Save traffic to file in JSON format
httpseal -o traffic.json --format json -- wget https://baidu.com

# Quiet mode - only save to file, no console output
httpseal -q -o traffic.log -- curl https://api.github.com/repos/golang/go

# Filter specific domains and limit body size
httpseal --filter-domain api.github.com --max-body-size 1024 -- curl https://api.github.com/users/octocat

# Minimal logging level
httpseal --log-level minimal -o summary.txt -- wget https://httpbin.org/json
```

### Command Line Options

```bash
httpseal [options] -- <command> [args...]

Network Options:
      --dns-ip string           DNS server IP address (default "127.0.53.1")
      --dns-port int           DNS server port (default 53)
      --proxy-port int         HTTPS proxy port (default 443)
      --ca-dir string          Certificate authority directory (default "ca")

Output Options:
  -o, --output string          Output file for traffic logs
      --format string          Output format: text, json, csv (default "text")
      --log-level string       Logging level: none, minimal, normal, verbose (default "normal")
  -q, --quiet                  Quiet mode - no console output
  -v, --verbose                Verbose output

Filtering Options:
      --filter-domain strings        Only log traffic for specified domains
      --exclude-content-type strings Exclude specific content types from logging
      --max-body-size int            Maximum body size to log in bytes (default 4096)

Other Options:
  -h, --help                   Show help message
      --version                Show version
```

## CA Certificate Installation

**IMPORTANT**: For HTTPS interception to work, you must install HTTPSeal's CA certificate:

```bash
# After first run, the CA certificate will be generated in ca/ca.crt
# Install it to your system's trust store:

# For Ubuntu/Debian:
sudo cp ca/ca.crt /usr/local/share/ca-certificates/httpseal-ca.crt
sudo update-ca-certificates

# For CentOS/RHEL:
sudo cp ca/ca.crt /etc/pki/ca-trust/source/anchors/httpseal-ca.crt
sudo update-ca-trust

# For Firefox (separate trust store):
# Import ca/ca.crt through Firefox Settings > Certificates
```

## Development

### Project Structure

```
httpseal/
├── cmd/httpseal/           # Main application entry point
├── pkg/
│   ├── cert/              # Certificate authority and management
│   ├── dns/               # DNS server component
│   ├── logger/            # Enhanced logging functionality
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

## Security Considerations

- **Use only for authorized testing**: HTTPSeal performs MITM attacks on network traffic
- **Development environments only**: Installing the CA certificate reduces system security
- **Remove CA when done**: Uninstall the CA certificate when not actively using HTTPSeal
- **Capability model**: While safer than full root, `CAP_SYS_ADMIN` is still a powerful privilege

## Example Output

```
[15:30:42] INFO: Starting HTTPSeal v0.1.0
[15:30:42] INFO: Listening on 0.0.0.0:443 (HTTPS), DNS on 127.0.53.1:53
[15:30:42] INFO: Starting process 'wget' with PID will be assigned...
[15:30:42] INFO: Process 'wget' started with PID 12345
----------------------------------------------------
[15:30:43] INFO: >> Request to api.github.com (from 127.0.0.2)
[15:30:43] INFO: GET /users/octocat HTTP/1.1
[15:30:43] INFO: Host: api.github.com
[15:30:43] INFO: User-Agent: Wget/1.21.3

[15:30:43] INFO: << Response from api.github.com
[15:30:43] INFO: HTTP/1.1 200 OK
[15:30:43] INFO: Content-Type: application/json; charset=utf-8
[15:30:43] INFO: Content-Length: 1234
----------------------------------------------------
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
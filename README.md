# HTTPSeal

English | [Simplified Chinese](README-zh.md)

HTTPSeal is a Linux command-line tool for intercepting and logging HTTP and HTTPS traffic from a command that it launches. It uses Linux namespaces, DNS redirection, a local proxy, and a generated certificate authority to keep the interception scoped to the target process instead of changing system-wide proxy or trust settings.

## Demo

[![asciicast](https://asciinema.org/a/730013.svg)](https://asciinema.org/a/730013)

> Any credentials shown in the demo have been removed and invalidated.

## Requirements

- Linux with user namespace support enabled. User namespaces are available on Linux 3.8 and later, but some distributions or hardened systems disable them.
- `CAP_NET_BIND_SERVICE` on the `httpseal` binary when using the default privileged ports 443 and 80.
- `uidmap` (`newuidmap` and `newgidmap`) is recommended. HTTPSeal can fall back without it, but the target process may appear as UID/GID 0 inside the namespace.

HTTPSeal does not require installing its CA into the system trust store. It prepares an isolated CA bundle for the launched process.

## Installation

### Build From Source

```bash
git clone https://github.com/hmgle/httpseal.git
cd httpseal
make build
sudo make install
```

`make install` copies the binary to `/usr/local/bin/httpseal` and sets `cap_net_bind_service`.

### Manual Installation

```bash
go build -o httpseal ./cmd/httpseal
sudo cp httpseal /usr/local/bin/
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/httpseal
```

If you install the binary somewhere else, set the capability on that path.

## Quick Start

Use `--` to separate HTTPSeal flags from the command to run.

```bash
# Intercept HTTPS traffic.
httpseal -- curl https://api.github.com/users/octocat

# Show more request and response detail.
httpseal -v -- curl https://httpbin.org/get

# Include response bodies, including binary bodies, in log output.
httpseal -vv -- curl https://httpbin.org/get

# Intercept plain HTTP traffic as well as HTTPS.
httpseal --enable-http -- curl http://httpbin.org/get

# Write structured traffic logs.
httpseal -o traffic.json --format json -- curl https://httpbin.org/get
httpseal -o traffic.har --format har -- curl https://api.github.com/users/octocat

# Filter logged traffic.
httpseal --filter-host-suffix github.com --filter-method GET --log-body-limit 2048 -- curl https://api.github.com/users/octocat

# Mirror intercepted traffic as local HTTP for Wireshark.
httpseal --enable-mirror -- curl https://api.github.com/users/octocat

# Send upstream connections through SOCKS5.
httpseal --socks5-addr 127.0.0.1:1080 -- curl https://www.google.com

# Load settings from a config file. Explicit CLI flags override file values.
httpseal --config ./config.json --log-level minimal -- curl https://httpbin.org/get
```

## How It Works

1. HTTPSeal starts local DNS, HTTPS proxy, and optionally HTTP proxy and mirror servers.
2. The target command runs in a new namespace.
3. Inside that namespace, HTTPSeal bind-mounts generated resolver, hosts, NSS, and CA bundle files over the standard system paths.
4. DNS lookups from the target command resolve through HTTPSeal's DNS server.
5. Domains are mapped to loopback addresses, and connections on port 443 or optional port 80 reach HTTPSeal's local proxy.
6. HTTPS connections receive dynamically generated certificates signed by HTTPSeal's CA. The target process trusts this CA through the isolated CA bundle.
7. HTTPSeal forwards requests to the real upstream server, logs the exchange, and returns the upstream response to the target process.

By default, HTTPS interception is enabled and plain HTTP interception is disabled. Use `--enable-http` to intercept plain HTTP on port 80.

## Configuration

Unless `--config` is set, HTTPSeal reads one default JSON configuration path. The path is computed from the environment:

```bash
$XDG_CONFIG_HOME/httpseal/config.json    # when XDG_CONFIG_HOME is set
~/.config/httpseal/config.json           # otherwise, when HOME is available
./.httpseal/config.json                  # final fallback
```

You can also pass a file explicitly:

```bash
httpseal --config ./config.json -- curl https://httpbin.org/get
```

Explicitly changed CLI flags take precedence over values from the configuration file.

```json
{
  "verbose": false,
  "extra_verbose": false,
  "dns_ip": "127.0.53.1",
  "dns_port": 53,
  "upstream_dns": "8.8.8.8:53",
  "proxy_port": 443,
  "ca_dir": "",
  "keep_ca": false,
  "enable_http": true,
  "http_port": 80,
  "connection_timeout": 30,
  "socks5_enabled": false,
  "socks5_address": "127.0.0.1:1080",
  "socks5_username": "",
  "socks5_password": "",
  "upstream_ca_file": "",
  "upstream_client_cert": "",
  "upstream_client_key": "",
  "upstream_server_name": "",
  "upstream_insecure_skip_verify": false,
  "output_file": "",
  "output_format": "text",
  "log_level": "normal",
  "file_log_level": "",
  "log_file": "",
  "quiet": false,
  "no_redact": false,
  "capture_body_limit": 1048576,
  "log_body_limit": 0,
  "filter_domains": [],
  "filter_host_exact": [],
  "filter_host_suffix": [],
  "filter_methods": [],
  "filter_status_codes": [],
  "filter_paths": [],
  "exclude_content_types": ["image/", "video/", "audio/"],
  "decompress_response": true,
  "enable_mirror": false,
  "mirror_port": 8080
}
```

### CA Directory

If `ca_dir` or `--ca-dir` is not set, HTTPSeal uses:

```bash
$XDG_CONFIG_HOME/httpseal/ca
~/.config/httpseal/ca
```

The default CA directory is persistent. Generated CA and domain certificates are reused across runs. If the default directory cannot be created, HTTPSeal falls back to a temporary CA directory and removes it on exit unless `--keep-ca` is set.

## Logging and Output

HTTPSeal supports `text`, `json`, `csv`, and `har` output:

```bash
httpseal -o traffic.txt --format text -- curl https://httpbin.org/get
httpseal -o traffic.json --format json -- curl https://httpbin.org/get
httpseal -o traffic.csv --format csv -- curl https://httpbin.org/get
httpseal -o traffic.har --format har -- curl https://httpbin.org/get
```

Console and file logging levels can be set separately:

```bash
httpseal --log-level minimal --file-log-level verbose -o traffic.log -- curl https://httpbin.org/get
httpseal -q -o traffic.json --format json -- curl https://httpbin.org/get
httpseal --log-file system.log -o traffic.har --format har -- curl https://httpbin.org/get
```

Logging levels are `none`, `minimal`, `normal`, `verbose`, and `extra-verbose`. `-v` enables verbose mode, and `-vv` enables extra-verbose mode. When `-o` is used and `--file-log-level` is not set, file logging defaults to `verbose`. Quiet mode (`-q`) requires an output file.

Important logging semantics:

- `duration_ms` is emitted in JSON, CSV, and HAR output.
- JSON request and response headers preserve repeated header values as arrays.
- `--filter-domain`, `--filter-host-exact`, `--filter-host-suffix`, `--filter-method`, `--filter-status`, and `--filter-path` combine with AND semantics.
- `--capture-body-limit` controls how many bytes are captured per request or response. Larger bodies spill to a temporary file while the configured prefix is retained for logs.
- `--log-body-limit` controls how many captured body bytes are written to console, text, CSV, JSON, and HAR output. `--max-body-size` remains as a deprecated alias.
- Sensitive headers, URL query parameters, and text bodies are redacted by default. Use `--no-redact` to disable redaction.
- Compressed response bodies are decompressed for logging by default. Use `--decompress-response=false` to keep compressed bodies as-is in logs.

## Wireshark Mirror

`--enable-mirror` starts a local HTTP mirror server on `127.0.0.1:8080` by default. HTTPSeal sends a second, plain HTTP representation of each intercepted exchange to this port so tools such as Wireshark can inspect the request and response without TLS decryption setup.

```bash
# Terminal 1
wireshark -i lo -f "tcp port 8080"

# Terminal 2
httpseal --enable-mirror -- curl https://api.github.com/users/octocat
```

Use a different mirror port when needed:

```bash
httpseal --enable-mirror --mirror-port 9090 -- curl https://httpbin.org/get
```

Mirror traffic includes trace headers such as `X-HTTPSeal-Original-Host`, `X-HTTPSeal-Mirror-ID`, and `X-HTTPSeal-Timestamp`. The mirror path uses the original request and response bodies before log redaction and log body trimming, so treat mirror captures as sensitive.

## SOCKS5 and Upstream TLS

SOCKS5 applies to upstream connections from HTTPSeal to the real server. The target application does not need proxy settings.

```bash
# Use the default SOCKS5 address, 127.0.0.1:1080.
httpseal --socks5 -- curl https://www.google.com

# Setting any SOCKS5 parameter also enables SOCKS5 mode.
httpseal --socks5-addr 127.0.0.1:1080 -- curl https://www.google.com

# Username/password authentication.
httpseal --socks5-addr 127.0.0.1:1080 --socks5-user user --socks5-pass pass -- curl https://api.github.com
```

Upstream TLS options configure how HTTPSeal verifies and authenticates to the real server:

```bash
httpseal \
  --upstream-ca-file ./certs/upstream-ca.pem \
  --upstream-client-cert ./certs/client.pem \
  --upstream-client-key ./certs/client-key.pem \
  -- curl https://internal.example.test
```

`--upstream-server-name` globally overrides SNI and hostname verification for every upstream TLS connection. Use it only when all intercepted TLS traffic is expected to match the same certificate name. `--upstream-insecure-skip-verify` disables upstream certificate verification and should be limited to controlled test environments.

## CLI Reference

```text
httpseal [flags] -- <command> [args...]

Network:
      --dns-ip string                   DNS server IP address (default "127.0.53.1")
      --dns-port int                    DNS server port (default 53)
      --upstream-dns string             Upstream DNS server used for forwarded non-hijacked queries (default "8.8.8.8:53")
      --proxy-port int                  HTTPS proxy port (default 443)
      --connection-timeout int          Client connection idle timeout in seconds (default 30)

Certificate management:
      --ca-dir string                   Certificate authority directory (default: XDG_CONFIG_HOME/httpseal/ca)
      --keep-ca                         Keep CA directory after exit (always true for default persistent directory)

HTTP interception:
      --enable-http                     Enable HTTP traffic interception (default: disabled)
      --http-port int                   HTTP proxy port (default 80)

SOCKS5 and upstream TLS:
      --socks5                          Enable SOCKS5 proxy with default address (127.0.0.1:1080)
      --socks5-addr string              SOCKS5 proxy address (auto-enables SOCKS5 when specified) (default "127.0.0.1:1080")
      --socks5-user string              SOCKS5 username for authentication (optional)
      --socks5-pass string              SOCKS5 password for authentication (optional)
      --upstream-ca-file string         Additional CA bundle used to verify upstream TLS certificates
      --upstream-client-cert string     Client certificate PEM used for upstream mTLS
      --upstream-client-key string      Client private key PEM used for upstream mTLS
      --upstream-server-name string     Globally override the upstream TLS server name for all upstream TLS connections
      --upstream-insecure-skip-verify   Skip upstream TLS certificate verification

Wireshark mirror:
      --enable-mirror                   Enable HTTP mirror server for Wireshark analysis
      --mirror-port int                 HTTP mirror server port for Wireshark capture (default 8080)

Output:
  -o, --output string                   Output traffic to file
      --format string                   Output format: text, json, csv, har (default "text")
      --log-level string                Console logging level: none, minimal, normal, verbose, extra-verbose (default "normal")
      --file-log-level string           File logging level (defaults to verbose when -o is used): none, minimal, normal, verbose, extra-verbose
      --log-file string                 Output system logs to file (separate from traffic data)
  -q, --quiet                           Suppress console output
  -v, --verbose count                   Enable verbose output (-v for verbose, -vv for extra-verbose)
      --no-redact                       Disable default redaction of sensitive headers, URLs, and text bodies

Filtering and body handling:
      --filter-domain strings           Only log traffic for these domains (can be repeated)
      --filter-host-exact strings       Only log traffic for these exact hosts
      --filter-host-suffix strings      Only log traffic for hosts matching these suffixes
      --filter-method strings           Only log traffic for these HTTP methods
      --filter-status ints              Only log traffic for these HTTP status codes
      --filter-path strings             Only log traffic whose request path contains one of these strings
      --exclude-content-type strings    Exclude these content types from logging
      --capture-body-limit int          Maximum request/response body bytes to capture per message (0=unlimited) (default 1048576)
      --log-body-limit int              Maximum captured body bytes to print/write (0=full captured body)
      --max-body-size int               Deprecated alias for --log-body-limit
      --decompress-response             Decompress compressed response bodies for logging (default true)

Configuration and metadata:
  -c, --config string                   Configuration file path (default: XDG_CONFIG_HOME/httpseal/config.json)
  -h, --help                            Show help
      --version                         Show version
```

## Troubleshooting

### Privileged Ports

The default HTTPS and HTTP interception ports are 443 and 80. If HTTPSeal cannot bind those ports, set the required capability:

```bash
sudo setcap 'cap_net_bind_service=+ep' "$(command -v httpseal)"
```

You can also choose unprivileged ports with `--proxy-port` and `--http-port`, but transparent interception of normal HTTPS/HTTP traffic expects the standard ports.

### `unshare: failed to execute newuidmap`

Some systems do not install `newuidmap` and `newgidmap` by default. On Debian and Ubuntu, install them with:

```bash
sudo apt install uidmap
```

If these helpers are missing, HTTPSeal falls back to `unshare --map-root-user`. In that fallback mode, the process may appear as UID/GID 0 inside the namespace, while files created on the host still map to the invoking user.

### Privilege Dropping Fallbacks

HTTPSeal tries to drop from namespace root back to the invoking user with `setpriv`, and then `runuser` when available. Some systems reject this. If privilege dropping fails, HTTPSeal continues as namespace root. Use `-v` or `-vv` to show the fallback details.

### Tools That Preserve File Ownership

Archive tools such as `tar`, `gtar`, and `bsdtar` may try to restore UID/GID values that are not mapped inside the namespace. HTTPSeal detects these commands and sets:

```bash
TAR_OPTIONS=--no-same-owner --no-same-permissions
```

Set `TAR_OPTIONS` yourself before running HTTPSeal if you need different behavior.

### Traffic Is Not Intercepted

Common causes:

- The target application uses hard-coded IP addresses instead of DNS.
- The target application uses a custom resolver or ignores `/etc/resolv.conf`.
- The target application does not use the CA locations or environment variables prepared by HTTPSeal.
- Another local service is already bound to port 443, or to port 80 when `--enable-http` is used.
- The target protocol is not HTTP over TLS or plain HTTP.

## Development

Project layout:

```text
cmd/httpseal/        CLI entry point
internal/config/     Configuration loading and merge logic
pkg/cert/            CA and dynamic certificate generation
pkg/dns/             DNS server and domain-to-loopback mapping
pkg/logger/          Traffic records, redaction, output formats
pkg/mirror/          Local HTTP mirror server
pkg/mount/           Mount helpers
pkg/namespace/       Namespace wrapper and bind mounts
pkg/proxy/           HTTPS and HTTP interception proxy
```

Common commands:

```bash
make build
make test
make fmt
make vet
make lint
make dev
make clean
```

## Security

HTTPSeal performs man-in-the-middle interception for the process it launches. Use it only for development, debugging, and authorized security testing.

HTTPSeal is designed to avoid system-wide trust or proxy changes, but captured traffic can include credentials, tokens, cookies, and request or response bodies. Store logs and mirror captures accordingly. Do not use HTTPSeal for production monitoring or for traffic you are not authorized to inspect.

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Run the relevant checks.
4. Open a pull request with a concise description of the change.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

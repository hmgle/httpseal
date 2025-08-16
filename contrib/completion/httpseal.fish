# httpseal fish completion script

# Common content types for --exclude-content-type
set -l content_types 'application/json' 'application/xml' 'text/html' 'text/plain' 'image/jpeg' 'image/png' 'video/mp4' 'application/octet-stream' 'application/pdf'

# Log levels
set -l log_levels none minimal normal verbose

# Output formats
set -l output_formats text json csv har

# Common values for various options
set -l timeout_values 30 60 120 300
set -l dns_ips '127.0.53.1' '127.0.0.1'
set -l dns_ports 53 5353
set -l http_ports 80 8080 3128
set -l https_ports 443 8443
set -l mirror_ports 8080 9090 8000
set -l socks5_addrs '127.0.0.1:1080' '127.0.0.1:1081'
set -l body_sizes 0 1024 4096 65536 10485760

# Check if we're after -- separator
function __httpseal_after_separator
    set -l cmd (commandline -poc)
    for i in (seq (count $cmd))
        if test "$cmd[$i]" = "--"
            return 0
        end
    end
    return 1
end

# Main completion function
complete -c httpseal -f

# Network settings
complete -c httpseal -l dns-ip -d "DNS server IP address" -xa "$dns_ips"
complete -c httpseal -l dns-port -d "DNS server port" -xa "$dns_ports"
complete -c httpseal -l proxy-port -d "HTTPS proxy port" -xa "$https_ports"
complete -c httpseal -l ca-dir -d "Certificate authority directory" -xa "(__fish_complete_directories)"
complete -c httpseal -l keep-ca -d "Keep CA directory after exit"

# HTTP traffic interception
complete -c httpseal -l enable-http -d "Enable HTTP traffic interception"
complete -c httpseal -l http-port -d "HTTP proxy port" -xa "$http_ports"

# Connection settings
complete -c httpseal -l connection-timeout -d "Client connection idle timeout in seconds" -xa "$timeout_values"

# SOCKS5 proxy settings
complete -c httpseal -l socks5 -d "Enable SOCKS5 proxy with default address"
complete -c httpseal -l socks5-addr -d "SOCKS5 proxy address" -xa "$socks5_addrs"
complete -c httpseal -l socks5-user -d "SOCKS5 username for authentication"
complete -c httpseal -l socks5-pass -d "SOCKS5 password for authentication"

# Traffic logging and output
complete -c httpseal -s o -l output -d "Output traffic to file" -rF
complete -c httpseal -l format -d "Output format" -xa "$output_formats"
complete -c httpseal -l log-level -d "Console logging level" -xa "$log_levels"
complete -c httpseal -l file-log-level -d "File logging level" -xa "$log_levels"
complete -c httpseal -l log-file -d "Output system logs to file" -rF
complete -c httpseal -s q -l quiet -d "Suppress console output (quiet mode)"
complete -c httpseal -l max-body-size -d "Maximum response body size to log (bytes, 0=unlimited)" -xa "$body_sizes"
complete -c httpseal -l filter-domain -d "Only log traffic for these domains"
complete -c httpseal -l exclude-content-type -d "Exclude these content types from logging" -xa "$content_types"

# Wireshark integration
complete -c httpseal -l enable-mirror -d "Enable HTTP mirror server for Wireshark analysis"
complete -c httpseal -l mirror-port -d "HTTP mirror server port for Wireshark capture" -xa "$mirror_ports"

# Configuration file
complete -c httpseal -s c -l config -d "Configuration file path" -rF

# Verbose mode
complete -c httpseal -s v -l verbose -d "Enable verbose output (-v for verbose, -vv for extra-verbose)"

# Help and version
complete -c httpseal -s h -l help -d "Show help"
complete -c httpseal -l version -d "Show version"

# Complete commands after -- separator
complete -c httpseal -n '__httpseal_after_separator' -xa "(__fish_complete_command)"
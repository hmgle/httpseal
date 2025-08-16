#!/bin/bash

# httpseal bash completion script

_httpseal() {
    local cur prev words cword
    _init_completion || return

    local common_content_types=(
        'application/json'
        'application/xml'
        'text/html'
        'text/plain'
        'image/jpeg'
        'image/png'
        'video/mp4'
        'application/octet-stream'
        'application/pdf'
    )

    local log_levels="none minimal normal verbose"
    local output_formats="text json csv har"
    local timeout_values="30 60 120 300"
    local dns_ips="127.0.53.1 127.0.0.1"
    local dns_ports="53 5353"
    local http_ports="80 8080 3128"
    local https_ports="443 8443"
    local mirror_ports="8080 9090 8000"
    local socks5_addrs="127.0.0.1:1080 127.0.0.1:1081"
    local body_sizes="0 1024 4096 65536 10485760"

    # Check if we're after -- separator
    local i
    for ((i=1; i < cword; i++)); do
        if [[ "${words[i]}" == "--" ]]; then
            # After --, complete normal commands
            _command_offset $((i + 1))
            return
        fi
    done

    case "$prev" in
        --ca-dir)
            _filedir -d
            return
            ;;
        -c|--config|--log-file|-o|--output)
            _filedir
            return
            ;;
        --connection-timeout)
            COMPREPLY=($(compgen -W "$timeout_values" -- "$cur"))
            return
            ;;
        --dns-ip)
            COMPREPLY=($(compgen -W "$dns_ips" -- "$cur"))
            return
            ;;
        --dns-port)
            COMPREPLY=($(compgen -W "$dns_ports" -- "$cur"))
            return
            ;;
        --exclude-content-type)
            if [[ "$cur" == *,* ]]; then
                # Handle comma-separated values
                local prefix="${cur%,*},"
                local suffix="${cur##*,}"
                COMPREPLY=($(compgen -W "${common_content_types[*]}" -- "$suffix"))
                COMPREPLY=("${COMPREPLY[@]/#/$prefix}")
            else
                COMPREPLY=($(compgen -W "${common_content_types[*]}" -- "$cur"))
            fi
            return
            ;;
        --file-log-level|--log-level)
            COMPREPLY=($(compgen -W "$log_levels" -- "$cur"))
            return
            ;;
        --filter-domain)
            # Complete hostnames if possible
            _known_hosts_real -- "$cur"
            return
            ;;
        --format)
            COMPREPLY=($(compgen -W "$output_formats" -- "$cur"))
            return
            ;;
        --http-port)
            COMPREPLY=($(compgen -W "$http_ports" -- "$cur"))
            return
            ;;
        --max-body-size)
            COMPREPLY=($(compgen -W "$body_sizes" -- "$cur"))
            return
            ;;
        --mirror-port)
            COMPREPLY=($(compgen -W "$mirror_ports" -- "$cur"))
            return
            ;;
        --proxy-port)
            COMPREPLY=($(compgen -W "$https_ports" -- "$cur"))
            return
            ;;
        --socks5-addr)
            COMPREPLY=($(compgen -W "$socks5_addrs" -- "$cur"))
            return
            ;;
        --socks5-pass|--socks5-user)
            # No completion for passwords/usernames
            return
            ;;
    esac

    # Complete long options
    if [[ "$cur" == --* ]]; then
        local long_opts="
            --ca-dir
            --config
            --connection-timeout
            --dns-ip
            --dns-port
            --enable-http
            --enable-mirror
            --exclude-content-type
            --file-log-level
            --filter-domain
            --format
            --help
            --http-port
            --keep-ca
            --log-file
            --log-level
            --max-body-size
            --mirror-port
            --output
            --proxy-port
            --quiet
            --socks5
            --socks5-addr
            --socks5-pass
            --socks5-user
            --verbose
            --version
        "
        COMPREPLY=($(compgen -W "$long_opts" -- "$cur"))
        return
    fi

    # Complete short options
    if [[ "$cur" == -* ]]; then
        local short_opts="-c -h -o -q -v"
        COMPREPLY=($(compgen -W "$short_opts" -- "$cur"))
        return
    fi

    # If no -- found yet, suggest it
    if [[ "$cur" != "-"* ]]; then
        COMPREPLY=($(compgen -W "-- " -- "$cur"))
    fi
}

complete -F _httpseal httpseal
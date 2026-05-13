# HTTPSeal

[English](README.md) | 简体中文

HTTPSeal 是一个 Linux 命令行工具，用于拦截并记录由它启动的命令所产生的 HTTP 和 HTTPS 流量。它通过 Linux 命名空间、DNS 重定向、本地代理和动态生成的证书颁发机构，将拦截范围限制在目标进程内，而不是修改系统全局代理或信任设置。

## 演示

[![asciicast](https://asciinema.org/a/730013.svg)](https://asciinema.org/a/730013)

> 演示中出现过的凭据均已删除并失效。

## 系统要求

- 启用用户命名空间的 Linux。用户命名空间自 Linux 3.8 起可用，但部分发行版或加固系统可能禁用它。
- 使用默认特权端口 443 和 80 时，`httpseal` 二进制文件需要 `CAP_NET_BIND_SERVICE`。
- 建议安装 `uidmap`（提供 `newuidmap` 和 `newgidmap`）。没有它也可以回退运行，但目标进程在命名空间内可能显示为 UID/GID 0。

HTTPSeal 不需要把自己的 CA 安装到系统信任存储中。它会为被启动的进程准备隔离的 CA bundle。

## 安装

### 从源码构建

```bash
git clone https://github.com/hmgle/httpseal.git
cd httpseal
make build
sudo make install
```

`make install` 会把二进制文件复制到 `/usr/local/bin/httpseal`，并设置 `cap_net_bind_service`。

### 手动安装

```bash
go build -o httpseal ./cmd/httpseal
sudo cp httpseal /usr/local/bin/
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/httpseal
```

如果安装到其他路径，请对实际路径设置 capability。

## 快速开始

使用 `--` 分隔 HTTPSeal 的参数和要运行的命令。

```bash
# 拦截 HTTPS 流量。
httpseal -- curl https://api.github.com/users/octocat

# 显示更多请求和响应细节。
httpseal -v -- curl https://httpbin.org/get

# 在日志输出中包含响应体，包括二进制 body。
httpseal -vv -- curl https://httpbin.org/get

# 同时拦截明文 HTTP。
httpseal --enable-http -- curl http://httpbin.org/get

# 写入结构化流量日志。
httpseal -o traffic.json --format json -- curl https://httpbin.org/get
httpseal -o traffic.har --format har -- curl https://api.github.com/users/octocat

# 过滤要写入日志的流量。
httpseal --filter-host-suffix github.com --filter-method GET --log-body-limit 2048 -- curl https://api.github.com/users/octocat

# 将拦截到的流量镜像为本地 HTTP，便于 Wireshark 抓取。
httpseal --enable-mirror -- curl https://api.github.com/users/octocat

# 通过 SOCKS5 发起上游连接。
httpseal --socks5-addr 127.0.0.1:1080 -- curl https://www.google.com

# 从配置文件加载设置。显式传入的 CLI 参数会覆盖配置文件。
httpseal --config ./config.json --log-level minimal -- curl https://httpbin.org/get
```

## 工作原理

1. HTTPSeal 启动本地 DNS、HTTPS 代理，并按需启动 HTTP 代理和 mirror server。
2. 目标命令在新的命名空间内运行。
3. 在该命名空间内，HTTPSeal 会把生成的 resolver、hosts、NSS 和 CA bundle 文件 bind mount 到标准系统路径。
4. 目标命令的 DNS 查询会经过 HTTPSeal 的 DNS server。
5. 域名会被映射到 loopback 地址，访问 443 或可选的 80 端口时会进入 HTTPSeal 的本地代理。
6. HTTPS 连接会收到由 HTTPSeal CA 签发的动态证书。目标进程通过隔离的 CA bundle 信任该 CA。
7. HTTPSeal 将请求转发到真实上游服务器，记录交换内容，并把上游响应返回给目标进程。

默认只拦截 HTTPS。需要拦截明文 HTTP 时，使用 `--enable-http`。

## 配置

如果没有设置 `--config`，HTTPSeal 会读取一个默认 JSON 配置路径。该路径根据环境计算：

```bash
$XDG_CONFIG_HOME/httpseal/config.json    # 设置了 XDG_CONFIG_HOME 时
~/.config/httpseal/config.json           # 否则在 HOME 可用时
./.httpseal/config.json                  # 最终回退
```

也可以显式指定配置文件：

```bash
httpseal --config ./config.json -- curl https://httpbin.org/get
```

显式传入的 CLI 参数优先级高于配置文件。

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

### CA 目录

如果没有设置 `ca_dir` 或 `--ca-dir`，HTTPSeal 会使用：

```bash
$XDG_CONFIG_HOME/httpseal/ca
~/.config/httpseal/ca
```

默认 CA 目录是持久目录。生成的 CA 和域名证书会跨运行复用。如果默认目录无法创建，HTTPSeal 会回退到临时 CA 目录，并在退出时删除；设置 `--keep-ca` 时会保留该临时目录。

## 日志和输出

HTTPSeal 支持 `text`、`json`、`csv` 和 `har` 输出：

```bash
httpseal -o traffic.txt --format text -- curl https://httpbin.org/get
httpseal -o traffic.json --format json -- curl https://httpbin.org/get
httpseal -o traffic.csv --format csv -- curl https://httpbin.org/get
httpseal -o traffic.har --format har -- curl https://httpbin.org/get
```

控制台和文件日志级别可以分开设置：

```bash
httpseal --log-level minimal --file-log-level verbose -o traffic.log -- curl https://httpbin.org/get
httpseal -q -o traffic.json --format json -- curl https://httpbin.org/get
httpseal --log-file system.log -o traffic.har --format har -- curl https://httpbin.org/get
```

日志级别包括 `none`、`minimal`、`normal`、`verbose` 和 `extra-verbose`。`-v` 启用 verbose，`-vv` 启用 extra-verbose。使用 `-o` 且没有设置 `--file-log-level` 时，文件日志默认使用 `verbose`。静默模式 (`-q`) 必须同时设置输出文件。

重要语义：

- JSON、CSV 和 HAR 都会输出 `duration_ms`。
- JSON 的请求和响应 headers 会保留重复值，格式为字符串数组。
- `--filter-domain`、`--filter-host-exact`、`--filter-host-suffix`、`--filter-method`、`--filter-status` 和 `--filter-path` 同时使用时是 AND 关系。
- `--capture-body-limit` 控制每条请求或响应最多捕获多少字节。较大的 body 会落到临时文件，同时保留配置范围内的前缀用于日志。
- `--log-body-limit` 控制 console、text、CSV、JSON 和 HAR 最多写出多少已捕获 body 字节。`--max-body-size` 仍可用，但只是兼容别名。
- 默认会脱敏敏感 header、URL query 参数和文本 body。使用 `--no-redact` 可以关闭脱敏。
- 默认会为日志解压压缩响应体。使用 `--decompress-response=false` 可以让日志保留压缩 body 的原始状态。

## Wireshark Mirror

`--enable-mirror` 会启动本地 HTTP mirror server，默认监听 `127.0.0.1:8080`。HTTPSeal 会把每条拦截到的交换额外发送一份明文 HTTP 表示到该端口，Wireshark 等工具可以直接抓取，不需要配置 TLS 解密。

```bash
# 终端 1
wireshark -i lo -f "tcp port 8080"

# 终端 2
httpseal --enable-mirror -- curl https://api.github.com/users/octocat
```

需要其他端口时：

```bash
httpseal --enable-mirror --mirror-port 9090 -- curl https://httpbin.org/get
```

Mirror 流量会包含 `X-HTTPSeal-Original-Host`、`X-HTTPSeal-Mirror-ID` 和 `X-HTTPSeal-Timestamp` 等追踪 header。Mirror 使用的是日志脱敏和 body 裁剪之前的原始请求体和响应体，因此抓包文件应按敏感数据处理。

## SOCKS5 和上游 TLS

SOCKS5 作用于 HTTPSeal 到真实服务器的上游连接。目标应用不需要设置代理。

```bash
# 使用默认 SOCKS5 地址 127.0.0.1:1080。
httpseal --socks5 -- curl https://www.google.com

# 设置任一 SOCKS5 参数也会自动启用 SOCKS5。
httpseal --socks5-addr 127.0.0.1:1080 -- curl https://www.google.com

# 用户名和密码认证。
httpseal --socks5-addr 127.0.0.1:1080 --socks5-user user --socks5-pass pass -- curl https://api.github.com
```

上游 TLS 选项用于配置 HTTPSeal 如何校验真实服务器，以及如何向真实服务器认证：

```bash
httpseal \
  --upstream-ca-file ./certs/upstream-ca.pem \
  --upstream-client-cert ./certs/client.pem \
  --upstream-client-key ./certs/client-key.pem \
  -- curl https://internal.example.test
```

`--upstream-server-name` 会全局覆盖所有上游 TLS 连接的 SNI 和主机名校验。只有当所有被拦截的 TLS 流量都应匹配同一个证书名时才应使用它。`--upstream-insecure-skip-verify` 会关闭上游证书校验，应只用于受控测试环境。

## CLI 参考

```text
httpseal [flags] -- <command> [args...]

网络:
      --dns-ip string                   DNS server IP 地址 (默认 "127.0.53.1")
      --dns-port int                    DNS server 端口 (默认 53)
      --upstream-dns string             非劫持 DNS 查询使用的上游 DNS (默认 "8.8.8.8:53")
      --proxy-port int                  HTTPS 代理端口 (默认 443)
      --connection-timeout int          客户端连接空闲超时秒数 (默认 30)

证书管理:
      --ca-dir string                   CA 目录 (默认: XDG_CONFIG_HOME/httpseal/ca)
      --keep-ca                         退出后保留 CA 目录 (默认持久 CA 目录总会保留)

HTTP 拦截:
      --enable-http                     启用 HTTP 流量拦截 (默认禁用)
      --http-port int                   HTTP 代理端口 (默认 80)

SOCKS5 和上游 TLS:
      --socks5                          使用默认地址启用 SOCKS5 (127.0.0.1:1080)
      --socks5-addr string              SOCKS5 地址 (显式设置时自动启用 SOCKS5) (默认 "127.0.0.1:1080")
      --socks5-user string              SOCKS5 用户名 (可选)
      --socks5-pass string              SOCKS5 密码 (可选)
      --upstream-ca-file string         用于校验上游 TLS 证书的额外 CA bundle
      --upstream-client-cert string     上游 mTLS 客户端证书 PEM
      --upstream-client-key string      上游 mTLS 客户端私钥 PEM
      --upstream-server-name string     全局覆盖所有上游 TLS 连接的 server name
      --upstream-insecure-skip-verify   跳过上游 TLS 证书校验

Wireshark mirror:
      --enable-mirror                   启用用于 Wireshark 分析的 HTTP mirror server
      --mirror-port int                 HTTP mirror server 端口 (默认 8080)

输出:
  -o, --output string                   将流量输出到文件
      --format string                   输出格式: text, json, csv, har (默认 "text")
      --log-level string                控制台日志级别: none, minimal, normal, verbose, extra-verbose (默认 "normal")
      --file-log-level string           文件日志级别 (使用 -o 时默认 verbose): none, minimal, normal, verbose, extra-verbose
      --log-file string                 单独输出系统日志到文件
  -q, --quiet                           关闭控制台输出
  -v, --verbose count                   启用详细输出 (-v 为 verbose, -vv 为 extra-verbose)
      --no-redact                       关闭敏感 header、URL 和文本 body 的默认脱敏

过滤和 body 处理:
      --filter-domain strings           只记录包含这些 domain 的流量 (可重复)
      --filter-host-exact strings       只记录这些精确 host 的流量
      --filter-host-suffix strings      只记录匹配这些后缀的 host
      --filter-method strings           只记录这些 HTTP method
      --filter-status ints              只记录这些 HTTP status code
      --filter-path strings             只记录请求路径包含这些片段的流量
      --exclude-content-type strings    排除这些 content type 的日志记录
      --capture-body-limit int          每条请求/响应最多捕获多少 body 字节 (0=无限制) (默认 1048576)
      --log-body-limit int              最多打印/写出多少已捕获 body 字节 (0=完整已捕获 body)
      --max-body-size int               --log-body-limit 的废弃兼容别名
      --decompress-response             为日志解压压缩响应体 (默认 true)

配置和元信息:
  -c, --config string                   配置文件路径 (默认: XDG_CONFIG_HOME/httpseal/config.json)
  -h, --help                            显示帮助
      --version                         显示版本
```

## 故障排查

### 特权端口

默认 HTTPS 和 HTTP 拦截端口分别是 443 和 80。如果 HTTPSeal 无法绑定这些端口，请设置所需 capability：

```bash
sudo setcap 'cap_net_bind_service=+ep' "$(command -v httpseal)"
```

也可以通过 `--proxy-port` 和 `--http-port` 使用非特权端口，但普通 HTTPS/HTTP 流量的透明拦截通常依赖标准端口。

### `unshare: failed to execute newuidmap`

部分系统默认没有安装 `newuidmap` 和 `newgidmap`。Debian 和 Ubuntu 可使用：

```bash
sudo apt install uidmap
```

如果缺少这些 helper，HTTPSeal 会回退到 `unshare --map-root-user`。该模式下，进程在命名空间内可能显示为 UID/GID 0，但在宿主机上创建的文件仍会映射为调用 HTTPSeal 的用户。

### 特权降级回退

HTTPSeal 会优先使用 `setpriv`，再尝试 `runuser`，把命名空间内的 root 身份降回调用用户。部分系统会拒绝该操作。如果降级失败，HTTPSeal 会继续以命名空间内 root 身份运行。使用 `-v` 或 `-vv` 可以查看相关细节。

### 会恢复文件所有权的工具

`tar`、`gtar` 和 `bsdtar` 等归档工具可能尝试恢复命名空间内未映射的 UID/GID。HTTPSeal 会检测这些命令并设置：

```bash
TAR_OPTIONS=--no-same-owner --no-same-permissions
```

如果需要其他行为，请在运行 HTTPSeal 前自行设置 `TAR_OPTIONS`。

### 流量没有被拦截

常见原因：

- 目标应用使用硬编码 IP，而不是 DNS。
- 目标应用使用自定义 resolver，或忽略 `/etc/resolv.conf`。
- 目标应用没有使用 HTTPSeal 准备的 CA 路径或环境变量。
- 另一个本地服务已经占用 443；启用 `--enable-http` 时，也可能是 80 被占用。
- 目标协议不是 TLS 上的 HTTP，也不是明文 HTTP。

## 开发

项目结构：

```text
cmd/httpseal/        CLI 入口
internal/config/     配置加载和合并逻辑
pkg/cert/            CA 和动态证书生成
pkg/dns/             DNS server 与域名到 loopback 的映射
pkg/logger/          流量记录、脱敏和输出格式
pkg/mirror/          本地 HTTP mirror server
pkg/mount/           mount 辅助逻辑
pkg/namespace/       命名空间 wrapper 和 bind mount
pkg/proxy/           HTTPS 与 HTTP 拦截代理
```

常用命令：

```bash
make build
make test
make fmt
make vet
make lint
make dev
make clean
```

## 安全

HTTPSeal 会对它启动的进程执行中间人拦截。请仅用于开发、调试和授权安全测试。

HTTPSeal 的设计目标是避免修改系统全局信任或代理设置，但捕获的流量可能包含凭据、token、cookie、请求体和响应体。请按敏感数据处理日志和 mirror 抓包文件。不要把 HTTPSeal 用作生产监控工具，也不要检查未授权的流量。

## 贡献

1. Fork 仓库。
2. 创建功能分支。
3. 运行相关检查。
4. 提交包含清晰说明的 pull request。

## 许可证

本项目使用 MIT 许可证。详情见 [LICENSE](LICENSE)。

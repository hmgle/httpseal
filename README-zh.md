# HTTPSeal

[English](README.md) | 简体中文

> ⚠️ **开发中项目 (WIP)** ⚠️  
> HTTPSeal 目前正在积极开发中，尚未准备好用于生产环境。功能可能不完整、不稳定或存在重大变更。使用风险自负，可能会遇到问题。欢迎贡献和反馈！

HTTPSeal 是一个 Linux 命令行工具，使用命名空间隔离和 DNS 劫持技术来拦截和分析特定进程的 HTTPS/HTTP 流量。

## 演示

[![asciicast](https://asciinema.org/a/730013.svg)](https://asciinema.org/a/730013)

> **注意**：演示中显示的任何 API 密钥已被删除和失效以确保安全。

## 关于项目名称

**HTTPSeal** 结合了 "HTTP/HTTPS" 和 "Seal"（海豹），代表在受控环境中对进程流量的安全封装和隔离。这个名字是对传奇网络分析工具 **Wireshark** 🦈 的致敬。当 Wireshark 在整个网络海洋中狩猎时，HTTPSeal 是专门的海洋猎手，专注于隔离进程区域内的 HTTP/HTTPS 流量。

## 核心优势

🎯 **独特的进程隔离**：与全局代理工具（mitmproxy、Burp）不同，HTTPSeal 只影响它启动的进程 - 对系统或其他应用程序零影响

⚡ **零配置**：目标应用无需代理设置或修改 - 只需用 HTTPSeal 运行它们即可自动拦截

🔐 **高级证书管理**：完全自动的 CA 处理，支持 XDG 兼容的持久存储（默认：`$XDG_CONFIG_HOME/httpseal/ca/`）- 证书在会话间重用以获得更好性能

🔧 **Linux 原生架构**：专为 Linux 构建，使用命名空间隔离、用户命名空间和绑定挂载实现最大安全性和效率

🦈 **革命性 Wireshark 集成**：HTTP 镜像服务器创建解密 HTTPS 流量的实时明文 HTTP 副本 - 在 Wireshark 中零复杂度分析 TLS 1.3 流量

📊 **专业输出格式**：原生 HAR（HTTP Archive）支持用于浏览器开发工具，以及 JSON、CSV 和文本格式与智能双重日志系统

🌐 **企业级 SOCKS5**：内置 SOCKS5 代理支持带身份验证，可绕过网络限制

⚙️ **配置驱动**：XDG 兼容的 JSON 配置文件，支持 CLI 覆盖和智能默认值

## 架构

HTTPSeal 结合多种 Linux 技术创建隔离的 HTTPS/HTTP 拦截：

1. **挂载命名空间隔离**：使用带 UID 映射的用户命名空间（`unshare --map-root-user`）实现隔离的文件系统视图
2. **DNS 劫持**：替换 `/etc/resolv.conf` 将 DNS 查询重定向到本地服务器
3. **IP 地址映射**：将域名映射到 localhost 地址（127.0.0.0/8 范围）
4. **HTTPS 代理**：拦截 443 端口流量并执行 MITM 解密
5. **HTTP 代理**：拦截 80 端口的明文 HTTP 流量（启用时）
6. **证书颁发机构**：动态生成和缓存目标域的证书（仅 HTTPS）
7. **自动 CA 集成**：在隔离命名空间中合并 HTTPSeal CA 与系统 CA 包
8. **环境配置**：设置 SSL/TLS 环境变量以实现无缝证书使用

## 系统要求

- **操作系统**：Linux（内核 3.8+ 支持用户命名空间）
- **Go 版本**：1.24.4 或更高版本
- **Linux 权限**：
  - `CAP_NET_BIND_SERVICE`：用于绑定特权端口（80、443）
  - HTTPSeal 使用用户命名空间 UID 映射进行挂载操作（无需 `CAP_SYS_ADMIN`）

## 安装

> ⚠️ **开发版本说明**：这是一个开发中的构建版本。预期可能出现编译问题、运行时错误和不完整功能。安装过程可能随项目发展而变化。

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/hmgle/httpseal.git
cd httpseal

# 构建二进制文件
make build

# 安装并设置所需权限
make install
```

### 手动安装

```bash
# 构建
go build -o httpseal ./cmd/httpseal

# 安装二进制文件
sudo cp httpseal /usr/local/bin/

# 设置所需权限（仅需要 CAP_NET_BIND_SERVICE）
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/httpseal
```

## 使用方法

### 基本用法

```bash
# 拦截 HTTPS 流量（默认行为）
httpseal -- wget https://api.github.com/users/octocat

# 拦截 HTTP 流量（需要 --enable-http 标志）
httpseal --enable-http -- curl http://httpbin.org/get

# 同时拦截 HTTPS 和 HTTP 流量
httpseal --enable-http -- curl -v https://httpbin.org/get http://httpbin.org/headers
```

### 高级用法

```bash
# 详细模式显示所有流量详细信息
httpseal -v --enable-http -- curl -v https://httpbin.org/get

# 超详细模式 - 显示所有响应主体包括二进制内容
httpseal -V -- curl https://httpbin.org/get

# 使用 -vv 作为超详细模式的快捷方式
httpseal -vv -- wget https://baidu.com

# 保存流量到 JSON 格式文件
httpseal --enable-http -o traffic.json --format json -- wget http://httpbin.org/get

# 以 HAR 格式保存流量用于浏览器开发工具分析
httpseal -o performance.har --format har -- curl https://api.github.com/users/octocat

# 使用 SOCKS5 代理绕过限制
httpseal --socks5-addr 127.0.0.1:1080 -- curl https://www.google.com

# 🦈 Wireshark 集成 - 镜像 HTTPS 和 HTTP 流量
httpseal --enable-http --enable-mirror -- curl https://api.github.com/users/octocat

# 配置文件使用
httpseal --config ./my-config.json -- curl https://api.github.com/users/octocat
```

## 🌊 Wireshark 集成（HTTP 镜像）

HTTPSeal 具有**革命性的 HTTP 镜像服务器**功能，可创建解密 HTTPS 流量和明文 HTTP 流量的实时 HTTP 副本，实现无缝的 Wireshark 分析，无需复杂的 TLS 证书配置。

### 工作原理

```
客户端 → HTTPSeal (HTTPS 代理) → 真实服务器
             ↓
    HTTP 镜像服务器 (localhost:8080)
             ↓
        Wireshark 捕获
```

### Wireshark 快速开始

```bash
# 终端 1：启动 Wireshark 并在环回接口上捕获
wireshark -i lo -f "tcp port 8080"

# 终端 2：启用镜像运行 HTTPSeal
httpseal --enable-mirror -- curl https://api.github.com/users/octocat
```

## 📋 配置文件支持

HTTPSeal 支持遵循 XDG 基础目录规范的 JSON 配置文件：

### 默认配置位置

```bash
# XDG 兼容路径（按顺序检查）
$XDG_CONFIG_HOME/httpseal/config.json
~/.config/httpseal/config.json
./.httpseal/config.json  # 备用
```

### 配置文件示例

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
  "connection_timeout": 60,
  "max_body_size": 4096,
  "filter_domains": ["api.github.com", "httpbin.org"],
  "ca_dir": "./my-ca",
  "keep_ca": true
}
```

## 🌐 SOCKS5 代理支持

HTTPSeal 包含完整的 SOCKS5 代理支持用于上游连接，非常适合绕过网络限制或通过 VPN 路由流量：

```bash
# 启用默认地址的 SOCKS5 (127.0.0.1:1080)
httpseal --socks5 -- curl https://www.google.com

# 自定义 SOCKS5 地址（自动启用 SOCKS5）
httpseal --socks5-addr 192.168.1.100:1080 -- wget https://github.com

# 带身份验证的 SOCKS5
httpseal --socks5-addr 127.0.0.1:1080 --socks5-user myuser --socks5-pass mypass -- curl https://api.github.com
```

## 📊 输出格式和日志

HTTPSeal 提供多种输出格式和复杂的日志控制：

### 输出格式

1. **HAR (HTTP Archive) 格式** - 适用于浏览器开发工具和性能分析
2. **JSON 格式** - 用于程序化分析的结构化数据
3. **CSV 格式** - 兼容电子表格的完整数据
4. **文本格式** - 人类可读的控制台输出

### 双重日志系统

```bash
# 控制台和文件使用不同级别
httpseal --log-level minimal --file-log-level verbose -o detailed.log -- curl https://api.github.com

# 日志级别：none, minimal, normal, verbose
# 静默模式需要输出文件
httpseal -q -o traffic.json -- curl https://api.github.com
```

## 🛠️ 完整命令行参考

```bash
httpseal [选项] -- <命令> [参数...]

网络选项:
      --dns-ip string           DNS 服务器 IP 地址 (默认 "127.0.53.1")
      --dns-port int           DNS 服务器端口 (默认 53)
      --proxy-port int         HTTPS 代理端口 (默认 443)
      --connection-timeout int  客户端连接空闲超时秒数 (默认 30)

证书管理:
      --ca-dir string          证书颁发机构目录 (默认: $XDG_CONFIG_HOME/httpseal/ca/)
      --keep-ca                退出后保留 CA 目录

HTTP 流量拦截:
      --enable-http            启用 HTTP 流量拦截 (默认: 禁用)
      --http-port int          HTTP 代理端口 (默认 80)

SOCKS5 代理支持:
      --socks5                 启用默认地址的 SOCKS5 代理 (127.0.0.1:1080)
      --socks5-addr string     SOCKS5 代理地址 (自动启用 SOCKS5)
      --socks5-user string     SOCKS5 用户名
      --socks5-pass string     SOCKS5 密码

Wireshark 集成:
      --enable-mirror          启用 HTTP 镜像服务器用于 Wireshark 分析
      --mirror-port int        HTTP 镜像服务器端口 (默认 8080)

输出选项:
  -o, --output string          将流量输出到文件
      --format string          输出格式: text, json, csv, har (默认 "text")
      --log-level string       控制台日志级别: none, minimal, normal, verbose
  -q, --quiet                  静默模式 (需要 -o)
  -v, --verbose                启用详细输出
  -V, --extra-verbose          启用超详细输出

过滤和限制:
      --filter-domain strings        仅记录这些域的流量
      --max-body-size int            最大响应主体大小 (字节, 0=无限制)

配置:
  -c, --config string          配置文件路径

其他选项:
  -h, --help                   显示帮助信息
      --version                显示版本
```

## 证书管理

HTTPSeal 提供**智能、自动化的证书管理**和持久存储以获得最佳性能：

### 持久 CA 目录

HTTPSeal 现在默认使用 **XDG 兼容的持久 CA 目录**：

- **默认位置**：`$XDG_CONFIG_HOME/httpseal/ca/`（通常是 `~/.config/httpseal/ca/`）
- **自动创建**：首次运行时创建目录并设置正确权限
- **证书重用**：在会话间重用相同的 CA 和域证书
- **性能提升**：消除频繁访问域的证书重新生成
- **优雅回退**：如果持久路径不可用则回退到临时目录

## 开发

### 项目结构

```
httpseal/
├── cmd/httpseal/           # 主应用程序入口点
├── pkg/
│   ├── cert/              # 证书颁发机构和管理
│   ├── dns/               # DNS 服务器组件
│   ├── logger/            # 增强日志功能
│   ├── mirror/            # HTTP 镜像服务器
│   ├── namespace/         # 进程包装和命名空间处理
│   ├── proxy/             # HTTPS 代理服务器
│   └── mount/             # OverlayFS 挂载操作
└── internal/
    └── config/            # 配置结构
```

### 开发命令

```bash
# 构建带竞态检测的开发版本
make dev

# 运行测试
make test

# 代码质量检查
make fmt      # 格式化代码
make vet      # 运行 go vet
make lint     # 代码检查 (需要 golangci-lint)

# 依赖和清理
make deps     # 安装/更新依赖
make clean    # 清理构建产物

# 实用命令
make run-example  # 运行 wget 示例
make check-caps   # 检查已安装的权限
make help         # 显示所有可用目标
```

## 优势和限制

### 核心优势

✅ **双协议支持**：处理 HTTPS（带 TLS 解密）和明文 HTTP 流量拦截

✅ **进程特定隔离**：仅拦截 HTTPSeal 启动的进程流量 - 无系统范围影响

✅ **零配置**：目标应用无需代理设置或代码修改

✅ **命名空间安全**：使用 Linux 挂载命名空间实现安全隔离，不污染系统环境

✅ **自动证书处理**：在隔离环境中完全自动的 CA 证书管理 - 无需手动安装

✅ **透明拦截**：应用程序正常连接到域名，不知道被监控

### 限制

❌ **仅限 Linux**：完全依赖平台 - 无法在 Windows、macOS 或其他系统上工作

❌ **DNS 解析依赖**：使用硬编码 IP 或自定义 DNS 的应用可能绕过拦截

❌ **单进程范围**：无法拦截非 HTTPSeal 启动的进程流量

❌ **端口独占**：运行期间阻止 localhost:443 上的其他 HTTPS 服务

### 最佳使用场景

🎯 **完美适用于**：

- **Linux 开发和调试**，零配置和自动证书管理
- **CLI 工具流量分析**（`wget`、`curl`、自定义应用）
- **基于 HAR 的性能分析**，集成浏览器开发工具
- **Wireshark 驱动的网络分析**，零 TLS 复杂度
- **CI/CD 管道集成**，结构化日志和会话跟踪
- **安全研究**，需要进程隔离和全面流量分析

🚫 **不适用于**：

- 跨平台开发（仅限 Linux）
- 交互式请求/响应修改
- 生产环境监控
- 大容量或企业级流量分析
- Web 浏览器流量（请使用内置浏览器开发工具）

## 安全考虑

> ⚠️ **WIP 安全警告**：作为开发中工具，HTTPSeal 可能包含安全漏洞、不完整的输入验证或不稳定的证书处理。请勿在生产环境或敏感数据中使用。

- **仅用于授权测试**：HTTPSeal 对网络流量执行 MITM 攻击
- **仅限开发环境**：专为开发和测试场景设计
- **权限模型**：仅需要 `CAP_NET_BIND_SERVICE` 用于特权端口绑定
- **命名空间隔离**：更改包含在进程命名空间内并自动清理
- **无系统修改**：HTTPSeal 从不修改系统的证书存储或全局网络设置

## 贡献

1. Fork 仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开 Pull Request

## 许可证

本项目根据 MIT 许可证授权 - 请参阅 LICENSE 文件了解详情。

## 免责声明

**WIP 状态**：HTTPSeal 目前正在积极开发中（开发中）。功能可能不完整、不稳定或包含错误。此工具"按原样"提供，不提供任何保证。

HTTPSeal 仅用于合法开发、调试和授权安全测试目的。用户有责任确保使用此工具时遵守适用的法律法规。
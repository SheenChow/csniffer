# rsniffer - Rust 版本的轻量级被动嗅探器

这是一个基于 libpcap 的轻量级被动嗅探工具，用于在局域网流量中提取源 MAC 地址，并通过 OUI 表映射出厂商信息。

## 功能特性

- 实时捕获以太网数据包
- 自动提取源 MAC 地址并去重
- 通过 OUI 数据库映射厂商信息
- **自动从 IEEE 官网下载最新 OUI 数据**
- 本地缓存 OUI 数据，避免重复下载
- 支持显示源 IP 地址

## 与 C 版本的区别

| 特性 | C 版本 | Rust 版本 |
|------|--------|-----------|
| OUI 数据来源 | 内置静态表 | 从 IEEE 官网动态下载 |
| OUI 更新方式 | 重新编译 | 运行时 `--force-download` |
| 去重机制 | 自定义哈希表 | 标准库 `HashSet` |
| 内存管理 | 手动管理 | Rust 所有权系统 |
| 错误处理 | 返回码 | `anyhow` 错误链 |

## 安装依赖

### macOS

```bash
brew install libpcap
```

### Ubuntu/Debian

```bash
sudo apt install libpcap-dev
```

### CentOS/RHEL

```bash
sudo yum install libpcap-devel
```

## 编译

```bash
cd rust_version

# 开发模式编译
cargo build

# 发布模式编译（优化性能）
cargo build --release
```

编译后的可执行文件位于：
- 开发模式：`target/debug/rsniffer`
- 发布模式：`target/release/rsniffer`

## 测试流程

### 第一步：查看帮助信息

```bash
# 查看所有可用选项
./target/release/rsniffer --help
```

预期输出：
```
rsniffer 1.0
A lightweight passive sniffer based on libpcap

USAGE:
    rsniffer [OPTIONS]

OPTIONS:
    -c, --cache <CACHE>          OUI 数据缓存文件路径 [default: ~/.cache/rsniffer/oui.txt]
    -d, --debug                  启用调试日志
    -f, --force-download         强制重新下载 OUI 数据（忽略缓存）
    -h, --help                   Print help information
    -I, --print-ip               打印 IP 地址信息
    -i, --interface <INTERFACE>  网络接口名称（如 eth0, en0 等）
        --download-only          仅下载 OUI 数据并退出（不进行嗅探）
    -V, --version                Print version information
```

### 第二步：下载 OUI 数据（首次运行建议）

由于 OUI 数据库较大（约 5-10MB），建议首次运行先单独下载：

```bash
# 下载 OUI 数据并缓存
./target/release/rsniffer --download-only
```

预期输出：
```
rsniffer 1.0 [被动 MAC -> OUI 厂商映射工具]
按 Ctrl-C 退出
[INFO  rsniffer] 正在加载 OUI 数据库...
[INFO  rsniffer::oui] 正在从 IEEE 网站下载 OUI 数据...
[INFO  rsniffer::oui] 下载完成，共 5678901 字节
[INFO  rsniffer::oui] OUI 数据已缓存到: "/home/user/.cache/rsniffer/oui.txt"
[INFO  rsniffer::oui] 解析完成，共 34567 个 OUI 条目
[INFO  rsniffer] OUI 数据库加载完成，共 34567 个条目
OUI 数据已下载并缓存到: "/home/user/.cache/rsniffer/oui.txt"
```

### 第三步：基本嗅探测试

**注意：** 数据包捕获需要 root/管理员权限。

#### macOS

```bash
# 查看可用网络接口
ifconfig

# 使用 en0（通常是 Wi-Fi）或 en1（通常是以太网）进行嗅探
sudo ./target/release/rsniffer -i en0
```

#### Linux

```bash
# 查看可用网络接口
ip link show

# 使用指定接口（如 eth0 或 wlan0）进行嗅探
sudo ./target/release/rsniffer -i eth0
```

#### 使用默认接口

如果不指定 `-i` 参数，程序会自动选择第一个非回环接口：

```bash
sudo ./target/release/rsniffer
```

预期输出：
```
rsniffer 1.0 [被动 MAC -> OUI 厂商映射工具]
按 Ctrl-C 退出
使用默认网络接口: en0
[INFO  rsniffer] 正在加载 OUI 数据库...
[INFO  rsniffer::oui] 从缓存文件读取 OUI 数据: "/home/user/.cache/rsniffer/oui.txt"
[INFO  rsniffer::oui] 解析完成，共 34567 个 OUI 条目
[INFO  rsniffer] OUI 数据库加载完成，共 34567 个条目

开始捕获数据包...
--------------------------------------------------
aa:bb:cc:dd:ee:ff -> Apple, Inc.
11:22:33:44:55:66 -> Intel Corporate
00:1a:2b:3c:4d:5e -> Dell Inc.
...
```

### 第四步：显示 IP 地址

使用 `-I` 或 `--print-ip` 选项可以同时显示源 IP 地址：

```bash
sudo ./target/release/rsniffer -i en0 -I
```

预期输出：
```
aa:bb:cc:dd:ee:ff @ 192.168.1.100 -> Apple, Inc.
11:22:33:44:55:66 @ 192.168.1.101 -> Intel Corporate
```

### 第五步：强制更新 OUI 数据

OUI 数据会定期更新，使用以下命令强制下载最新版本：

```bash
# 强制重新下载并嗅探
sudo ./target/release/rsniffer -i en0 -f

# 或仅下载不嗅探
./target/release/rsniffer --download-only -f
```

## 命令行选项详解

| 选项 | 简写 | 说明 |
|------|------|------|
| `--interface` | `-i` | 指定网络接口，如 `-i en0`、`-i eth0` |
| `--print-ip` | `-I` | 同时显示源 IP 地址 |
| `--cache` | `-c` | 指定 OUI 缓存文件路径，默认 `~/.cache/rsniffer/oui.txt` |
| `--force-download` | `-f` | 强制重新下载 OUI 数据，忽略缓存 |
| `--download-only` | | 仅下载 OUI 数据并退出，不进行嗅探 |
| `--debug` | `-d` | 启用调试日志输出 |
| `--help` | `-h` | 显示帮助信息 |
| `--version` | `-V` | 显示版本信息 |

## 常见问题

### Q1: 为什么需要 sudo/root 权限？

数据包捕获需要访问原始网络接口，这在大多数操作系统中需要特殊权限。

### Q2: 为什么看不到任何数据包？

可能的原因：
1. 网络接口选择错误，尝试使用其他接口
2. 网络上没有流量，可以尝试 ping 网关或访问网页产生流量
3. 接口不支持混杂模式

### Q3: 如何更新 OUI 数据库？

```bash
# 强制重新下载
./target/release/rsniffer --download-only -f
```

建议每月更新一次以获取最新的厂商信息。

### Q4: OUI 缓存文件在哪里？

默认位置：`~/.cache/rsniffer/oui.txt`

可以使用 `--cache` 选项指定自定义路径：

```bash
./target/release/rsniffer --cache /tmp/oui.txt --download-only
```

### Q5: 编译时找不到 libpcap？

确保已安装 libpcap 开发库：

**macOS:**
```bash
brew install libpcap
```

**Ubuntu:**
```bash
sudo apt install libpcap-dev
```

## 输出格式说明

### 默认输出格式

```
<MAC地址> -> <厂商名称>
```

示例：
```
aa:bb:cc:dd:ee:ff -> Apple, Inc.
```

### 带 IP 的输出格式 (`-I` 选项)

```
<MAC地址> @ <IP地址> -> <厂商名称>
```

示例：
```
aa:bb:cc:dd:ee:ff @ 192.168.1.100 -> Apple, Inc.
```

### 退出时的统计信息

按 `Ctrl+C` 停止嗅探后，会显示统计信息：

```
收到中断信号，正在停止...

--------------------------------------------------
捕获统计:
  总数据包数:      1567
  唯一 MAC 地址数: 23
  OUI 数据库大小:  34567 条
```

## 性能说明

- 内存占用：主要取决于已发现的唯一 MAC 地址数量和 OUI 数据库大小
- OUI 数据库：约 3-4 万条记录，占用内存约 5-10MB
- 数据包捕获：使用 64 字节快照长度，最小化内存拷贝

## 与 C 版本功能对比

| 功能 | C 版本 (csniffer) | Rust 版本 (rsniffer) |
|------|-------------------|----------------------|
| 捕获以太网数据包 | ✅ | ✅ |
| 提取源 MAC 地址 | ✅ | ✅ |
| 去重显示 | ✅ | ✅ |
| OUI 厂商映射 | ✅ | ✅ |
| 显示 IP 地址 | ✅ (`-I`) | ✅ (`-I`) |
| 指定网络接口 | ✅ (`-i`) | ✅ (`-i`) |
| 自动选择默认接口 | ✅ | ✅ |
| 动态下载 OUI | ❌ | ✅ |
| OUI 本地缓存 | ❌ | ✅ |
| 强制更新 OUI | ❌ | ✅ (`-f`) |
| 单元测试 | ❌ | ✅ |

## 许可证

BSD 2-Clause License，与原版 C 代码保持一致。

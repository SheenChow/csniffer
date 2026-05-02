# gsniffer - Go 版本的轻量级被动嗅探器

这是一个基于 gopacket（libpcap 的 Go 绑定）实现的轻量级被动嗅探工具，用于在局域网流量中提取源 MAC 地址，并通过 OUI 表映射出厂商信息。

## 功能特性

- **实时数据包捕获**：基于 gopacket/libpcap 实现高性能数据包捕获
- **MAC 地址去重**：使用 Go 原生 `map` 实现高效的 MAC 地址去重
- **OUI 厂商映射**：自动从 IEEE 官网下载最新的 OUI 数据库
- **本地缓存**：支持 OUI 数据本地缓存，避免重复下载
- **子命令架构**：清晰的 `sniff`（嗅探）和 `download`（下载 OUI）子命令

## 与 C 版本的区别

| 特性 | C 版本 | Go 版本 |
|------|--------|---------|
| OUI 数据来源 | 内置静态表 | 从 IEEE 官网动态下载 |
| OUI 更新方式 | 重新编译 | `download` 子命令或 `-force` 选项 |
| 去重机制 | 自定义哈希表 | 标准库 `map[string]struct{}` |
| 内存管理 | 手动管理 | Go 垃圾回收 |
| 并发安全 | 无 | `sync.RWMutex` 保护 |
| 子命令 | 无 | `sniff`、`download` |

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

### 第一步：下载依赖（go mod tidy）

`go mod tidy` 是 Go 1.16+ 推荐的依赖管理方式，它会：
1. 读取 `go.mod` 文件中的依赖声明
2. 下载所有缺失的依赖包到本地缓存
3. 更新 `go.sum` 文件（记录依赖的校验和）
4. 移除不需要的依赖

```bash
cd go_version

# 下载并整理依赖
go mod tidy
```

**常见问题：**
- 如果网络较慢，可以设置 Go 代理：
  ```bash
  # 国内用户建议使用七牛云代理
  export GOPROXY=https://goproxy.cn,direct
  
  # 或使用阿里云代理
  export GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
  ```

### 第二步：编译

```bash
# 编译为 gsniffer
go build -o gsniffer .
```

编译后的可执行文件：`gsniffer`

### 快速编译（单步）

```bash
# 也可以一步完成（会自动下载依赖）
go build -o gsniffer .
```

## 测试流程

### 第一步：查看帮助信息

```bash
./gsniffer -help
```

预期输出：
```
gsniffer - Go 版本的轻量级被动嗅探工具

使用方法:
  gsniffer [全局选项] <子命令> [子命令选项]

子命令:
  sniff     进行数据包嗅探（默认子命令，可省略）
  download  从 IEEE 官网下载 OUI 数据

全局选项:
  -cache <path>    OUI 缓存文件路径 (默认: ~/.cache/gsniffer/oui.txt)
  -force           强制重新下载 OUI 数据（忽略缓存）
  -v, -verbose     详细输出模式
  -h, -help        显示帮助信息

sniff 子命令选项:
  -i <interface>   指定网络接口（如 en0, eth0），不指定则使用默认接口
  -I, -print-ip    同时显示源 IP 地址

download 子命令选项:
  无额外选项

示例:
  # 使用默认接口进行嗅探
  gsniffer sniff

  # 指定接口并显示 IP 地址
  gsniffer sniff -i en0 -I

  # 仅下载 OUI 数据
  gsniffer download

  # 强制重新下载 OUI 并嗅探
  gsniffer -force sniff -i eth0
```

### 第二步：下载 OUI 数据（首次运行建议）

由于 OUI 数据库较大（约 5-10MB），建议首次运行先单独下载：

```bash
./gsniffer download
```

预期输出：
```
gsniffer - OUI 数据下载工具

[INFO] 正在从 IEEE 网站下载 OUI 数据...
[DEBUG] 下载地址: https://standards-oui.ieee.org/oui/oui.txt
[INFO] 下载完成，共 5678901 字节
[INFO] OUI 数据已缓存到: /home/user/.cache/gsniffer/oui.txt
[INFO] 解析完成，共 34567 个 OUI 条目

OUI 数据已保存到: /home/user/.cache/gsniffer/oui.txt
共 34567 个 OUI 条目
```

### 第三步：基本嗅探测试

**注意：** 数据包捕获需要 root/管理员权限。

#### macOS

根据您提供的设备信息，您的活跃接口是 `en1`：

```bash
# 查看可用网络接口
ifconfig

# 使用您的接口 en1（Wi-Fi）进行嗅探
sudo ./gsniffer sniff -i en1
```

#### Linux

```bash
# 查看可用网络接口
ip link show

# 使用指定接口（如 eth0 或 wlan0）进行嗅探
sudo ./gsniffer sniff -i eth0
```

#### 使用默认接口

如果不指定 `-i` 参数，程序会自动选择第一个非回环接口：

```bash
sudo ./gsniffer sniff
```

预期输出：
```
[INFO] 使用默认网络接口: en1
[INFO] 正在加载 OUI 数据库...
[INFO] 从缓存文件读取 OUI 数据: /home/user/.cache/gsniffer/oui.txt
[INFO] 解析完成，共 34567 个 OUI 条目
[INFO] OUI 数据库加载完成，共 34567 个条目

开始捕获数据包...
--------------------------------------------------
aa:bb:cc:dd:ee:ff -> Apple, Inc.
11:22:33:44:55:66 -> Intel Corporate
00:1a:2b:3c:4d:5e -> Dell Inc.
...
```

### 第四步：显示 IP 地址

使用 `-I` 或 `-print-ip` 选项可以同时显示源 IP 地址：

```bash
sudo ./gsniffer sniff -i en1 -I
```

预期输出：
```
aa:bb:cc:dd:ee:ff @ 192.168.1.100 -> Apple, Inc.
11:22:33:44:55:66 @ 192.168.1.101 -> Intel Corporate
```

### 第五步：停止嗅探并查看统计

按 `Ctrl+C` 停止嗅探：

```
^C
收到中断信号，正在停止...

--------------------------------------------------
捕获统计:
  总数据包数:      1567
  唯一 MAC 地址数: 23
  OUI 数据库大小:  34567 条
```

### 第六步：强制更新 OUI 数据

OUI 数据会定期更新，使用以下命令强制下载最新版本：

```bash
# 强制重新下载并嗅探
sudo ./gsniffer -force sniff -i en1

# 或仅下载不嗅探
./gsniffer -force download
```

## 命令行选项详解

### 全局选项

| 选项 | 简写 | 说明 |
|------|------|------|
| `-cache <path>` | - | 指定 OUI 缓存文件路径，默认 `~/.cache/gsniffer/oui.txt` |
| `-force` | - | 强制重新下载 OUI 数据，忽略缓存 |
| `-v` `-verbose` | - | 启用详细输出模式 |
| `-h` `-help` | - | 显示帮助信息 |

### sniff 子命令选项

| 选项 | 简写 | 说明 |
|------|------|------|
| `-i <interface>` | - | 指定网络接口，如 `-i en0`、`-i eth0` |
| `-I` `-print-ip` | - | 同时显示源 IP 地址 |

### download 子命令选项

无额外选项。

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
--------------------------------------------------
捕获统计:
  总数据包数:      1567
  唯一 MAC 地址数: 23
  OUI 数据库大小:  34567 条
```

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
./gsniffer -force download
```

建议每月更新一次以获取最新的厂商信息。

### Q4: OUI 缓存文件在哪里？

默认位置：`~/.cache/gsniffer/oui.txt`

可以使用 `-cache` 选项指定自定义路径：

```bash
./gsniffer -cache /tmp/oui.txt download
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

### Q6: go mod tidy 下载依赖慢怎么办？

可以设置 Go 代理：

```bash
# 国内用户建议使用七牛云代理
export GOPROXY=https://goproxy.cn,direct

# 或使用阿里云代理
export GOPROXY=https://mirrors.aliyun.com/goproxy/,direct

# 然后重新下载依赖
go mod tidy
```

## 与 C 版本功能对比

| 功能 | C 版本 (csniffer) | Go 版本 (gsniffer) |
|------|-------------------|---------------------|
| 捕获以太网数据包 | ✅ | ✅ |
| 提取源 MAC 地址 | ✅ | ✅ |
| 去重显示 | ✅ | ✅ |
| OUI 厂商映射 | ✅ | ✅ |
| 显示 IP 地址 | ✅ (`-I`) | ✅ (`-I`) |
| 指定网络接口 | ✅ (`-i`) | ✅ (`-i`) |
| 自动选择默认接口 | ✅ | ✅ |
| 动态下载 OUI | ❌ | ✅ |
| OUI 本地缓存 | ❌ | ✅ |
| 强制更新 OUI | ❌ | ✅ (`-force`) |
| 子命令架构 | ❌ | ✅ |

## 项目结构

```
go_version/
├── go.mod           # Go 模块定义
├── go.sum           # 依赖校验和（go mod tidy 自动生成）
├── main.go          # 主程序入口
├── oui/
│   └── oui.go       # OUI 下载和解析模块
└── README.md        # 本文档
```

## 许可证

BSD 2-Clause License，与原版 C 代码保持一致。

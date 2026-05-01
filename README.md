# csniffer

一个基于 `libpcap` 的轻量级被动嗅探工具，用于在局域网流量中提取源 MAC 地址，并通过 OUI 表映射出厂商信息。

## 项目简介

- 主程序：`csniffer.c`
- 头文件：`csniffer.h`、`oui.h`
- 辅助工具：`csniffer_ace.c`（用于从 IEEE OUI 文本生成 `oui.h`）

运行时，程序会持续抓包并输出：

- `MAC -> Vendor`
- 或使用 `-I` 时输出 `MAC @ IP -> Vendor`

## 依赖

- C 编译器（`gcc` 或 `clang`）
- `make`
- `libpcap`

## 快速开始

在项目目录执行：

```bash
make
```

默认会生成两个可执行文件：

- `csniffer`
- `csniffer_ace`

## 使用方法

### 1) 运行 `csniffer`

```bash
sudo ./csniffer
```

常用参数：

- `-i <网卡名>`：指定抓包网卡
- `-I`：额外输出 IP 信息

示例：

```bash
sudo ./csniffer -i en0
sudo ./csniffer -i en0 -I
```

按 `Ctrl + C` 结束，程序会输出抓包统计信息。

### 2) （可选）重新生成 `oui.h`

先下载 IEEE 的 OUI 文本文件（通常命名为 `oui.txt`），然后执行：

```bash
./csniffer_ace oui.txt
```

这会重新生成 `oui.h`。

## macOS 使用说明

### 安装构建工具

先安装 Xcode Command Line Tools：

```bash
xcode-select --install
```

### 安装 `libpcap`（如需要）

多数 macOS 已自带运行时库；若编译时报找不到头文件或库，可使用 Homebrew：

```bash
brew install libpcap
```

如果仍报错，可在 `Makefile` 中按注释补充：

- `INCS`：`-I` 指向 `libpcap` 头文件目录
- `LDFLAGS`：`-L` 指向 `libpcap` 库目录

### 抓包权限

macOS 抓包通常需要 root 权限，请使用 `sudo` 运行。

## 清理构建产物

```bash
make clean
```

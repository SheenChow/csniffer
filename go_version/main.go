// rsniffer - Go 版本的轻量级被动嗅探工具
//
// 基于 gopacket（libpcap 的 Go 绑定）实现，用于在局域网流量中
// 提取源 MAC 地址，并通过 OUI 表映射出厂商信息。
//
// 功能特性：
//   - 实时捕获以太网数据包
//   - 自动提取源 MAC 地址并去重
//   - 通过 OUI 数据库映射厂商信息
//   - 支持从 IEEE 官网自动下载最新 OUI 数据
//   - 支持本地缓存 OUI 数据
//   - 子命令架构：sniff（默认）、download（下载 OUI）
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"rsniffer/oui"
)

// ============================================================
// 命令行参数定义
// ============================================================

// 通用配置
type Config struct {
	CachePath      string // OUI 缓存文件路径
	ForceDownload  bool   // 强制重新下载 OUI
	Verbose        bool   // 详细输出
}

// sniff 子命令配置
type SniffConfig struct {
	Interface string // 网络接口名称
	PrintIP   bool   // 打印 IP 地址
}

// download 子命令配置
type DownloadConfig struct {
	// 无需额外参数
}

// ============================================================
// 全局变量
// ============================================================

var (
	// 信号处理相关
	running   = true
	runningMu sync.Mutex

	// 统计信息
	packetCount uint64 // 总数据包数
	uniqueMACs  = make(map[[6]byte]struct{}) // 已发现的唯一 MAC 地址
	uniqueMu    sync.RWMutex
)

// ============================================================
// 使用说明
// ============================================================

const usage = `rsniffer - Go 版本的轻量级被动嗅探工具

使用方法:
  rsniffer [全局选项] <子命令> [子命令选项]

子命令:
  sniff     进行数据包嗅探（默认子命令，可省略）
  download  从 IEEE 官网下载 OUI 数据

全局选项:
  -cache <path>    OUI 缓存文件路径 (默认: ~/.cache/rsniffer/oui.txt)
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
  rsniffer sniff

  # 指定接口并显示 IP 地址
  rsniffer sniff -i en0 -I

  # 仅下载 OUI 数据
  rsniffer download

  # 强制重新下载 OUI 并嗅探
  rsniffer -force sniff -i eth0
`

// ============================================================
// 辅助函数
// ============================================================

// 获取默认缓存路径
func getDefaultCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "oui.txt")
	}
	return filepath.Join(home, ".cache", "rsniffer", "oui.txt")
}

// 获取默认网络接口
func getDefaultInterface() (string, error) {
	// 获取所有网络设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("无法获取网络设备列表: %w", err)
	}

	if len(devices) == 0 {
		return "", fmt.Errorf("未找到可用的网络接口")
	}

	// 尝试找到第一个非回环接口
	// 回环接口通常命名为 "lo" (Linux) 或 "lo0" (macOS)
	for _, dev := range devices {
		if dev.Name != "lo" && dev.Name != "lo0" {
			return dev.Name, nil
		}
	}

	// 如果所有接口都是回环，返回第一个
	return devices[0].Name, nil
}

// 列出所有可用的网络接口
func listInterfaces() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("无法获取网络设备列表: %w", err)
	}

	fmt.Println("可用的网络接口：")
	for i, dev := range devices {
		desc := dev.Description
		if desc == "" {
			desc = "(无描述)"
		}
		fmt.Printf("  %d. %s - %s\n", i+1, dev.Name, desc)
	}
	return nil
}

// ============================================================
// 信号处理
// ============================================================

// 设置信号处理函数（捕获 Ctrl+C）
func setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n收到中断信号，正在停止...")
		runningMu.Lock()
		running = false
		runningMu.Unlock()
	}()
}

// 检查是否应该继续运行
func isRunning() bool {
	runningMu.Lock()
	defer runningMu.Unlock()
	return running
}

// ============================================================
// OUI 数据加载
// ============================================================

// 加载 OUI 数据库
func loadOUIDatabase(config *Config) (*oui.Database, error) {
	cachePath := config.CachePath
	if cachePath == "" {
		cachePath = getDefaultCachePath()
	}

	// 如果强制下载，则忽略缓存
	var cacheForDownload string
	if !config.ForceDownload {
		cacheForDownload = cachePath
	} else {
		fmt.Println("[INFO] 强制重新下载 OUI 数据...")
	}

	// 下载/读取 OUI 数据
	content, err := oui.DownloadFromIEEE(cacheForDownload)
	if err != nil {
		return nil, err
	}

	// 解析 OUI 数据
	db := oui.NewDatabase()
	_, err = db.Parse(content)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// ============================================================
// 数据包处理
// ============================================================

// 解析以太网帧并提取信息
//
// 以太网帧格式：
//   字节 0-5:  目的 MAC 地址
//   字节 6-11: 源 MAC 地址
//   字节 12-13: 类型/长度 (0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP)
func parsePacket(data []byte) (srcMAC [6]byte, dstMAC [6]byte, srcIP *[4]byte, hasIP bool) {
	if len(data) < 14 {
		return
	}

	// 提取 MAC 地址
	copy(dstMAC[:], data[0:6])
	copy(srcMAC[:], data[6:12])

	// 检查是否为 IPv4 (0x0800)
	etherType := (uint16(data[12]) << 8) | uint16(data[13])
	if etherType == 0x0800 && len(data) >= 34 {
		// IPv4 数据包，提取源 IP 地址
		// IP 头从字节 14 开始，源 IP 在字节 26-29 (14+12)
		var ip [4]byte
		copy(ip[:], data[26:30])
		srcIP = &ip
		hasIP = true
	}

	return
}

// 处理单个数据包
func handlePacket(packet gopacket.Packet, db *oui.Database, printIP bool) {
	// 方法 1：使用 gopacket 的层解析
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}

	eth, _ := ethLayer.(*layers.Ethernet)
	srcMAC := eth.SrcMAC

	// 检查是否是新的 MAC 地址
	uniqueMu.Lock()
	if _, exists := uniqueMACs[srcMAC]; !exists {
		uniqueMACs[srcMAC] = struct{}{}
		uniqueMu.Unlock()

		// 查找厂商信息
		vendor := db.Lookup(srcMAC)
		macStr := oui.MACToString(srcMAC)

		if printIP {
			// 尝试获取 IP 地址
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				var srcIP [4]byte
				copy(srcIP[:], ip.SrcIP)
				ipStr := oui.IPToString(srcIP)
				fmt.Printf("%s @ %s -> %s\n", macStr, ipStr, vendor)
			} else {
				fmt.Printf("%s -> %s\n", macStr, vendor)
			}
		} else {
			fmt.Printf("%s -> %s\n", macStr, vendor)
		}
	} else {
		uniqueMu.Unlock()
	}
}

// ============================================================
// 子命令实现
// ============================================================

// runSniff - 执行嗅探子命令
func runSniff(config *Config, sniffConfig *SniffConfig) error {
	// 1. 确定网络接口
	iface := sniffConfig.Interface
	if iface == "" {
		var err error
		iface, err = getDefaultInterface()
		if err != nil {
			return err
		}
		fmt.Printf("[INFO] 使用默认网络接口: %s\n", iface)
	}

	// 2. 加载 OUI 数据库
	fmt.Println("[INFO] 正在加载 OUI 数据库...")
	db, err := loadOUIDatabase(config)
	if err != nil {
		return err
	}
	fmt.Printf("[INFO] OUI 数据库加载完成，共 %d 个条目\n", db.Len())

	// 3. 打开网络接口进行捕获
	// 参数说明：
	//   - iface: 网络接口名称
	//   - 64: 快照长度（只需要以太网头和 IP 头）
	//   - true: 混杂模式
	//   - pcap.BlockForever: 超时设置（阻塞模式）
	handle, err := pcap.OpenLive(iface, 64, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("无法打开网络接口 %s: %w", iface, err)
	}
	defer handle.Close()

	// 4. 设置信号处理
	setupSignalHandler()

	// 5. 开始捕获数据包
	fmt.Println()
	fmt.Println("开始捕获数据包...")
	fmt.Println("--------------------------------------------------")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for isRunning() {
		// 使用非阻塞方式读取
		select {
		case packet := <-packetSource.Packets():
			packetCount++
			handlePacket(packet, db, sniffConfig.PrintIP)
		default:
			// 短暂休眠，避免 CPU 占用过高
		}
	}

	// 6. 输出统计信息
	fmt.Println()
	fmt.Println("--------------------------------------------------")
	fmt.Println("捕获统计:")
	fmt.Printf("  总数据包数:      %d\n", packetCount)

	uniqueMu.RLock()
	fmt.Printf("  唯一 MAC 地址数: %d\n", len(uniqueMACs))
	uniqueMu.RUnlock()

	fmt.Printf("  OUI 数据库大小:  %d 条\n", db.Len())

	return nil
}

// runDownload - 执行下载子命令
func runDownload(config *Config, _ *DownloadConfig) error {
	cachePath := config.CachePath
	if cachePath == "" {
		cachePath = getDefaultCachePath()
	}

	fmt.Println("rsniffer - OUI 数据下载工具")
	fmt.Println()

	// 下载 OUI 数据
	db, err := loadOUIDatabase(config)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("OUI 数据已保存到: %s\n", cachePath)
	fmt.Printf("共 %d 个 OUI 条目\n", db.Len())

	return nil
}

// ============================================================
// 主函数
// ============================================================

func main() {
	// 解析命令行参数
	// Go 的 flag 包比较基础，我们手动实现子命令解析

	// 全局标志
	flagSet := flag.NewFlagSet("rsniffer", flag.ExitOnError)

	// 全局选项
	cachePath := flagSet.String("cache", "", "OUI 缓存文件路径")
	forceDownload := flagSet.Bool("force", false, "强制重新下载 OUI 数据")
	verbose := flagSet.Bool("v", false, "详细输出模式")
	verboseLong := flagSet.Bool("verbose", false, "详细输出模式")
	help := flagSet.Bool("h", false, "显示帮助信息")
	helpLong := flagSet.Bool("help", false, "显示帮助信息")

	// 自定义用法
	flagSet.Usage = func() {
		fmt.Print(usage)
	}

	// 解析参数
	if len(os.Args) > 1 {
		// 检查是否有子命令
		cmd := os.Args[1]
		if cmd == "sniff" || cmd == "download" || cmd == "help" {
			// 有子命令，先解析全局选项（在子命令之前的选项）
			// 这是简化处理，实际应该使用更完善的子命令解析
		}
	}

	// 简化处理：先解析所有参数，然后确定子命令
	// 由于 Go flag 的限制，我们使用简单的位置参数解析

	args := os.Args[1:]
	subCmd := "sniff" // 默认子命令
	var globalArgs []string
	var cmdArgs []string

	// 分离全局选项和子命令
	for i, arg := range args {
		if !strings.HasPrefix(arg, "-") && i == 0 {
			if arg == "sniff" || arg == "download" || arg == "help" {
				subCmd = arg
				globalArgs = args[0:i]
				cmdArgs = args[i+1:]
				break
			}
		}
	}

	// 如果没有识别到子命令，所有参数都是全局+sniff参数
	if len(globalArgs) == 0 && len(cmdArgs) == 0 {
		globalArgs = args
	}

	// 解析全局选项
	_ = flagSet.Parse(globalArgs)

	// 处理 help
	if *help || *helpLong || subCmd == "help" {
		fmt.Print(usage)
		os.Exit(0)
	}

	// 构建配置
	config := &Config{
		CachePath:     *cachePath,
		ForceDownload: *forceDownload,
		Verbose:       *verbose || *verboseLong,
	}

	// 根据子命令执行
	var err error
	switch subCmd {
	case "sniff":
		// 解析 sniff 子命令选项
		sniffFlagSet := flag.NewFlagSet("sniff", flag.ExitOnError)
		iface := sniffFlagSet.String("i", "", "网络接口名称")
		printIP := sniffFlagSet.Bool("I", false, "打印 IP 地址")
		printIPLong := sniffFlagSet.Bool("print-ip", false, "打印 IP 地址")
		sniffFlagSet.Usage = func() {
			fmt.Println("sniff 子命令用法:")
			fmt.Println("  rsniffer sniff [-i <interface>] [-I]")
			fmt.Println()
			fmt.Println("选项:")
			fmt.Println("  -i <interface>   指定网络接口")
			fmt.Println("  -I, -print-ip    显示源 IP 地址")
		}
		_ = sniffFlagSet.Parse(cmdArgs)

		sniffConfig := &SniffConfig{
			Interface: *iface,
			PrintIP:   *printIP || *printIPLong,
		}

		err = runSniff(config, sniffConfig)

	case "download":
		err = runDownload(config, &DownloadConfig{})

	default:
		fmt.Printf("未知的子命令: %s\n", subCmd)
		fmt.Print(usage)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

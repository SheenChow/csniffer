// Package oui 提供 OUI (Organizationally Unique Identifier) 数据库的下载、解析和查询功能
//
// OUI 是 MAC 地址的前 3 个字节，用于标识网络设备的厂商。
// 本包支持从 IEEE 官网下载最新的 OUI 数据，并提供快速查询功能。
package oui

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// IEEE OUI 数据库的官方下载地址
const IEEEOUIURL = "https://standards-oui.ieee.org/oui/oui.txt"

// Entry 表示一个 OUI 条目
// 包含 OUI 前缀（3字节）和对应的厂商名称
type Entry struct {
	Prefix [3]byte // OUI 前缀（MAC 地址的前 3 字节）
	Vendor string  // 厂商名称
}

// Database 表示 OUI 数据库
// 使用 Go 原生 map 进行快速查询
type Database struct {
	// 内部存储：使用 uint32 作为 key（只使用低 24 位存储 OUI 前缀）
	// 相比数组，map 提供 O(1) 的平均查询复杂度
	entries map[uint32]string
}

// NewDatabase 创建一个新的空 OUI 数据库
func NewDatabase() *Database {
	return &Database{
		entries: make(map[uint32]string),
	}
}

// DownloadFromIEEE 从 IEEE 官网下载 OUI 数据
//
// 参数：
//   - cachePath: 可选的缓存文件路径。如果非空且文件存在，
//     则从缓存读取而不是重新下载
//
// 返回：
//   - 下载的原始文本内容
//   - 错误信息（如果有）
func DownloadFromIEEE(cachePath string) (string, error) {
	// 如果提供了缓存路径且文件存在，从缓存读取
	if cachePath != "" {
		if _, err := os.Stat(cachePath); err == nil {
			fmt.Printf("[INFO] 从缓存文件读取 OUI 数据: %s\n", cachePath)
			data, err := os.ReadFile(cachePath)
			if err != nil {
				return "", fmt.Errorf("无法读取缓存文件: %w", err)
			}
			return string(data), nil
		}
	}

	fmt.Println("[INFO] 正在从 IEEE 网站下载 OUI 数据...")
	fmt.Printf("[DEBUG] 下载地址: %s\n", IEEEOUIURL)

	// 创建 HTTP 客户端，设置超时
	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	// 创建请求，添加完整的浏览器 headers
	// 注意：IEEE 网站有反爬虫策略，需要模拟真实浏览器请求
	req, err := http.NewRequest("GET", IEEEOUIURL, nil)
	if err != nil {
		return "", fmt.Errorf("无法创建 HTTP 请求: %w", err)
	}

	// 添加浏览器 headers（模拟 Chrome 浏览器）
	// 参考用户提供的 curl 命令
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "https://www.google.com/")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	// 模拟 Chrome 浏览器的 User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")
	// 添加 sec-ch-ua 系列 headers
	req.Header.Set("sec-ch-ua", `"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"macOS"`)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("无法连接到 IEEE OUI 服务器: %w", err)
	}
	defer resp.Body.Close()

	// 检查 HTTP 状态码
	// 允许 200 (OK) 和 304 (Not Modified)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		// 读取错误响应体，提供更详细的错误信息
		errBody, _ := io.ReadAll(resp.Body)
		errMsg := string(errBody)
		if len(errMsg) > 200 {
			errMsg = errMsg[:200] + "..."
		}
		return "", fmt.Errorf("HTTP 请求失败，状态码: %d\n响应内容: %s", resp.StatusCode, errMsg)
	}

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("无法读取 HTTP 响应内容: %w", err)
	}

	content := string(body)
	fmt.Printf("[INFO] 下载完成，共 %d 字节\n", len(content))

	// 如果提供了缓存路径，保存到缓存
	if cachePath != "" {
		// 确保目录存在
		dir := filepath.Dir(cachePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", fmt.Errorf("无法创建缓存目录: %w", err)
		}

		// 写入缓存文件
		if err := os.WriteFile(cachePath, body, 0644); err != nil {
			return "", fmt.Errorf("无法写入缓存文件: %w", err)
		}
		fmt.Printf("[INFO] OUI 数据已缓存到: %s\n", cachePath)
	}

	return content, nil
}

// Parse 从原始文本解析 OUI 数据
//
// IEEE OUI 文本格式示例：
//
//	28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd.
//	286FB9     (base 16)		Nokia Shanghai Bell Co., Ltd.
//				No.388 Ning Qiao Road,Jin Qiao Pudong Shanghai
//				Shanghai     201206
//				CN
//
// 我们只关心包含 "(hex)" 的行，因为它包含标准格式的 OUI。
func (db *Database) Parse(content string) (int, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行
		if line == "" {
			continue
		}

		// 查找包含 "(hex)" 的行，这是 OUI 条目的第一行
		if strings.Contains(line, "(hex)") {
			entry, err := parseHexLine(line)
			if err != nil {
				// 忽略解析错误的行，继续处理下一行
				continue
			}

			// 将 3 字节的 OUI 前缀转换为 uint32 作为 map 的 key
			// 格式: 0x00XXXXXX，其中 XXXXXX 是 24 位的 OUI
			key := uint32(entry.Prefix[0])<<16 |
				uint32(entry.Prefix[1])<<8 |
				uint32(entry.Prefix[2])

			db.entries[key] = entry.Vendor
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("读取 OUI 数据时出错: %w", err)
	}

	fmt.Printf("[INFO] 解析完成，共 %d 个 OUI 条目\n", count)
	return count, nil
}

// parseHexLine 解析单行 "(hex)" 格式的 OUI 条目
//
// 格式示例: "28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd."
func parseHexLine(line string) (*Entry, error) {
	// 按 "(hex)" 分割
	parts := strings.SplitN(line, "(hex)", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的 OUI 行格式: %s", line)
	}

	// 解析 OUI 前缀部分（如 "28-6F-B9"）
	prefixStr := strings.TrimSpace(parts[0])
	prefix, err := parseOUIPrefix(prefixStr)
	if err != nil {
		return nil, err
	}

	// 解析厂商名称（去除制表符和多余空格）
	vendor := strings.TrimSpace(parts[1])

	return &Entry{
		Prefix: prefix,
		Vendor: vendor,
	}, nil
}

// parseOUIPrefix 解析 OUI 前缀字符串
//
// 支持的格式：
//   - "28-6F-B9" (带分隔符的十六进制)
//   - "28:6F:B9" (带冒号分隔符的十六进制)
//   - "286FB9" (不带分隔符的十六进制)
func parseOUIPrefix(s string) ([3]byte, error) {
	// 移除所有分隔符（- 或 :）
	cleaned := strings.Map(func(r rune) rune {
		if r == '-' || r == ':' {
			return -1
		}
		return r
	}, s)

	if len(cleaned) != 6 {
		return [3]byte{}, fmt.Errorf("无效的 OUI 前缀长度: %s", s)
	}

	// 解析每两个字符为一个字节
	var result [3]byte
	for i := 0; i < 3; i++ {
		hexByte := cleaned[i*2 : (i+1)*2]
		val, err := strconv.ParseUint(hexByte, 16, 8)
		if err != nil {
			return [3]byte{}, fmt.Errorf("无法解析字节 %s: %w", hexByte, err)
		}
		result[i] = byte(val)
	}

	return result, nil
}

// Lookup 根据 MAC 地址查找厂商名称
//
// 参数：
//   - mac: 6 字节的 MAC 地址
//
// 返回：
//   - 如果找到匹配的 OUI，返回厂商名称
//   - 否则返回 "Unknown Vendor"
func (db *Database) Lookup(mac [6]byte) string {
	// 提取前 3 字节作为 OUI 前缀
	key := uint32(mac[0])<<16 |
		uint32(mac[1])<<8 |
		uint32(mac[2])

	if vendor, ok := db.entries[key]; ok {
		return vendor
	}
	return "Unknown Vendor"
}

// LookupBytes 根据 MAC 地址（字节切片）查找厂商名称
//
// 适用于 net.HardwareAddr 类型（本质是 []byte）
//
// 参数：
//   - mac: MAC 地址的字节切片，长度必须为 6
//
// 返回：
//   - 如果找到匹配的 OUI，返回厂商名称
//   - 否则返回 "Unknown Vendor"（或在长度不匹配时返回 "Invalid MAC"）
func (db *Database) LookupBytes(mac []byte) string {
	if len(mac) != 6 {
		return "Invalid MAC"
	}

	// 将 []byte 转换为 [6]byte
	var macArr [6]byte
	copy(macArr[:], mac)

	return db.Lookup(macArr)
}

// Len 返回数据库中的条目数量
func (db *Database) Len() int {
	return len(db.entries)
}

// IsEmpty 检查数据库是否为空
func (db *Database) IsEmpty() bool {
	return len(db.entries) == 0
}

// MACToString 将 MAC 地址格式化为标准字符串
//
// 输出格式: "00:11:22:33:44:55"
func MACToString(mac [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// MACToStringBytes 将 MAC 地址（字节切片）格式化为标准字符串
//
// 适用于 net.HardwareAddr 类型（本质是 []byte）
//
// 输出格式: "00:11:22:33:44:55"
func MACToStringBytes(mac []byte) string {
	if len(mac) != 6 {
		return "invalid"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// IPToString 将 IP 地址格式化为字符串
//
// 输出格式: "192.168.1.1"
func IPToString(ip [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

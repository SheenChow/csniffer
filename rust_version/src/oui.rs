//! OUI (Organizationally Unique Identifier) 模块
//!
//! 负责从 IEEE 网站下载并解析 OUI 数据库，
//! 提供 MAC 地址到厂商名称的映射功能。

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// IEEE OUI 数据库的官方 URL
const IEEE_OUI_URL: &str = "https://standards-oui.ieee.org/oui/oui.txt";

/// OUI 条目结构
///
/// 存储 OUI 前缀和对应的厂商信息
#[derive(Debug, Clone)]
pub struct OuiEntry {
    /// OUI 前缀（3 字节）
    pub prefix: [u8; 3],
    /// 厂商名称
    pub vendor: String,
}

/// OUI 数据库
///
/// 使用 HashMap 存储 OUI 前缀到厂商名称的映射，
/// 提供快速查找功能
#[derive(Debug, Default)]
pub struct OuiDatabase {
    /// 内部存储：OUI 前缀（作为 u32，只使用低 24 位）到厂商名称的映射
    entries: HashMap<u32, String>,
}

impl OuiDatabase {
    /// 创建一个空的 OUI 数据库
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// 从 IEEE 网站下载 OUI 数据
    ///
    /// # 参数
    /// * `cache_path` - 可选的缓存文件路径，如果提供且文件存在，
    ///   则从缓存读取而不是重新下载
    ///
    /// # 返回
    /// 下载的原始文本内容
    pub fn download(cache_path: Option<&Path>) -> Result<String> {
        // 如果提供了缓存路径且文件存在，从缓存读取
        if let Some(path) = cache_path {
            if path.exists() {
                log::info!("从缓存文件读取 OUI 数据: {:?}", path);
                return fs::read_to_string(path)
                    .with_context(|| format!("无法读取缓存文件: {:?}", path));
            }
        }

        log::info!("正在从 IEEE 网站下载 OUI 数据...");
        log::debug!("下载地址: {}", IEEE_OUI_URL);

        // 使用 reqwest 的 blocking API 下载
        let response = reqwest::blocking::get(IEEE_OUI_URL)
            .with_context(|| "无法连接到 IEEE OUI 服务器")?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("HTTP 请求失败，状态码: {}", status);
        }

        let content = response.text()
            .with_context(|| "无法读取 HTTP 响应内容")?;

        log::info!("下载完成，共 {} 字节", content.len());

        // 如果提供了缓存路径，保存到缓存
        if let Some(path) = cache_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("无法创建缓存目录: {:?}", parent))?;
            }
            fs::write(path, &content)
                .with_context(|| format!("无法写入缓存文件: {:?}", path))?;
            log::info!("OUI 数据已缓存到: {:?}", path);
        }

        Ok(content)
    }

    /// 从原始文本解析 OUI 数据
    ///
    /// IEEE OUI 文本格式示例：
    /// ```text
    /// 28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd.
    /// 286FB9     (base 16)		Nokia Shanghai Bell Co., Ltd.
    /// 				No.388 Ning Qiao Road,Jin Qiao Pudong Shanghai
    /// 				Shanghai     201206
    /// 				CN
    /// ```
    ///
    /// 我们只关心 `(hex)` 开头的行，因为它包含标准格式的 OUI。
    pub fn parse(&mut self, content: &str) -> Result<usize> {
        let mut count = 0;
        let mut lines = content.lines();

        while let Some(line) = lines.next() {
            // 跳过空行
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // 查找包含 "(hex)" 的行，这是 OUI 条目的第一行
            if line.contains("(hex)") {
                // 解析格式: "28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd."
                if let Some(entry) = Self::parse_hex_line(line) {
                    let prefix_u32 = ((entry.prefix[0] as u32) << 16)
                        | ((entry.prefix[1] as u32) << 8)
                        | (entry.prefix[2] as u32);

                    self.entries.insert(prefix_u32, entry.vendor);
                    count += 1;
                }
            }
        }

        log::info!("解析完成，共 {} 个 OUI 条目", count);
        Ok(count)
    }

    /// 解析单行 "(hex)" 格式的 OUI 条目
    ///
    /// 格式: "28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd."
    fn parse_hex_line(line: &str) -> Option<OuiEntry> {
        // 分割 "(hex)" 标记
        let parts: Vec<&str> = line.splitn(2, "(hex)").collect();
        if parts.len() != 2 {
            return None;
        }

        // 解析 OUI 前缀部分（"28-6F-B9"）
        let prefix_str = parts[0].trim();
        let prefix = Self::parse_oui_prefix(prefix_str)?;

        // 解析厂商名称（去除制表符和多余空格）
        let vendor = parts[1].trim().to_string();

        Some(OuiEntry { prefix, vendor })
    }

    /// 解析 OUI 前缀字符串
    ///
    /// 支持的格式：
    /// - "28-6F-B9" (带分隔符的十六进制)
    /// - "286FB9" (不带分隔符的十六进制)
    fn parse_oui_prefix(s: &str) -> Option<[u8; 3]> {
        // 移除所有分隔符（- 或 :）
        let cleaned: String = s.chars().filter(|c| *c != '-' && *c != ':').collect();

        if cleaned.len() != 6 {
            return None;
        }

        // 解析每两个字符为一个字节
        let b1 = u8::from_str_radix(&cleaned[0..2], 16).ok()?;
        let b2 = u8::from_str_radix(&cleaned[2..4], 16).ok()?;
        let b3 = u8::from_str_radix(&cleaned[4..6], 16).ok()?;

        Some([b1, b2, b3])
    }

    /// 根据 MAC 地址查找厂商名称
    ///
    /// # 参数
    /// * `mac` - 6 字节的 MAC 地址
    ///
    /// # 返回
    /// 如果找到匹配的 OUI，返回厂商名称；否则返回 "Unknown Vendor"
    pub fn lookup(&self, mac: &[u8; 6]) -> &str {
        // 提取前 3 字节作为 OUI 前缀
        let prefix_u32 = ((mac[0] as u32) << 16)
            | ((mac[1] as u32) << 8)
            | (mac[2] as u32);

        self.entries
            .get(&prefix_u32)
            .map(|s| s.as_str())
            .unwrap_or("Unknown Vendor")
    }

    /// 获取数据库中的条目数量
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 检查数据库是否为空
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// 将 MAC 地址格式化为标准字符串
///
/// # 参数
/// * `mac` - 6 字节的 MAC 地址
///
/// # 返回
/// 格式化的字符串，如 "00:11:22:33:44:55"
pub fn mac_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_oui_prefix() {
        assert_eq!(
            OuiDatabase::parse_oui_prefix("28-6F-B9"),
            Some([0x28, 0x6F, 0xB9])
        );
        assert_eq!(
            OuiDatabase::parse_oui_prefix("28:6F:B9"),
            Some([0x28, 0x6F, 0xB9])
        );
        assert_eq!(
            OuiDatabase::parse_oui_prefix("286FB9"),
            Some([0x28, 0x6F, 0xB9])
        );
    }

    #[test]
    fn test_parse_hex_line() {
        let line = "28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd.";
        let entry = OuiDatabase::parse_hex_line(line).unwrap();

        assert_eq!(entry.prefix, [0x28, 0x6F, 0xB9]);
        assert_eq!(entry.vendor, "Nokia Shanghai Bell Co., Ltd.");
    }

    #[test]
    fn test_mac_to_string() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(mac_to_string(&mac), "00:11:22:33:44:55");
    }

    #[test]
    fn test_lookup() {
        let mut db = OuiDatabase::new();
        db.entries.insert(0x001122, "Test Vendor".to_string());

        let mac = [0x00, 0x11, 0x22, 0xAA, 0xBB, 0xCC];
        assert_eq!(db.lookup(&mac), "Test Vendor");

        let unknown_mac = [0xFF, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC];
        assert_eq!(db.lookup(&unknown_mac), "Unknown Vendor");
    }
}

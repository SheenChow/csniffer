//! 轻量级被动嗅探工具
//!
//! 基于 libpcap，用于在局域网流量中提取源 MAC 地址，
//! 并通过 OUI 表映射出厂商信息。
//!
//! 功能特性：
//! - 实时捕获以太网数据包
//! - 提取源 MAC 地址并去重
//! - 通过 OUI 数据库映射厂商信息
//! - 支持从 IEEE 网站自动下载最新 OUI 数据
//! - 支持缓存 OUI 数据到本地

use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod oui;
use oui::{mac_to_string, OuiDatabase};

/// 命令行参数
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 网络接口名称（如 eth0, en0 等），不指定则使用默认接口
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// 打印 IP 地址信息
    #[arg(short = 'I', long)]
    print_ip: bool,

    /// OUI 数据缓存文件路径
    #[arg(short = 'c', long, default_value = "~/.cache/rsniffer/oui.txt")]
    cache: String,

    /// 强制重新下载 OUI 数据（忽略缓存）
    #[arg(short = 'f', long)]
    force_download: bool,

    /// 仅下载 OUI 数据并退出（不进行嗅探）
    #[arg(long)]
    download_only: bool,

    /// 启用调试日志
    #[arg(short = 'd', long)]
    debug: bool,
}

/// 捕获的数据包信息
#[derive(Debug, Clone)]
struct PacketInfo {
    /// 源 MAC 地址
    source_mac: [u8; 6],
    /// 目的 MAC 地址
    dest_mac: [u8; 6],
    /// 源 IP 地址（如果是 IP 数据包）
    source_ip: Option<[u8; 4]>,
    /// 目的 IP 地址（如果是 IP 数据包）
    dest_ip: Option<[u8; 4]>,
}

/// 从以太网帧中提取 MAC 地址和可能的 IP 地址
///
/// 以太网帧格式：
/// - 字节 0-5:  目的 MAC 地址
/// - 字节 6-11: 源 MAC 地址
/// - 字节 12-13: 类型/长度
///   - 0x0800: IPv4
///   - 0x86DD: IPv6
///   - 0x0806: ARP
fn parse_ethernet_frame(data: &[u8]) -> Option<PacketInfo> {
    if data.len() < 14 {
        return None;
    }

    let dest_mac: [u8; 6] = data[0..6].try_into().ok()?;
    let source_mac: [u8; 6] = data[6..12].try_into().ok()?;

    let ether_type = u16::from_be_bytes([data[12], data[13]]);

    let (source_ip, dest_ip) = if ether_type == 0x0800 && data.len() >= 34 {
        // IPv4 数据包
        // IP 头从字节 14 开始
        // 源 IP 在字节 26-29（14+12）
        // 目的 IP 在字节 30-33（14+16）
        let s_ip: [u8; 4] = data[26..30].try_into().ok()?;
        let d_ip: [u8; 4] = data[30..34].try_into().ok()?;
        (Some(s_ip), Some(d_ip))
    } else {
        (None, None)
    };

    Some(PacketInfo {
        source_mac,
        dest_mac,
        source_ip,
        dest_ip,
    })
}

/// 将 IP 地址格式化为字符串
fn ip_to_string(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// 获取默认网络接口名称
fn get_default_interface() -> Result<String> {
    // 使用 pcap 的 findalldevs 获取所有设备并选择第一个
    let devices = pcap::Device::list()
        .with_context(|| "无法获取网络设备列表")?;

    devices
        .iter()
        .find(|d| !d.is_loopback())
        .or_else(|| devices.first())
        .map(|d| d.name.clone())
        .with_context(|| "未找到可用的网络接口")
}

/// 列出所有可用的网络接口
#[allow(dead_code)]
fn list_interfaces() -> Result<()> {
    let devices = pcap::Device::list()
        .with_context(|| "无法获取网络设备列表")?;

    println!("可用的网络接口：");
    for (i, dev) in devices.iter().enumerate() {
        let desc = dev.desc.as_deref().unwrap_or("(无描述)");
        println!("  {}. {} - {}", i + 1, dev.name, desc);
    }

    Ok(())
}

/// 初始化日志系统
fn init_logging(debug: bool) {
    let filter = if debug { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(filter))
        .format_target(false)
        .format_timestamp(None)
        .init();
}

/// 展开包含波浪号的路径
fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with('~') {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(&path[2..])
    } else {
        PathBuf::from(path)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // 初始化日志
    init_logging(args.debug);

    println!("rsniffer 1.0 [被动 MAC -> OUI 厂商映射工具]");
    println!("按 Ctrl-C 退出");

    // 确定网络接口
    let interface = if let Some(iface) = args.interface {
        iface
    } else {
        let default = get_default_interface()?;
        println!("使用默认网络接口: {}", default);
        default
    };

    // 处理 OUI 数据
    let cache_path = expand_tilde(&args.cache);
    let cache_for_download = if args.force_download {
        None
    } else {
        Some(cache_path.as_path())
    };

    // 下载 OUI 数据
    log::info!("正在加载 OUI 数据库...");
    let oui_content = OuiDatabase::download(cache_for_download)
        .with_context(|| "无法下载或加载 OUI 数据")?;

    let mut oui_db = OuiDatabase::new();
    oui_db.parse(&oui_content)
        .with_context(|| "无法解析 OUI 数据")?;

    log::info!("OUI 数据库加载完成，共 {} 个条目", oui_db.len());

    // 如果只是下载模式，退出
    if args.download_only {
        println!("OUI 数据已下载并缓存到: {:?}", cache_path);
        return Ok(());
    }

    // 准备捕获
    let seen_macs: HashSet<[u8; 6]> = HashSet::new();
    let seen_macs = Arc::new(std::sync::Mutex::new(seen_macs));

    // 设置信号处理
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\n收到中断信号，正在停止...");
        r.store(false, Ordering::SeqCst);
    })
    .with_context(|| "无法设置信号处理函数")?;

    // 打开捕获句柄
    // 使用 pcap crate 的现代 API
    let mut cap = pcap::Capture::from_device(&interface[..])
        .with_context(|| format!("无法打开网络接口: {}", interface))?
        .promisc(true)
        .snaplen(64)  // 只需要以太网头和 IP 头
        .timeout(500)  // 500ms 超时
        .open()
        .with_context(|| format!("无法激活网络接口: {}", interface))?;

    // 设置过滤器（不过滤，捕获所有）
    // 注意：pcap crate 的 API 与原始 libpcap 略有不同
    // filter("") 表示不过滤

    println!("\n开始捕获数据包...");
    println!("--------------------------------------------------");

    // 主捕获循环
    let mut packet_count: u32 = 0;

    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;

                // 解析以太网帧
                if let Some(info) = parse_ethernet_frame(packet.data) {
                    // 检查是否是新的 MAC 地址
                    let mut seen = seen_macs.lock().unwrap();

                    if !seen.contains(&info.source_mac) {
                        seen.insert(info.source_mac);

                        let vendor = oui_db.lookup(&info.source_mac);
                        let mac_str = mac_to_string(&info.source_mac);

                        if args.print_ip {
                            if let Some(ip) = info.source_ip {
                                let ip_str = ip_to_string(&ip);
                                println!("{} @ {} -> {}", mac_str, ip_str, vendor);
                            } else {
                                println!("{} -> {}", mac_str, vendor);
                            }
                        } else {
                            println!("{} -> {}", mac_str, vendor);
                        }
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // 超时是正常的，继续循环检查 running 标志
                continue;
            }
            Err(e) => {
                log::error!("捕获数据包时出错: {}", e);
                break;
            }
        }
    }

    // 输出统计信息
    let seen = seen_macs.lock().unwrap();
    println!("\n--------------------------------------------------");
    println!("捕获统计:");
    println!("  总数据包数:      {}", packet_count);
    println!("  唯一 MAC 地址数: {}", seen.len());
    println!("  OUI 数据库大小:  {} 条", oui_db.len());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ethernet_frame() {
        // 构造一个简单的以太网帧
        // 目的 MAC: 00:11:22:33:44:55
        // 源 MAC:   AA:BB:CC:DD:EE:FF
        // 类型:     IPv4 (0x0800)
        let mut data = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // 目的 MAC
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // 源 MAC
            0x08, 0x00,                            // IPv4
        ];

        // 添加最小的 IP 头（20 字节）
        data.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x3C,  // 版本/IHL, TOS, 总长度
            0x00, 0x00, 0x00, 0x00,  // 标识, 标志/片偏移
            0x40, 0x06, 0x00, 0x00,  // TTL, 协议, 校验和
            0xC0, 0xA8, 0x01, 0x01,  // 源 IP: 192.168.1.1
            0xC0, 0xA8, 0x01, 0x02,  // 目的 IP: 192.168.1.2
        ]);

        let info = parse_ethernet_frame(&data).unwrap();

        assert_eq!(info.source_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(info.dest_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(info.source_ip, Some([192, 168, 1, 1]));
        assert_eq!(info.dest_ip, Some([192, 168, 1, 2]));
    }

    #[test]
    fn test_ip_to_string() {
        assert_eq!(ip_to_string(&[192, 168, 1, 1]), "192.168.1.1");
        assert_eq!(ip_to_string(&[10, 0, 0, 1]), "10.0.0.1");
    }

    #[test]
    fn test_expand_tilde() {
        // 这个测试依赖于环境，只测试非波浪号路径
        let path = expand_tilde("/tmp/test");
        assert_eq!(path, PathBuf::from("/tmp/test"));
    }
}

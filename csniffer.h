/*
 *  $Id: csniffer.h,v 1.1.1.1 2001/11/29 00:16:48 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  csniffer.h - pcap 示例代码头文件
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 *  更新说明：
 *  - 添加了详细的中文注释
 *  - 说明各个宏定义和数据结构的用途
 *
 *  许可证信息：
 *  在满足以下条件的前提下，允许以源代码和二进制形式重新分发和使用，无论是否进行修改：
 *  1. 源代码的重新分发必须保留上述版权声明、此条件列表和以下免责声明。
 *  2. 二进制形式的重新分发必须在随分发提供的文档和/或其他材料中复制上述版权声明、
 *     此条件列表和以下免责声明。
 */

/* 标准库头文件 */
#include <unistd.h>      /* Unix 标准函数定义（如 read, write, close 等） */
#include <errno.h>         /* 错误码定义 */
#include <stdio.h>         /* 标准输入输出函数 */
#include <stdlib.h>        /* 标准库函数（如 malloc, free, exit 等） */
#include <sys/types.h>     /* 系统数据类型定义 */
#include <netinet/in.h>    /* Internet 地址族定义（如 sockaddr_in 等） */

/* 第三方库头文件 */
#include <pcap.h>          /* libpcap 数据包捕获库头文件 */
#include <signal.h>        /* 信号处理函数定义 */

/* 本地头文件 */
#include "./oui.h"         /* OUI（组织唯一标识符）数据库头文件 */

/*
 * 宏定义说明
 */

/* SNAPLEN: 捕获的最大字节数
 * 设置为 34 字节是因为：
 *   - 以太网帧头：14 字节（目的 MAC 6 + 源 MAC 6 + 类型/长度 2）
 *   - IP 头：最小 20 字节
 *   对于只需要 MAC 地址和可能的 IP 地址信息，34 字节足够。
 * 较小的快照长度可以减少内存使用和数据包拷贝开销。
 */
#define SNAPLEN         34

/* PROMISC: 混杂模式标志
 * 1 表示启用混杂模式，可以捕获网络上所有经过的数据包，
 * 而不仅仅是发送到本机的数据包。
 */
#define PROMISC         1

/* TIMEOUT: 读取超时时间（毫秒）
 * 设置为 500ms，即 0.5 秒。
 * pcap_next() 或 pcap_loop() 会在这个时间内没有数据包时返回，
 * 允许程序有机会检查退出标志（loop）。
 */
#define TIMEOUT         500

/* FILTER: BPF（伯克利数据包过滤器）表达式
 * 默认为空字符串，表示不过滤，捕获所有数据包。
 * 可以设置为如 "tcp port 80" 等过滤表达式。
 */
#define FILTER          ""

/* HASH_TABLE_SIZE: 哈希表大小
 * 设置为 251，这是一个素数。
 * 使用素数作为哈希表大小可以减少哈希冲突的概率。
 */
#define HASH_TABLE_SIZE 251

/*
 * 数据结构定义
 */

/* table_entry: 哈希表条目结构
 * 用于存储已捕获的唯一 MAC 地址。
 * 采用链地址法解决哈希冲突。
 */
struct table_entry
{
    u_char mac[6];              /* 存储 6 字节的 MAC 地址 */
    struct table_entry *next;   /* 指向链表中下一个条目的指针 */
};

/*
 * 函数声明
 */

/* b_search: 在 OUI 表中执行二分查找
 * 参数: prefix - 指向 MAC 地址前 3 字节（OUI）的指针
 * 返回: 找到时返回厂商名称字符串，否则返回 "Unknown Vendor"
 */
const char *b_search(u_char *);

/* eprintf: 格式化以太网 MAC 地址
 * 参数: packet - 指向以太网数据包的指针
 * 返回: 格式化后的 MAC 地址字符串（如 "00:11:22:33:44:55"）
 */
char *eprintf(u_char *);

/* iprintf: 格式化 IP 地址
 * 参数: address - 指向 4 字节 IP 地址的指针
 * 返回: 格式化后的 IP 地址字符串（如 "192.168.1.1"）
 */
char *iprintf(u_char *);

/* interesting: 检查数据包中的源 MAC 地址是否是新的
 * 参数: packet - 指向数据包的指针
 *       hash_table - 指向哈希表数组的指针
 * 返回: 1 表示是新地址，0 表示已存在
 */
int interesting(u_char *, struct table_entry **);

/* ht_dup_check: 检查哈希表中是否已存在指定的 MAC 地址
 * 参数: packet - 指向数据包的指针
 *       hash_table - 指向哈希表数组的指针
 *       loc - 哈希桶索引
 * 返回: 1 表示已存在，0 表示不存在
 */
int ht_dup_check(u_char *, struct table_entry **, int);

/* ht_add_entry: 将 MAC 地址添加到哈希表
 * 参数: packet - 指向数据包的指针
 *       hash_table - 指向哈希表数组的指针
 *       loc - 哈希桶索引
 * 返回: 1 表示添加成功，0 表示添加失败（内存分配失败）
 */
int ht_add_entry(u_char *, struct table_entry **, int);

/* ht_hash: 计算 MAC 地址的哈希值
 * 参数: packet - 指向数据包的指针
 * 返回: 计算出的哈希值（已对哈希表大小取模）
 */
u_long ht_hash(u_char *);

/* ht_init_table: 初始化哈希表
 * 参数: hash_table - 指向哈希表数组的指针
 * 返回: 无
 */
void ht_init_table(struct table_entry **);

/* cleanup: SIGINT 信号处理函数
 * 参数: signo - 信号编号
 * 返回: 无
 * 功能: 设置全局变量 loop 为 0，使程序优雅退出
 */
void cleanup(int);

/* catch_sig: 注册信号处理函数
 * 参数: signo - 要捕获的信号编号
 *       handler - 指向信号处理函数的指针
 * 返回: 1 表示注册成功，-1 表示注册失败
 */
int catch_sig(int, void(*)());

/* 文件结束标记 */
/* EOF */

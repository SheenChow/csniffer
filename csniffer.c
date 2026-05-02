/*
 *  $Id: csniffer.c,v 1.1.1.1 2001/11/29 00:16:48 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  csniffer.c - pcap 示例代码
 *
 *  功能说明：
 *  这是一个被动的 MAC 地址嗅探器，用于捕获网络中的以太网数据包，
 *  并将源 MAC 地址映射到对应的厂商（通过 OUI 数据库）。
 *
 *  更新说明：
 *  - 使用最新的 libpcap API（pcap_findalldevs, pcap_create, pcap_activate）
 *  - 替代了已弃用的 pcap_lookupdev() 和 pcap_open_live()
 *  - 添加了详细的中文注释
 */

#include "./csniffer.h"

/* 全局变量定义 */
int loop = 1;                     /* 主循环控制标志，1表示继续运行，0表示退出 */
u_long mac = 0;                   /* 已捕获的唯一 MAC 地址计数器 */

/*
 * 函数名称：main
 * 功能描述：程序主函数，处理命令行参数，初始化 libpcap，
 *           进入数据包捕获循环，最后清理资源并退出。
 * 参数说明：
 *   argc - 命令行参数个数
 *   argv - 命令行参数数组
 * 返回值：
 *   EXIT_SUCCESS - 正常退出
 *   EXIT_FAILURE - 异常退出
 */
int
main(int argc, char **argv)
{
    int c;                          /* 用于存储 getopt() 的返回值 */
    pcap_t *p;                      /* libpcap 捕获描述符 */
    char *device;                   /* 网络接口设备名称 */
    pcap_if_t *alldevs;            /* 所有可用网络设备列表 */
    u_char *packet;                 /* 指向捕获的数据包数据 */
    int print_ip;                   /* 是否打印 IP 地址的标志 */
    struct pcap_pkthdr h;          /* 数据包头部信息（时间戳、长度等） */
    struct pcap_stat ps;           /* libpcap 统计信息 */
    char errbuf[PCAP_ERRBUF_SIZE]; /* 错误信息缓冲区，大小由 libpcap 定义 */
    struct bpf_program filter_code;/* 编译后的 BPF 过滤器程序 */
    bpf_u_int32 local_net, netmask;/* 本地网络地址和子网掩码 */
    struct table_entry *hash_table[HASH_TABLE_SIZE];  /* 哈希表，用于存储已捕获的 MAC 地址 */

    /* 初始化变量 */
    device = NULL;
    alldevs = NULL;
    print_ip = 0;

    /* 解析命令行参数 */
    /* 选项说明：
     *   -I: 启用 IP 地址打印功能
     *   -i <device>: 指定要使用的网络接口
     */
    while ((c = getopt(argc, argv, "Ii:")) != EOF)
    {
        switch (c)
        {
            case 'I':
                print_ip = 1;      /* 设置打印 IP 地址标志 */
                break;
            case 'i':
                device = optarg;    /* 获取用户指定的网络接口名称 */
                break;
            default:
                exit(EXIT_FAILURE); /* 遇到未知选项，退出程序 */
        }
    }

    /* 打印程序欢迎信息 */
    printf("csniffer 1.0 [被动 MAC -> OUI 厂商映射工具]\n");
    printf("按 Ctrl-C 退出\n");

    /*
     * 如果用户未指定网络接口，则自动查找可用的网络设备。
     * 使用 pcap_findalldevs() 替代已弃用的 pcap_lookupdev()。
     */
    if (device == NULL)
    {
        /* 获取所有可用的网络设备列表 */
        if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR)
        {
            fprintf(stderr, "pcap_findalldevs() 失败: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
        
        /* 检查是否找到任何设备 */
        if (alldevs == NULL)
        {
            fprintf(stderr, "未找到可用的网络设备\n");
            exit(EXIT_FAILURE);
        }
        
        /* 使用列表中的第一个设备作为默认设备 */
        device = alldevs->name;
        printf("使用默认设备: %s\n", device);
    }

    /*
     * 创建 libpcap 捕获句柄。
     * 使用 pcap_create() + pcap_activate() 替代已弃用的 pcap_open_live()。
     * 这种方式允许在激活之前设置各种捕获选项。
     */
    p = pcap_create(device, errbuf);
    if (p == NULL)
    {
        fprintf(stderr, "pcap_create() 失败: %s\n", errbuf);
        /* 清理已分配的资源 */
        if (alldevs != NULL)
        {
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
    }

    /* 设置捕获的最大数据包长度（快照长度） */
    if (pcap_set_snaplen(p, SNAPLEN) == PCAP_ERROR)
    {
        fprintf(stderr, "pcap_set_snaplen() 失败: %s\n", pcap_geterr(p));
        pcap_close(p);
        if (alldevs != NULL)
        {
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
    }

    /* 设置混杂模式（1 表示启用） */
    if (pcap_set_promisc(p, PROMISC) == PCAP_ERROR)
    {
        fprintf(stderr, "pcap_set_promisc() 失败: %s\n", pcap_geterr(p));
        pcap_close(p);
        if (alldevs != NULL)
        {
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
    }

    /* 设置读取超时时间（毫秒） */
    if (pcap_set_timeout(p, TIMEOUT) == PCAP_ERROR)
    {
        fprintf(stderr, "pcap_set_timeout() 失败: %s\n", pcap_geterr(p));
        pcap_close(p);
        if (alldevs != NULL)
        {
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
    }

    /* 激活捕获句柄，使所有设置生效 */
    if (pcap_activate(p) == PCAP_ERROR)
    {
        fprintf(stderr, "pcap_activate() 失败: %s\n", pcap_geterr(p));
        pcap_close(p);
        if (alldevs != NULL)
        {
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
    }

    /*
     * 获取指定网络接口的网络地址和子网掩码。
     * 这些信息用于编译 BPF 过滤器。
     */
    if (pcap_lookupnet(device, &local_net, &netmask, errbuf) == -1)
    {
        fprintf(stderr, "pcap_lookupnet() 失败: %s\n", errbuf);
        pcap_close(p);
        if (alldevs != NULL)
        {
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
    }

    /*
     * 编译 BPF 过滤器表达式。
     * FILTER 定义在头文件中，默认为空字符串（不过滤）。
     * 参数 1 表示优化过滤器代码。
     */
    if (pcap_compile(p, &filter_code, FILTER, 1, netmask) == -1)
    {
        fprintf(stderr, "pcap_compile() 失败: %s\n", pcap_geterr(p));
        pcap_close(p);
        if (alldevs != NULL)
        {
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
    }

    /* 将编译好的过滤器设置到捕获句柄上 */
    if (pcap_setfilter(p, &filter_code) == -1)
    {
        fprintf(stderr, "pcap_setfilter() 失败: %s\n", pcap_geterr(p));
        pcap_close(p);
        if (alldevs != NULL)
        {
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
    }

    /* 检查数据链路层类型，确保是以太网 */
    if (pcap_datalink(p) != DLT_EN10MB)
    {
        fprintf(stderr, "csniffer 仅支持以太网链路类型。\n");
        pcap_close(p);
        if (alldevs != NULL)
        {
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
    }

    /* 注册 SIGINT 信号处理函数（用于捕获 Ctrl-C） */
    if (catch_sig(SIGINT, cleanup) == -1)
    {
        fprintf(stderr, "无法注册信号处理函数。\n");
        pcap_close(p);
        if (alldevs != NULL)
        {
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
    }

    /*
     * 主捕获循环。
     * 首先初始化哈希表，然后进入循环捕获数据包。
     * 当 loop 变量被信号处理函数设置为 0 时，循环结束。
     */
    for (ht_init_table(hash_table); loop;)
    {
        /* 读取下一个数据包 */
        packet = (u_char *)pcap_next(p, &h);
        if (packet == NULL)
        {
            continue;   /* 如果超时或出错，继续尝试 */
        }

        /*
         * 检查这个数据包是否"有趣"（即是否是新的 MAC 地址）。
         * 如果是新的 MAC 地址，打印相关信息。
         */
        if (interesting(packet, hash_table))
        {
            if (print_ip)
            {
                /* 打印 MAC 地址 @ IP 地址 -> 厂商名称 */
                printf("%s @ %s -> %s\n", eprintf(packet),
                        iprintf(packet + 26),
                        b_search(packet + 6));
            }
            else
            {
                /* 仅打印 MAC 地址 -> 厂商名称 */
                printf("%s -> %s\n", eprintf(packet),
                        b_search(packet + 6));
            }
        }
    }

    /*
     * 获取并打印 libpcap 统计信息。
     * 包括接收的数据包数、丢弃的数据包数等。
     */
    if (pcap_stats(p, &ps) == -1)
    {
        fprintf(stderr, "pcap_stats() 失败: %s\n", pcap_geterr(p));
    }
    else
    {
        printf("\nlibpcap 接收的数据包数:\t%6d\n"
                 "libpcap 丢弃的数据包数:\t%6d\n"
                 "已记录的唯一 MAC 数:\t%6ld\n",
                ps.ps_recv, ps.ps_drop, mac);
    }

    /* 关闭 libpcap 捕获句柄，释放相关资源 */
    pcap_close(p);

    /* 释放设备列表（如果已分配） */
    if (alldevs != NULL)
    {
        pcap_freealldevs(alldevs);
    }

    return (EXIT_SUCCESS);
}

/*
 * 函数名称：b_search
 * 功能描述：在 OUI 表中执行二分查找，根据 MAC 地址前缀查找对应的厂商名称。
 * 参数说明：
 *   prefix - 指向 MAC 地址前 3 字节（OUI 部分）的指针
 * 返回值：
 *   找到时返回厂商名称字符串
 *   未找到时返回 "Unknown Vendor"
 *
 * 注意：OUI 表必须是已排序的，二分查找才能正常工作。
 */
const char *
b_search(u_char *prefix)
{
    struct oui *ent;           /* 指向当前 OUI 表条目的指针 */
    int start, end, diff, mid; /* 二分查找的边界、差值和中间位置 */

    start = 0;
    /* 计算 OUI 表的条目数 */
    end = sizeof(oui_table) / sizeof(oui_table[0]);

    /* 二分查找主循环 */
    while (end > start)
    {
        mid = (start + end) / 2;  /* 计算中间位置 */
        ent = &oui_table[mid];     /* 获取中间条目 */

        /* 逐字节比较前缀（从高字节到低字节） */
        diff = prefix[0] - ent->prefix[0];

        if (diff == 0)
        {
            diff = prefix[1] - ent->prefix[1];
        }
        if (diff == 0)
        {
            diff = prefix[2] - ent->prefix[2];
        }

        /* 根据比较结果调整查找范围 */
        if (diff == 0)
        {
            return (ent->vendor);  /* 找到匹配项，返回厂商名称 */
        }
        if (diff < 0)
        {
            end = mid;              /* 在左半部分继续查找 */
        }
        else
        {
            start = mid + 1;        /* 在右半部分继续查找 */
        }
    }

    /* 未找到匹配项 */
    return ("Unknown Vendor");
}

/*
 * 函数名称：eprintf
 * 功能描述：将以太网数据包中的源 MAC 地址格式化为标准的冒号分隔字符串。
 * 参数说明：
 *   packet - 指向以太网数据包的指针
 * 返回值：
 *   格式化后的 MAC 地址字符串（静态缓冲区，每次调用会被覆盖）
 *
 * 以太网帧格式：
 *   字节 0-5:  目的 MAC 地址
 *   字节 6-11: 源 MAC 地址
 *   字节 12-13: 类型/长度
 */
char *
eprintf(u_char *packet)
{
    int n;                          /* 已写入字符数 */
    static char address[18];        /* 静态缓冲区，存储格式化后的地址 */
                                    /* 格式: "XX:XX:XX:XX:XX:XX\0" 需要 18 字节 */

    /* 逐字节格式化源 MAC 地址（从数据包偏移 6 开始） */
    n = sprintf(address, "%.2x:", packet[6]);
    n += sprintf(address + n, "%.2x:", packet[7]);
    n += sprintf(address + n, "%.2x:", packet[8]);
    n += sprintf(address + n, "%.2x:", packet[9]);
    n += sprintf(address + n, "%.2x:", packet[10]);
    n += sprintf(address + n, "%.2x", packet[11]);
    address[n] = '\0';              /* 确保字符串以 null 结尾 */

    return (address);
}

/*
 * 函数名称：iprintf
 * 功能描述：将 4 字节的 IP 地址格式化为点分十进制字符串。
 * 参数说明：
 *   address - 指向 4 字节 IP 地址的指针（网络字节序）
 * 返回值：
 *   格式化后的 IP 地址字符串（静态缓冲区，每次调用会被覆盖）
 *
 * 格式示例：
 *   输入: 0xC0A80101 (网络字节序)
 *   输出: "192.168.  1.  1"
 */
char *
iprintf(u_char *address)
{
    static char ip[17];             /* 静态缓冲区，最大需要 "XXX.XXX.XXX.XXX\0" */

    /* 使用 & 255 确保无符号字节值 */
    sprintf(ip, "%3d.%3d.%3d.%3d", (address[0] & 255), (address[1] & 255),
            (address[2] & 255), (address[3] & 255));

    return (ip);
}

/*
 * 函数名称：interesting
 * 功能描述：检查数据包中的源 MAC 地址是否是新的（未见过的）。
 *           如果是新的，将其添加到哈希表中。
 * 参数说明：
 *   packet - 指向数据包的指针
 *   hash_table - 指向哈希表数组的指针
 * 返回值：
 *   1 - 这是一个新的 MAC 地址（有趣的数据包）
 *   0 - 这个 MAC 地址已经见过（无趣的数据包）
 *
 * 注意：
 *   - 以太网帧的源 MAC 地址位于偏移 6-11 字节
 *   - 全局变量 mac 用于计数唯一的 MAC 地址数量
 */
int
interesting(u_char *packet, struct table_entry **hash_table)
{
    u_long n;                       /* 哈希值 */

    /* 计算源 MAC 地址的哈希值 */
    n = ht_hash(packet);

    /* 检查该哈希桶是否已有条目 */
    if (hash_table[n])
    {
        /* 哈希桶非空，检查是否已存在相同的 MAC 地址 */
        if (!ht_dup_check(packet, hash_table, n))
        {
            /* 不存在重复，添加新条目 */
            if (ht_add_entry(packet, hash_table, n))
            {
                mac++;              /* 唯一 MAC 计数器加 1 */
                return (1);         /* 返回 1 表示这是新地址 */
            }
        }
        else
        {
            /* 已存在重复 */
            return (0);
        }
    }
    else
    {
        /* 哈希桶为空，直接添加新条目 */
        if (ht_add_entry(packet, hash_table, n))
        {
            mac++;                  /* 唯一 MAC 计数器加 1 */
            return (1);
        }
    }

    return (0);
}

/*
 * 函数名称：ht_dup_check
 * 功能描述：检查给定的 MAC 地址是否已存在于哈希表的指定桶中。
 * 参数说明：
 *   packet - 指向数据包的指针（用于提取源 MAC 地址）
 *   hash_table - 指向哈希表数组的指针
 *   loc - 哈希桶索引
 * 返回值：
 *   1 - 已存在相同的 MAC 地址（重复）
 *   0 - 不存在相同的 MAC 地址
 *
 * 实现：
 *   遍历指定哈希桶中的链表，逐一比较 MAC 地址的 6 个字节。
 */
int
ht_dup_check(u_char *packet, struct table_entry **hash_table, int loc)
{
    struct table_entry *p;          /* 遍历链表的指针 */

    /* 遍历指定哈希桶的链表 */
    for (p = hash_table[loc]; p; p = p->next)
    {
        /* 比较 6 字节的 MAC 地址 */
        if (p->mac[0] == packet[6]  && p->mac[1] == packet[7] &&
            p->mac[2] == packet[8]  && p->mac[3] == packet[9] &&
            p->mac[4] == packet[10] && p->mac[5] == packet[11])
        {
            return (1);              /* 找到重复 */
        }
    }

    return (0);                      /* 未找到重复 */
}

/*
 * 函数名称：ht_add_entry
 * 功能描述：将新的 MAC 地址添加到哈希表的指定桶中。
 * 参数说明：
 *   packet - 指向数据包的指针（用于提取源 MAC 地址）
 *   hash_table - 指向哈希表数组的指针
 *   loc - 哈希桶索引
 * 返回值：
 *   1 - 添加成功
 *   0 - 添加失败（内存分配失败）
 *
 * 实现：
 *   - 如果哈希桶为空，直接创建新节点作为桶首
 *   - 如果哈希桶非空，将新节点追加到链表末尾
 *   - 使用尾插法保持插入顺序
 */
int
ht_add_entry(u_char *packet, struct table_entry **hash_table, int loc)
{
    struct table_entry *p;          /* 临时指针 */

    /* 情况 1：哈希桶为空，直接创建首节点 */
    if (hash_table[loc] == NULL)
    {
        hash_table[loc] = malloc(sizeof(struct table_entry));
        if (hash_table[loc] == NULL)
        {
            return(0);              /* 内存分配失败 */
        }

        /* 从数据包中复制源 MAC 地址（偏移 6-11） */
        hash_table[loc]->mac[0] = packet[6];
        hash_table[loc]->mac[1] = packet[7];
        hash_table[loc]->mac[2] = packet[8];
        hash_table[loc]->mac[3] = packet[9];
        hash_table[loc]->mac[4] = packet[10];
        hash_table[loc]->mac[5] = packet[11];
        hash_table[loc]->next = NULL;  /* 尾节点指针为空 */
        return (1);
    }
    else
    {
        /* 情况 2：哈希桶非空，找到链表末尾 */
        for (p = hash_table[loc]; p->next; p = p->next);
        
        /* 分配新节点 */
        p->next = malloc(sizeof(struct table_entry)); 
        if (p->next == NULL)
        {
            return (0);              /* 内存分配失败 */
        }

        /* 移动到新节点 */
        p = p->next;
        
        /* 复制 MAC 地址 */
        p->mac[0] = packet[6];
        p->mac[1] = packet[7];
        p->mac[2] = packet[8];
        p->mac[3] = packet[9];
        p->mac[4] = packet[10];
        p->mac[5] = packet[11];
        p->next = NULL;              /* 新节点成为新的尾节点 */
    }

    return (1);
}

/*
 * 函数名称：ht_hash
 * 功能描述：计算数据包中源 MAC 地址的哈希值。
 * 参数说明：
 *   packet - 指向数据包的指针
 * 返回值：
 *   计算出的哈希值（已对哈希表大小取模）
 *
 * 哈希算法：
 *   使用简单的多项式滚动哈希函数：
 *   hash = (...((byte0 * 13) + byte1) * 13 + byte2) * 13 + ...
 *   
 *   基数 13 是一个经验选择，用于减少冲突。
 *
 * 注意：
 *   源 MAC 地址位于以太网帧的偏移 6-11 字节处。
 */
u_long
ht_hash(u_char *packet)
{
    int i;                           /* 循环计数器 */
    u_long j;                        /* 哈希累加值 */

    /* 对源 MAC 地址的 6 个字节（偏移 6 到 11）计算哈希 */
    for (i = 6, j = 0; i != 12; i++)
    {
        j = (j * 13) + packet[i];   /* 多项式滚动哈希 */
    }

    /* 对哈希表大小取模，确保返回值在有效索引范围内 */
    return (j %= HASH_TABLE_SIZE);
}

/*
 * 函数名称：ht_init_table
 * 功能描述：初始化哈希表，将所有桶指针设置为 NULL。
 * 参数说明：
 *   hash_table - 指向哈希表数组的指针
 *
 * 注意：
 *   哈希表大小由 HASH_TABLE_SIZE 宏定义（通常是一个素数，以减少冲突）。
 */
void
ht_init_table(struct table_entry **hash_table)
{
    int c;                           /* 循环计数器 */

    /* 遍历所有哈希桶，初始化为 NULL */
    for (c = 0; c < HASH_TABLE_SIZE; c++)
    {
        hash_table[c] = NULL;
    }
}

/*
 * 函数名称：cleanup
 * 功能描述：SIGINT 信号处理函数。当用户按下 Ctrl-C 时被调用。
 * 参数说明：
 *   signo - 信号编号（此处应为 SIGINT）
 *
 * 作用：
 *   设置全局变量 loop 为 0，使主捕获循环优雅退出。
 *   打印提示信息告知用户程序正在退出。
 */
void
cleanup(int signo)
{
    loop = 0;                       /* 设置退出标志 */
    printf("已捕获中断信号，准备退出...\n");
}

/*
 * 函数名称：catch_sig
 * 功能描述：使用 sigaction() 系统调用注册信号处理函数。
 * 参数说明：
 *   signo - 要捕获的信号编号（如 SIGINT）
 *   handler - 指向信号处理函数的指针
 * 返回值：
 *   1  - 注册成功
 *   -1 - 注册失败
 *
 * 相比 signal() 函数，sigaction() 提供：
 *   - 更可靠的信号处理语义
 *   - 更好的可移植性
 *   - 更多的控制选项
 */
int
catch_sig(int signo, void (*handler)())
{
    struct sigaction action;        /* sigaction 结构体 */

    action.sa_handler = handler;    /* 设置信号处理函数 */
    sigemptyset(&action.sa_mask);   /* 清空信号掩码（不阻塞额外信号） */
    action.sa_flags = 0;            /* 无特殊标志 */

    /* 注册信号处理函数 */
    if (sigaction(signo, &action, NULL) == -1)
    {
        return (-1);                 /* 注册失败 */
    }
    else
    {
        return (1);                  /* 注册成功 */
    }
}

/* 文件结束标记 */
/* EOF */

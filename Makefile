#   Building Open Source Network Security Tools
#   csniffer Makefile - libpcap component sample code
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.
#
#   更新说明：
#   - all 目标现在只编译 csniffer（主嗅探器程序）
#   - csniffer_ace 是可选目标，需要 libnet 库才能编译
#   - csniffer_ace 用于从 IEEE OUI 文本文件生成 oui.h
#   - 如果您已经有 oui.h，则不需要编译 csniffer_ace

srcdir		= .
CC		= gcc -g
CFLAGS		= -O2 -Wall
#LDFLAGS	= -L/path/to/libpcap/library/if/needed
OBJECTS_S       = csniffer.o
OBJECTS_SA      = csniffer_ace.o
#INCS		= -I/path/to/libpcap/headers/if/needed
LIBS		= -lpcap

.c.o:
	$(CC) -c $(CFLAGS) $(INCS) $<

# 默认目标：只编译 csniffer（主程序）
all: csniffer

# 主嗅探器程序（需要 libpcap）
csniffer: $(OBJECTS_S)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS_S) $(LDFLAGS) $(LIBS)

# OUI 生成工具（需要 libnet，可选）
# 这个工具用于从 IEEE OUI 文本文件生成 oui.h
# 如果您已经有 oui.h，则不需要这个工具
csniffer_ace: $(OBJECTS_SA)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS_SA)

# 清理目标
clean:
	rm -f *.o *~ *core* csniffer csniffer_ace

# EOF

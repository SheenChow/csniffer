#   Building Open Source Network Security Tools
#   csniffer Makefile - libpcap component sample code
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.

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

all: csniffer csniffer_ace

csniffer: $(OBJECTS_S)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS_S) $(LDFLAGS) $(LIBS)

csniffer_ace: $(OBJECTS_SA)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS_SA)

clean:
	rm -f *.o *~ *core* csniffer csniffer_ace

# EOF

TARGETS=lltdscan

CD=cd
CP=cp
TAR=tar
GPG=gpg
MAKE=make
RM=rm
SUDO=sudo

CC=gcc
# explicit pcap include dir is for redhat which is fux0red
CFLAGS=-g -I/usr/local/include -L/usr/local/lib -DFINDIF=$(FINDIF) -DUSE_NETIF=$(USE_NETIF) -DOPENBSD=$(OPENBSD) -DLINUX=$(LINUX) -DSOLARIS=$(SOLARIS) -DFREEBSD=$(FREEBSD) -DMACOSX=$(MACOSX) -I/usr/include/pcap -L/opt/csw/lib -R/opt/csw/lib

CFLAGS2=-g -I/usr/local/include -I/usr/local/include/libnet-1.1 -I/usr/include/pcap -I/usr/local/include/libnet11
LDFLAGS2=-g -L/usr/local/lib -L/usr/local/lib/libnet-1.1 -L/opt/csw/lib -L/usr/local/lib/libnet11 -L/usr/local/lib/libnet113

all: lltdscan

doc: arping.yodl
	yodl2man -o arping.8 arping.yodl

install:
	install -c lltdscan /usr/local/bin/lltdscan
	install lltdscan.8 /usr/local/man/man8/lltdscan.8

SYS=$(shell uname -s)
ifeq ($(SYS),SunOS)
EXTRA_LIBS=-lsocket -lnsl
endif

lltdscan: lltdscan.c lltd.c
	$(CC) $(CFLAGS2) $(LDFLAGS2) -o lltdscan lltdscan.c -lnet -lpcap -lrt $(EXTRA_LIBS)

clean:
	rm -f *.o $(TARGETS)

distclean: clean
	rm -f config{.cache,.h,.log,.status}

V=$(shell grep version arping-2/arping.c|grep const|sed 's:[a-z =]*::;s:f;::')
DFILE=arping-$(V).tar.gz
DDIR=arping-$(V)
dist:
	($(CD) ..; \
	$(CP) -ax arping $(DDIR); \
	$(RM) -fr $(DDIR)/{.\#*,CVS,.svn,*~} \
		$(DDIR)/arping-2/{.\#*,CVS,.svn,*~}; \
	$(MAKE) -C $(DDIR) doc; \
	$(TAR) cfz $(DFILE) $(DDIR); \
	$(GPG) -b -a $(DFILE); \
	)

maintainerclean: distclean
	rm -f config{.h.in,ure}

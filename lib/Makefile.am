#
# Copyright (c) 1998 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@vt.uni-paderborn.de>
#
# Process this file with automake to produce Makefile.in.

AUTOMAKE_OPTIONS = 1.3 gnits

noinst_LIBRARIES = libcompat.a

EXTRA_DIST = clnt_udp.c 

CFLAGS = -D_REENTRANT=1 @WARNFLAGS@ @DEFS@ @CFLAGS@

libcompat_a_SOURCES = dns_hosts.c res_options.h
libcompat_a_LIBADD = @LIBOBJS@

localedir = $(datadir)/locale
INCLUDES = -I../intl -DLOCALEDIR=\"$(localedir)\"

CLEANFILES = *~

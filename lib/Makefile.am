#
# Copyright (c) 1998, 1999 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#
# Process this file with automake to produce Makefile.in.

AUTOMAKE_OPTIONS = 1.4 gnits

noinst_LIBRARIES = libcompat.a

EXTRA_DIST = clnt_udp.c 

CFLAGS = -D_REENTRANT=1 @WARNFLAGS@ @DEFS@ @CFLAGS@

libcompat_a_SOURCES = dns_hosts.c res_options.h
libcompat_a_LIBADD = @LIBOBJS@

localedir = $(datadir)/locale
INCLUDES = -I../intl -DLOCALEDIR=\"$(localedir)\"

CLEANFILES = *~

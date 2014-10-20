#
# Copyright (c) 1998, 1999, 2003 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#
# Process this file with automake to produce Makefile.in.

noinst_LIBRARIES = libcompat.a

EXTRA_DIST = clnt_udp.c

AM_CFLAGS = -D_REENTRANT=1 @WARNFLAGS@

libcompat_a_SOURCES = dns_hosts.c res_options.h
libcompat_a_LIBADD = @LIBOBJS@

localedir = $(datadir)/locale
AM_CPPFLAGS = -DLOCALEDIR=\"$(localedir)\"

CLEANFILES = *~

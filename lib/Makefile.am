#
# Copyright (c) 1998, 1999, 2003 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#
# Process this file with automake to produce Makefile.in.

noinst_LIBRARIES = libcompat.a
noinst_HEADERS = ypbind3_binding.h

AM_CFLAGS = -D_REENTRANT=1 @WARNFLAGS@
AM_CPPFLAGS = -I$(srcdir) @TIRPC_CFLAGS@ @NSL_CFLAGS@ -DLOCALEDIR=\"$(localedir)\"

libcompat_a_SOURCES = dns_hosts.c res_options.h ypbind3_binding_dup.c \
		ypbind3_binding_free.c host2ypbind3_binding.c
libcompat_a_LIBADD = @LIBOBJS@

localedir = $(datadir)/locale

CLEANFILES = *~

#
# Copyright (c) 1998, 1999, 2001, 2003 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.4 gnits

INSTALL_PROGRAM = @INSTALL_PROGRAM@ -s -m 555

AM_CFLAGS = -D_REENTRANT=1 @WARNFLAGS@ -DUSE_BROADCAST=@USE_BROADCAST@
LDADD = ../lib/libcompat.a @LIBINTL@ @SLP_LIBS@

localedir = $(datadir)/locale
INCLUDES = -DLOCALEDIR=\"$(localedir)\"

CLEANFILES = *~

sbin_PROGRAMS = ypbind

noinst_HEADERS = ypbind.h log_msg.h local.h pthread_np.h

ypbind_SOURCES = ypbind-mt.c ypbind_xdr.c ypbind_svc.c \
	 	 ypbind_server.c log_msg.c serv_list.c \
		 pthread_np.c ypbind_slp.c

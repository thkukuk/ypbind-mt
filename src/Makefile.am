#
# Copyright (c) 1998, 1999, 2001, 2003 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

localedir = $(datadir)/locale

WARNFLAGS = @WARNFLAGS@
AM_CFLAGS = -D_REENTRANT=1 $(WARNFLAGS) -DLOCALEDIR=\"$(localedir)\" \
	@NSL_CFLAGS@ @TIRPC_CFLAGS@ -DUSE_SD_NOTIFY=@USE_SD_NOTIFY@ \
	-I$(srcdir)/../lib
# Disabled for now: @DBUS_CFLAGS@ @GLIB_CFLAGS@
ypbind_LDADD = ../lib/libcompat.a @SYSTEMD_LIBS@ @NSL_LIBS@ @TIRPC_LIBS@
# Disabled for now: @DBUS_LIBS@ @GLIB_LIBS@ 

CLEANFILES = *~

sbin_PROGRAMS = ypbind

noinst_HEADERS = ypbind.h log_msg.h local.h pthread_np.h

ypbind_SOURCES = ypbind-mt.c ypbind_svc.c \
	 	 ypbind_server.c log_msg.c serv_list.c \
		 pthread_np.c

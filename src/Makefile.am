#
# Copyright (c) 1998, 1999, 2001 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.4 gnits

INSTALL_PROGRAM = @INSTALL_PROGRAM@ -s -m 555

CFLAGS = -D_REENTRANT=1 @WARNFLAGS@ @DEFS@ @CFLAGS@ \
	 -DUSE_BROADCAST=@USE_BROADCAST@
LDADD = ../lib/libcompat.a @INTLLIBS@

localedir = $(datadir)/locale
INCLUDES = -I../intl -DLOCALEDIR=\"$(localedir)\"

CLEANFILES = *~

sbin_PROGRAMS = ypbind

ypbind_SOURCES = ypbind.h ypbind-mt.c ypbind_xdr.c ypbind_svc.c \
	 	 ypbind_server.c log_msg.c log_msg.h local.h serv_list.c \
		 pthread_np.c pthread_np.h

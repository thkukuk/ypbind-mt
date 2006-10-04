#
# Copyright (c) 1998, 1999, 2001, 2002, 2004, 2006 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#
AUTOMAKE_OPTIONS = 1.6 gnits dist-bzip2
#
SUBDIRS = lib src man po

CLEANFILES = *~

M4_FILES = $(shell ls $(srcdir)/m4/*.m4)

EXTRA_DIST = config.rpath  ChangeLog etc/yp.conf etc/ypbind.init \
	$(shell ls $(srcdir)/m4/*.m4) $(M4_FILES)

ACLOCAL_AMFLAGS = -I m4

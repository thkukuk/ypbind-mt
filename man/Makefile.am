#
# Copyright (c) 1997, 1998, 1999 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.3 gnits

CLEANFILES = *~ sedscript ypbind.8 yp.conf.5

EXTRA_DIST = sedscript.in ypbind.8.in yp.conf.5.in

man_MANS = ypbind.8 yp.conf.5

ypbind.8: ypbind.8.in sedscript
	-rm -f ypbind.8
	./sedscript < $(srcdir)/ypbind.8.in > ypbind.8

yp.conf.5: yp.conf.5.in sedscript
	-rm -f yp.conf.5
	./sedscript < $(srcdir)/yp.conf.5.in > yp.conf.5

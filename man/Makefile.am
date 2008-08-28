#
# Copyright (c) 1997, 1998, 1999, 2002, 2006 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~ ypbind.8 yp.conf.5

EXTRA_DIST = $(MANS) $(XMLS)

man_MANS = ypbind.8 yp.conf.5
XMLS = ypbind.8.xml yp.conf.5.xml

if ENABLE_REGENERATE_MAN
yp.conf.5: yp.conf.5.xml
	$(XMLLINT) --nonet --xinclude --postvalid --noout $<
	$(XSLTPROC) -o $(srcdir)/$@ --path $(srcdir) --xinclude --nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

ypbind.8: ypbind.8.xml
	$(XMLLINT) --nonet --xinclude --postvalid --noout $<
	$(XSLTPROC) -o $(srcdir)/$@ --path $(srcdir) --xinclude --nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
endif

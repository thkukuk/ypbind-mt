# Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.3 from Makefile.am

# Copyright (C) 1994, 1995, 1996, 1997, 1998 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

#
# Copyright (c) 1998 Thorsten Kukuk, Germany
#
# Author: Thorsten Kukuk <kukuk@vt.uni-paderborn.de>
#


SHELL = /bin/sh

srcdir = .
top_srcdir = ..
prefix = /usr
exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
libexecdir = ${exec_prefix}/libexec
datadir = ${prefix}/share
sysconfdir = ${prefix}/etc
sharedstatedir = ${prefix}/com
localstatedir = ${prefix}/var
libdir = ${exec_prefix}/lib
infodir = ${prefix}/info
mandir = ${prefix}/man
includedir = ${prefix}/include
oldincludedir = /usr/include

DISTDIR =

pkgdatadir = $(datadir)/ypbind-mt
pkglibdir = $(libdir)/ypbind-mt
pkgincludedir = $(includedir)/ypbind-mt

top_builddir = ..

ACLOCAL = aclocal
AUTOCONF = autoconf
AUTOMAKE = automake
AUTOHEADER = autoheader

INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}
transform = s,x,x,

NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
host_alias = i586-pc-linux-gnu
host_triplet = i586-pc-linux-gnu
CATALOGS =  de.gmo
CATOBJEXT = .gmo
CC = gcc
DATADIRNAME = share
GENCAT = 
GMOFILES =  de.gmo
GMSGFMT = /usr/bin/msgfmt
GT_NO = 
GT_YES = #YES#
INCLUDE_LOCALE_H = #include <locale.h>
INSTOBJEXT = .mo
INTLDEPS = 
INTLLIBS = 
INTLOBJS = 
LIBOBJS =  clnt_udp.o
MAKEINFO = makeinfo
MKINSTALLDIRS = ./mkinstalldirs
MSGFMT = /usr/bin/msgfmt
PACKAGE = ypbind-mt
POFILES =  de.po
POSUB = po
RANLIB = ranlib
USE_BROADCAST = 1
USE_INCLUDED_LIBINTL = no
USE_NLS = yes
USE_PIDFILE = 0
VERSION = 1.4
WARNFLAGS = -Wall
l = 

AUTOMAKE_OPTIONS = 1.3 gnits

INSTALL_PROGRAM = ${INSTALL} -s -m 555

CFLAGS = -D_REENTRANT=1 -Wall -DHAVE_CONFIG_H -O6 \
	-DUSE_PIDFILE=0 -DUSE_BROADCAST=1
LDADD = ../lib/libcompat.a 

localedir = $(datadir)/locale
INCLUDES = -I../intl -DLOCALEDIR=\"$(localedir)\"

CLEANFILES = *~

sbin_PROGRAMS = ypbind

ypbind_SOURCES = ypbind.h ypbind-mt.c ypbind_xdr.c ypbind_svc.c \
	 	 ypbind_server.c log_msg.c log_msg.h local.h serv_list.c \
		 pthread_np.c pthread_np.h
mkinstalldirs = $(SHELL) $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = ../config.h
CONFIG_CLEAN_FILES = 
PROGRAMS =  $(sbin_PROGRAMS)


DEFS = -DHAVE_CONFIG_H -I. -I$(srcdir) -I..
CPPFLAGS = 
LDFLAGS = 
LIBS = -lpthread -lnsl 
ypbind_OBJECTS =  ypbind-mt.o ypbind_xdr.o ypbind_svc.o ypbind_server.o \
log_msg.o serv_list.o pthread_np.o
ypbind_LDADD = $(LDADD)
ypbind_DEPENDENCIES =  ../lib/libcompat.a
ypbind_LDFLAGS = 
COMPILE = $(CC) $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS)
LINK = $(CC) $(CFLAGS) $(LDFLAGS) -o $@
DIST_COMMON =  Makefile.am Makefile.in


DISTFILES = $(DIST_COMMON) $(SOURCES) $(HEADERS) $(TEXINFOS) $(EXTRA_DIST)

TAR = tar
GZIP = --best
DEP_FILES =  .deps/log_msg.P .deps/pthread_np.P .deps/serv_list.P \
.deps/ypbind-mt.P .deps/ypbind_server.P .deps/ypbind_svc.P \
.deps/ypbind_xdr.P
SOURCES = $(ypbind_SOURCES)
OBJECTS = $(ypbind_OBJECTS)

all: Makefile $(PROGRAMS)

.SUFFIXES:
.SUFFIXES: .S .c .o .s
$(srcdir)/Makefile.in: Makefile.am $(top_srcdir)/configure.in $(ACLOCAL_M4)
	cd $(top_srcdir) && $(AUTOMAKE) --gnits src/Makefile

Makefile: $(srcdir)/Makefile.in  $(top_builddir)/config.status $(BUILT_SOURCES)
	cd $(top_builddir) \
	  && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status


mostlyclean-sbinPROGRAMS:

clean-sbinPROGRAMS:
	-test -z "$(sbin_PROGRAMS)" || rm -f $(sbin_PROGRAMS)

distclean-sbinPROGRAMS:

maintainer-clean-sbinPROGRAMS:

install-sbinPROGRAMS: $(sbin_PROGRAMS)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(sbindir)
	@list='$(sbin_PROGRAMS)'; for p in $$list; do \
	  if test -f $$p; then \
	    echo "  $(INSTALL_PROGRAM) $$p $(DESTDIR)$(sbindir)/`echo $$p|sed '$(transform)'`"; \
	     $(INSTALL_PROGRAM) $$p $(DESTDIR)$(sbindir)/`echo $$p|sed '$(transform)'`; \
	  else :; fi; \
	done

uninstall-sbinPROGRAMS:
	@$(NORMAL_UNINSTALL)
	list='$(sbin_PROGRAMS)'; for p in $$list; do \
	  rm -f $(DESTDIR)$(sbindir)/`echo $$p|sed '$(transform)'`; \
	done

.s.o:
	$(COMPILE) -c $<

.S.o:
	$(COMPILE) -c $<

mostlyclean-compile:
	-rm -f *.o core *.core

clean-compile:

distclean-compile:
	-rm -f *.tab.c

maintainer-clean-compile:

ypbind: $(ypbind_OBJECTS) $(ypbind_DEPENDENCIES)
	@rm -f ypbind
	$(LINK) $(ypbind_LDFLAGS) $(ypbind_OBJECTS) $(ypbind_LDADD) $(LIBS)

tags: TAGS

ID: $(HEADERS) $(SOURCES) $(LISP)
	here=`pwd` && cd $(srcdir) \
	  && mkid -f$$here/ID $(SOURCES) $(HEADERS) $(LISP)

TAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) $(LISP)
	tags=; \
	here=`pwd`; \
	list='$(SOURCES) $(HEADERS)'; \
	unique=`for i in $$list; do echo $$i; done | \
	  awk '    { files[$$0] = 1; } \
	       END { for (i in files) print i; }'`; \
	test -z "$(ETAGS_ARGS)$$unique$(LISP)$$tags" \
	  || (cd $(srcdir) && etags $(ETAGS_ARGS) $$tags  $$unique $(LISP) -o $$here/TAGS)

mostlyclean-tags:

clean-tags:

distclean-tags:
	-rm -f TAGS ID

maintainer-clean-tags:

distdir = $(top_builddir)/$(PACKAGE)-$(VERSION)/$(subdir)

subdir = src

distdir: $(DISTFILES)
	here=`cd $(top_builddir) && pwd`; \
	top_distdir=`cd $(top_distdir) && pwd`; \
	distdir=`cd $(distdir) && pwd`; \
	cd $(top_srcdir) \
	  && $(AUTOMAKE) --include-deps --build-dir=$$here --srcdir-name=$(top_srcdir) --output-dir=$$top_distdir --gnits src/Makefile
	@for file in $(DISTFILES); do \
	  d=$(srcdir); \
	  test -f $(distdir)/$$file \
	  || ln $$d/$$file $(distdir)/$$file 2> /dev/null \
	  || cp -p $$d/$$file $(distdir)/$$file; \
	done

DEPS_MAGIC := $(shell mkdir .deps > /dev/null 2>&1 || :)

-include $(DEP_FILES)

mostlyclean-depend:

clean-depend:
	-rm -rf .deps

distclean-depend:
	-rm -rf .deps

maintainer-clean-depend:
	-rm -rf .deps

%.o: %.c
	@echo '$(COMPILE) -c $<'; \
	$(COMPILE) -Wp,-MD,.deps/$(*F).P -c $<

%.lo: %.c
	@echo '$(LTCOMPILE) -c $<'; \
	$(LTCOMPILE) -Wp,-MD,.deps/$(*F).p -c $<
	@-sed -e 's/^\([^:]*\)\.o:/\1.lo \1.o:/' \
	  < .deps/$(*F).p > .deps/$(*F).P
	@-rm -f .deps/$(*F).p
info:
dvi:
check: all
	$(MAKE)
installcheck:
install-exec: install-sbinPROGRAMS
	@$(NORMAL_INSTALL)

install-data: 
	@$(NORMAL_INSTALL)

install: install-exec install-data all
	@:

uninstall: uninstall-sbinPROGRAMS

install-strip:
	$(MAKE) INSTALL_PROGRAM='$(INSTALL_PROGRAM) -s' INSTALL_SCRIPT='$(INSTALL_PROGRAM)' install
installdirs:
	$(mkinstalldirs)  $(DATADIR)$(sbindir)


mostlyclean-generic:
	-test -z "$(MOSTLYCLEANFILES)" || rm -f $(MOSTLYCLEANFILES)

clean-generic:
	-test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

distclean-generic:
	-rm -f Makefile $(DISTCLEANFILES)
	-rm -f config.cache config.log stamp-h stamp-h[0-9]*
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)

maintainer-clean-generic:
	-test -z "$(MAINTAINERCLEANFILES)" || rm -f $(MAINTAINERCLEANFILES)
	-test -z "$(BUILT_SOURCES)" || rm -f $(BUILT_SOURCES)
mostlyclean:  mostlyclean-sbinPROGRAMS mostlyclean-compile \
		mostlyclean-tags mostlyclean-depend mostlyclean-generic

clean:  clean-sbinPROGRAMS clean-compile clean-tags clean-depend \
		clean-generic mostlyclean

distclean:  distclean-sbinPROGRAMS distclean-compile distclean-tags \
		distclean-depend distclean-generic clean
	-rm -f config.status

maintainer-clean:  maintainer-clean-sbinPROGRAMS \
		maintainer-clean-compile maintainer-clean-tags \
		maintainer-clean-depend maintainer-clean-generic \
		distclean
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."

.PHONY: mostlyclean-sbinPROGRAMS distclean-sbinPROGRAMS \
clean-sbinPROGRAMS maintainer-clean-sbinPROGRAMS uninstall-sbinPROGRAMS \
install-sbinPROGRAMS mostlyclean-compile distclean-compile \
clean-compile maintainer-clean-compile tags mostlyclean-tags \
distclean-tags clean-tags maintainer-clean-tags distdir \
mostlyclean-depend distclean-depend clean-depend \
maintainer-clean-depend info dvi installcheck install-exec install-data \
install uninstall all installdirs mostlyclean-generic distclean-generic \
clean-generic maintainer-clean-generic clean mostlyclean distclean \
maintainer-clean


# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:

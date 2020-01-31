dnl Process this file with autoconf to produce a configure script.
AC_INIT([ypbind-mt], [2.7.2])
AC_CONFIG_SRCDIR([src/ypbind-mt.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS(config.h)
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)

AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_CC
dnl If we're using gcc, we want warning flags
#test -n "$GCC" && WARNFLAGS="-Wall"
test -n "$GCC" && WARNFLAGS="-W -Wall -Wbad-function-cast -Wcast-align -Winline -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wshadow -Wstrict-prototypes -Wundef"
AC_SUBST(WARNFLAGS)
AC_ISC_POSIX
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_GNU_SOURCE

dnl Checks for libraries.
dnl AC_CHECK_LIB(nsl, yp_get_default_domain)
AC_CHECK_LIB(pthread, pthread_create)

PKG_CHECK_MODULES([SYSTEMD], [libsystemd >= 209], [USE_SD_NOTIFY=1], [USE_SD_NOTIFY=0])
AC_SUBST(USE_SD_NOTIFY)
#PKG_CHECK_MODULES([NSL], [libnsl], [], [AC_CHECK_LIB([nsl],[yp_match],[NSL_LIBS="-lnsl"],[NSL_LIBS=""])])
PKG_CHECK_MODULES([NSL], [libnsl])
PKG_CHECK_MODULES([TIRPC], [libtirpc], [], [TIRPC_LIBS=""])
if test -n "$TIRPC_LIBS"; then
  AC_DEFINE(HAVE_TIRPC, 1, [Define to 1 if TIRPC is available])
fi

dnl The difficult part: could we reconfigure NSS or must we use DNS ?
AC_CHECK_FUNCS(__nss_configure_lookup)
if eval "test \"`echo '$ac_cv_func___nss_configure_lookup'`\" != yes"; then
   AC_CHECK_LIB(resolv, res_gethostbyname)
fi

dnl Check for gettid wrapper
AC_CHECK_FUNC(gettid, [AC_DEFINE(HAVE_GETTID, 1, [Define to 1 if gettid() is available])])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

dnl
dnl Check for xsltproc
dnl
enable_man=yes
AC_PATH_PROG([XSLTPROC], [xsltproc])
if test -z "$XSLTPROC"; then
     enable_man=no
fi
AC_PATH_PROG([XMLLINT], [xmllint],[/bin/true])
dnl check for DocBook DTD and stylesheets in the local catalog.
JH_CHECK_XML_CATALOG([-//OASIS//DTD DocBook XML V4.3//EN],
                [DocBook XML DTD V4.3], [], enable_man=no)
JH_CHECK_XML_CATALOG([http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl],
                [DocBook XSL Stylesheets], [], enable_man=no)
AM_CONDITIONAL(ENABLE_REGENERATE_MAN, test x$enable_man != xno)

dnl internationalization macros
AM_GNU_GETTEXT_VERSION([0.19])
AM_GNU_GETTEXT([external])

AC_OUTPUT(Makefile lib/Makefile src/Makefile man/Makefile po/Makefile.in)

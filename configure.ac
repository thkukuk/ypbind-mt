dnl Process this file with autoconf to produce a configure script.
AC_INIT([ypbind-mt], [2.1])
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
PKG_CHECK_MODULES([NIS], [libnis])
PKG_CHECK_MODULES([TIRPC], [libtirpc])


dnl AC_ARG_ENABLE([dbus-nm],
dnl    AC_HELP_STRING([--enable-dbus-nm],[Enable DBUS/NetworkManager support]),
dnl 	[],[enable_dbus_nm=no])
dnl if test "$enable_dbus_nm" \!= "no"
dnl then
dnl   PKG_CHECK_MODULES(DBUS, dbus-glib-1 >= 0.60)
dnl   AC_SUBST(DBUS_CFLAGS)
dnl   AC_SUBST(DBUS_LIBS)
dnl   PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.6)
dnl   AC_SUBST(GLIB_CFLAGS)
dnl   AC_SUBST(GLIB_LIBS)
dnl   AC_CHECK_HEADERS([NetworkManager/NetworkManager.h])
dnl   AC_CHECK_HEADERS([NetworkManager/NetworkManagerVPN.h])
dnl   AC_DEFINE(USE_DBUS_NM, 1, [Enable DBUS/NetworkManager support])
dnl fi

dnl The difficult part: could we reconfigure NSS or must we use DNS ?
AC_CHECK_FUNCS(__nss_configure_lookup)
if eval "test \"`echo '$ac_cv_func___nss_configure_lookup'`\" != yes"; then
   AC_CHECK_LIB(resolv, res_gethostbyname)
fi

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
AM_GNU_GETTEXT_VERSION
AM_GNU_GETTEXT([external])

AC_OUTPUT(Makefile lib/Makefile src/Makefile man/Makefile po/Makefile.in)

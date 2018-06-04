#!/bin/sh -x

rm -fv ltmain.sh config.sub config.guess config.h.in
aclocal -I m4
autoheader
#libtoolize --force --automake --copy
automake --add-missing --copy
autoreconf
chmod 755 configure

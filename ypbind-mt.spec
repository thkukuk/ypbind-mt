Summary: NIS (YP) binding process
Name: ypbind-mt
Version: 1.4
Release: 1
Copyright: GPL
Group: Networking
Source: ftp.kernel.org:/pub/linux/utils/net/NIS/ypbind-mt-%{PACKAGE_VERSION}.tar.gz
Packager: Thorsten Kukuk <kukuk@suse.de>
BuildRoot: /var/tmp/ypbind-mt
Conflicts: ypbind

%description
This is a daemon which runs on NIS/YP clients and binds them to a
NIS domain. It must be running for systems based on glibc to behave
as NIS clients. This version uses pthreads for better responses.

This implementation is only for NIS _clients_. You must already have
a NIS server running somewhere. You can find one for linux on
http://www-vt.uni-paderborn.de/~kukuk/linux/nis.html. Please read the
NIS-HOWTO, too.

%prep
%setup

%clean
make distclean
rm -rf $RPM_BUILD_ROOT

%build
./configure
make

%install
rm -rf $RPM_BUILD_ROOT
make prefix="$RPM_BUILD_ROOT"/usr install
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m644 etc/yp.conf $RPM_BUILD_ROOT/etc
install -m755 etc/ypbind.init $RPM_BUILD_ROOT/etc/rc.d/init.d/ypbind

%post
/sbin/chkconfig --add ypbind

%postun
/sbin/chkconfig --del ypbind

%files
%doc README COPYING ChangeLog
%config /etc/yp.conf
%config /etc/rc.d/init.d/ypbind
/usr/man/man8/ypbind.8
/usr/man/man5/yp.conf.5
/usr/sbin/ypbind
/usr/share/locale/de/LC_MESSAGES/ypbind-mt.mo

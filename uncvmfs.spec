%if 0%{?rhel} && 0%{?rhel} <= 6
%{!?__python2: %global __python2 /usr/bin/python2}
%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python2_sitearch: %global python2_sitearch %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}
%endif
%if 0%{?rhel} >= 7
%define systemd 1
%else
%define systemd 0
%endif

Name:           uncvmfs
Version:        0.6
Release:        1%{?dist}
Summary:        A tool for unpacking CVMFS repos

Group:          Applications/Internet
License:        GPLv2
URL:            http://www.hep.ph.ic.ac.uk
# For github-based releases, download from
# https://github.com/ic-hep/uncvmfs/archive/%{version}.tar.gz
# For git snapshots, try:
# git archive --prefix=%{name}-%{version}/ %{gitrev} | bzip2 > %{name}-%{version}-%{gitrev}.tar.bz2
Source0:        http://fake.url/uncvmfs-%{version}.tar.bz2
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  python python-devel openssl-devel
Requires:       python openssl
Requires:       squashfs-tools
Requires(pre):  shadow-utils

%if %systemd
BuildRequires: systemd-units
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
%endif

%description
A tool for unpacking CVMFS repos to a local filesystem.

%prep
%setup -q

%build
%{__python2} setup.py build

%install
rm -Rf %{buildroot}
%{__python2} setup.py install --skip-build --root %{buildroot}
# Extras
## Sysconfig
install -d %{buildroot}/%{_sysconfdir}/sysconfig
install -m 0644 extra/uncvmfs.sysconfig \
                %{buildroot}/%{_sysconfdir}/sysconfig/uncvmfs
%if %systemd
install -d %{buildroot}/%{_unitdir}
install -m 0644 extra/uncvmfs.service \
                %{buildroot}/%{_unitdir}/uncvmfs@.service
install -m 0644 extra/uncvmfs.timer \
                %{buildroot}/%{_unitdir}/uncvmfs@.timer
%else
## Cron
install -d %{buildroot}/%{_sysconfdir}/cron.d
install -m 0644 extra/uncvmfs.cron \
                %{buildroot}/%{_sysconfdir}/cron.d/uncvmfs.cron
%endif
install -m 0755 extra/uncvmfs_cron %{buildroot}/%{_bindir}/uncvmfs_cron
## Conf & Keys
install -d %{buildroot}/%{_sysconfdir}/uncvmfs/keys
install -m 0644 uncvmfs.conf %{buildroot}/%{_sysconfdir}/uncvmfs/uncvmfs.conf
install -m 0644 extra/keys/* \
                %{buildroot}/%{_sysconfdir}/uncvmfs/keys
## "Home" directory
install -d %{buildroot}/%{_localstatedir}/lib/uncvmfs

%clean
rm -Rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/uncvmfs
%{_bindir}/uncvmfs_tool
%if %systemd
%{_unitdir}/uncvmfs@.service
%{_unitdir}/uncvmfs@.timer
%doc extra/uncvmfs.cron
%else
%{_bindir}/uncvmfs_cron
%config(noreplace) %{_sysconfdir}/cron.d/uncvmfs.cron
%endif
%dir %{_sysconfdir}/uncvmfs
%config(noreplace) %{_sysconfdir}/uncvmfs/uncvmfs.conf
%dir %{_sysconfdir}/uncvmfs/keys
%config %{_sysconfdir}/uncvmfs/keys/*
%config(noreplace) %{_sysconfdir}/sysconfig/uncvmfs
%{python2_sitearch}/CVMFSSig.so
%{python2_sitearch}/UNCVMFSLib.py*
%{python2_sitearch}/%{name}-%{version}-py2.*.egg-info
%{_localstatedir}/lib/uncvmfs
%doc README
%doc LICENSE

%pre
getent group cvmfs >/dev/null || groupadd -r cvmfs
getent passwd cvmfs >/dev/null || \
    useradd -r -g cvmfs -d %{_localstatedir}/lib/uncvmfs -s /sbin/nologin \
    -c "CVMFS tools" cvmfs
exit 0

%if %systemd
%post
%systemd_post uncvmfs@.service
%systemd_post uncvmfs@.timer

%preun
%systemd_preun uncvmfs@.service
%systemd_preun uncvmfs@.timer

%postun
%systemd_postun_with_restart uncvmfs@.service
%systemd_postun_with_restart uncvmfs@.timer
%endif

%changelog
* Wed Aug 24 2016 Simon Fayer <sf105@ic.ac.uk> - 0.6-1
 - Not released yet!
 - Skip files with hash missing from catalog.

* Wed Aug 24 2016 Simon Fayer <sf105@ic.ac.uk> - 0.5-1
 - Add LICENSE file.
 - Merge fixes, CentOS7/systemd & squashfs support from bbockelm.

* Thu Nov 12 2015 Simon Fayer <sf105@ic.ac.uk> - 0.4-2
 - Catch BadStatusLine exception correctly.

* Thu Sep 03 2015 Simon Fayer <sf105@ic.ac.uk> - 0.4-1
 - Fix problems created by introduction of xattr catalog column.

* Wed Dec 10 2014 Simon Fayer <sf105@ic.ac.uk> - 0.3-3
 - Minor fix in cron job logging.

* Mon Dec 08 2014 Simon Fayer <sf105@ic.ac.uk> - 0.3-2
 - Improved cron job & logging.

* Mon Dec 08 2014 Simon Fayer <sf105@ic.ac.uk> - 0.3-1
- Initial release.


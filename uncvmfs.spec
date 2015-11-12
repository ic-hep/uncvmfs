%if 0%{?rhel} && 0%{?rhel} <= 6
%{!?__python2: %global __python2 /usr/bin/python2}
%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python2_sitearch: %global python2_sitearch %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}
%endif

Name:           uncvmfs
Version:        0.5
Release:        1%{?dist}
Summary:        A tool for unpacking CVMFS repos

Group:          Applications/Internet
License:        GPLv2
URL:            http://www.hep.ph.ic.ac.uk
Source0:        http://fake.url/uncvmfs-%{version}.tar.bz2
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  python python-devel openssl-devel
Requires:       python openssl
Requires(pre):  shadow-utils

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
## Cron
install -d %{buildroot}/%{_sysconfdir}/cron.d
install -m 0644 extra/uncvmfs.cron \
                %{buildroot}/%{_sysconfdir}/cron.d/uncvmfs.cron
install -m 0755 extra/uncvmfs_cron %{buildroot}/%{_bindir}/uncvmfs_cron
## Conf & Keys
install -d %{buildroot}/%{_sysconfdir}/uncvmfs/keys
install -m 0644 uncvmfs.conf %{buildroot}/%{_sysconfdir}/uncvmfs/uncvmfs.conf
install -m 0644 extra/keys/* \
                %{buildroot}/%{_sysconfdir}/uncvmfs/keys
## "Home" directory
install -d %{buildroot}/%{_localstatedir}/lib/cvmfs

%clean
rm -Rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/uncvmfs
%{_bindir}/uncvmfs_tool
%{_bindir}/uncvmfs_cron
%dir %{_sysconfdir}/uncvmfs
%config(noreplace) %{_sysconfdir}/uncvmfs/uncvmfs.conf
%dir %{_sysconfdir}/uncvmfs/keys
%config %{_sysconfdir}/uncvmfs/keys/*
%config(noreplace) %{_sysconfdir}/cron.d/uncvmfs.cron
%config(noreplace) %{_sysconfdir}/sysconfig/uncvmfs
%{python2_sitearch}/CVMFSSig.so
%{python2_sitearch}/UNCVMFSLib.py*
%{python2_sitearch}/%{name}-%{version}-py2.6.egg-info
%{_localstatedir}/lib/cvmfs
%doc README

%pre
getent group cvmfs >/dev/null || groupadd -r cvmfs
getent passwd cvmfs >/dev/null || \
    useradd -r -g cvmfs -d %{_localstatedir}/lib/cvmfs -s /sbin/nologin \
    -c "CVMFS tools" cvmfs
exit 0

%changelog
* Thu Nov 12 2015 Simon Fayer <sf105@ic.ac.uk> - 0.5-1
 - Nothing yet!

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


Name:		msktutil
Version:	0.5.1
Release:	1%{?dist}
Summary:	Program for interoperability with Active Directory 

Group:		System Environment/Base
License:	GPLv2+
URL:		https://code.google.com/p/msktutil/
Source0:	https://msktutil.googlecode.com/files/msktutil-%{version}.tar.bz2
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	openldap-devel
BuildRequires:	krb5-devel
Requires:	cyrus-sasl-gssapi

%description
Msktutil is a program for interoperability with Active Directory that can
create a computer account in Active Directory, create a system Kerberos keytab,
add and remove principals to and from that keytab, and change the computer
account's password.

%prep
%setup -q

%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%doc LICENSE README ChangeLog
%{_mandir}/man1/*
%{_sbindir}/%{name}


%changelog
* Mon Sep 09 2013 Olaf Flebbe <o.flebbe@science-computing.de> - 0.5.1-1
- Update to 0.5.1 

* Mon Jul 01 2013 Ken Dreyer <ktdreyer@ktdreyer.com> - 0.5-1
- Update to 0.5 final

* Thu Feb 14 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.4.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Fri Nov 23 2012 Ken Dreyer <ktdreyer@ktdreyer.com> - 0.4.2-1
- Update to 0.4.2 final

* Tue Nov 19 2012 Ken Dreyer <ktdreyer@ktdreyer.com> - 0.4.2-0.1
- Update to 0.4.2
- Remove CPPFLAGS and PATH_KRB5_CONFIG hacks

* Fri Jul 20 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.4.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Fri Mar 16 2012 Ken Dreyer <ktdreyer@ktdreyer.com> 0.4.1-1
- Update to 0.4.1
- Remove all upstreamed patches
- No need to regenerate configure with autoconf
- New upstream URL

* Sat Dec 3 2011 Ken Dreyer <ktdreyer@ktdreyer.com> 0.4-7
- Adjust conditionals for setting CPPFLAGS and KRB5_CONFIG
- Use PATH_KRB5_CONFIG instead of KRB5_CONFIG when running configure,
  since the latter is used by the Kerberos libraries to specify an
  alternative path to krb5.conf. Thanks again Russ Allbery.

* Mon Oct 3 2011 Ken Dreyer <ktdreyer@ktdreyer.com> 0.4-6
- Adjust regex in krb5-config patch. Thanks Russ Allbery.

* Sat Oct 1 2011 Ken Dreyer <ktdreyer@ktdreyer.com> 0.4-5
- Use patches from upstream git, instead of my own from -4
- Patch Makefile to use $LIBS
- Patch to use krb5-config to automatically determine build flags
- Bump Fedora version to F16 for /usr/include/et
- Regenerate configure with autoconf

* Thu Jul 21 2011 Ken Dreyer <ktdreyer@ktdreyer.com> 0.4-4
- Patch LDAP debug code to correctly report get/set operations

* Sun Jul 10 2011 Ken Dreyer <ktdreyer@ktdreyer.com> 0.4-3
- Reformat BRs, include ChangeLog, explicitly name binary.
- Patch Makefile to be verbose.

* Tue Jul 5 2011 Ken Dreyer <ktdreyer@ktdreyer.com> 0.4-2
- Don't package INSTALL and un-mark manpages as doc

* Tue May 10 2011 Ken Dreyer <ktdreyer@ktdreyer.com> 0.4-1
- Initial package

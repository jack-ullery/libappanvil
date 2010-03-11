#
# spec file for package libapparmor
#
# norootforbuild
%define _unpackaged_files_terminate_build 0

Name:		libapparmor1
Version:	2.5
Release:	3.20070916
License:	LGPL
Group:		Development/Libraries/C and C++
BuildRoot:	%{_tmppath}/%{name}-%{version}-build
Source0:        %{name}-%{version}.tar.bz2
BuildRequires:	swig gcc perl
Provides:	libapparmor
Provides:	libimmunix
Obsoletes:	libapparmor
Obsoletes:	libimmunix
Summary: A utility library for AppArmor

%define aalibversion 1.0.2

%description
-

%package -n libapparmor-devel
Requires:	%{name} = %{version}-%{release}
Group:		Development/Libraries/C and C++
Provides:	libapparmor:/usr/include/sys/apparmor.h
Summary:	-

%description -n libapparmor-devel
-

%post -n libapparmor-devel
/sbin/ldconfig

%postun -n libapparmor-devel
/sbin/ldconfig

%package -n perl-libapparmor
Requires:	%{name} = %{version}
Requires:	perl = %{perl_version}
Group:		Development/Libraries/Perl
Summary:	-

%description -n perl-libapparmor
-

%prep
%setup -q

%build
./configure --prefix=%{_prefix} --libdir=%{_libdir} --with-perl
make CFLAGS="${RPM_OPT_FLAGS}"

%install
make install DESTDIR="$RPM_BUILD_ROOT"
mkdir ${RPM_BUILD_ROOT}/%{_lib}
# this is really hacky
rm ${RPM_BUILD_ROOT}/%{_libdir}/libapparmor.so
rm ${RPM_BUILD_ROOT}/%{_libdir}/libimmunix.so
cp ${RPM_BUILD_ROOT}/%{_libdir}/libapparmor.so.%{aalibversion} ${RPM_BUILD_ROOT}/%{_lib}
cp ${RPM_BUILD_ROOT}/%{_libdir}/libimmunix.so.%{aalibversion} ${RPM_BUILD_ROOT}/%{_lib}
ln -s /%{_lib}/libapparmor.so.%{aalibversion} ${RPM_BUILD_ROOT}/%{_libdir}/libapparmor.so

find $RPM_BUILD_ROOT -name .packlist -exec rm -f {} \;
find $RPM_BUILD_ROOT -name perllocal.pod -exec rm -f {} \;

# create symlink for old change_hat(2) manpage
ln -s aa_change_hat.2 ${RPM_BUILD_ROOT}/%{_mandir}/man2/change_hat.2
%clean
rm -rf "$RPM_BUILD_ROOT"

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%files
%defattr(-,root,root)
/%{_lib}/libapparmor.so.*
/%{_lib}/libimmunix.so.*

%files -n libapparmor-devel
%defattr(-,root,root)
%{_libdir}/libapparmor.so
%{_libdir}/libapparmor.la
%{_libdir}/libapparmor.a
%{_libdir}/libimmunix.la
%{_libdir}/libimmunix.a
%doc %{_mandir}/man*/*
%dir %{_includedir}/aalogparse
%{_includedir}/sys/apparmor.h
%{_includedir}/aalogparse/*

%files -n perl-libapparmor
%defattr(-,root,root)
%dir %{perl_vendorarch}/auto/LibAppArmor
%{perl_vendorarch}/auto/LibAppArmor/*
%{perl_vendorarch}/LibAppArmor.pm

%changelog
* Sun Sep 16 2007 - sbeattie@suse.de
- aalogparse: add support for type=15xx audit field
- aalogparse: add support for audit messages thru syslog
- aalogparse: reduce noise to stdout on syntax errors
- aalogparse: add support for more missing message types
- aalogparse: parse messages w/safe (hex) string encodings
* Fri Aug 17 2007 - sbeattie@suse.de
- Fix broken symlink for old change_hat(2) manpage
* Wed Aug 15 2007 - sbeattie@suse.de
- fix braindead symbol versioning issue with old version name
- re-enable CFLAGS=RPM_OPT_FLAGS for build
- convert change_hat(2) to aa_change_hat(2)
- use 64bit magic token
- add aa_change_profile(2) interface
* Sat Jul 28 2007 - mbarringer@suse.de
- Merged in libaalogparse to the library/package
* Tue Apr  7 2007 - sbeattie@suse.de
- Add change_hat manpage to package
* Thu Jan 18 2007 - sbeattie@suse.de
- Add a clean stage to remove buildroot to specfile
* Fri Feb 17 2006 Seth Arnold <seth.arnold@suse.de> 2.0-4.1
- use gettid() instead of /proc/self
* Fri Feb 10 2006 Steve Beattie <sbeattie@suse.de> 2.0-3.2
- Use RPM_OPT_FLAGS
- Fix installed library version to match specfile version
* Wed Feb  1 2006 Steve Beattie <sbeattie@suse.de> 2.0-3.1
- Fix prototype to match change_hat(2) manpage
* Mon Jan 23 2006 Steve Beattie <sbeattie@suse.de> 2.0-3
- Rename to libapparmor.so and apparmor.h
* Thu Jan  5 2006 Steve Beattie <sbeattie@suse.de> 2.0-2
- Add svn repo number to tarball
* Wed Dec  7 2005 Steve Beattie <sbeattie@suse.de> 2.0-1
- Reset version for inclusion is SUSE autobuild
* Wed Dec  7 2005 Steve Beattie <sbeattie@suse.de> 1.99-8
- Disable 32bit builds on 64bit platforms for now
* Mon Dec  5 2005 Steve Beattie <sbeattie@suse.de> 1.99-7
- Rename package to libapparmor
* Wed Aug 10 2005 Steve Beattie <sbeattie@suse.de> 1.99-6_imnx
- Cleanup some of the deprecated exported symbols
* Thu Aug  4 2005 John Johansen <jjohansen@novell.com> 1.99-5_imnx
- and -m31 flag for s390
* Mon Jul 11 2005 Steve Beattie <sbeattie@novell.com> 1.99-4_imnx
- get rid of libimmunix_post_upgrade
- Re-license to LGPL
- update description
* Fri May 27 2005 Steve Beattie <steve@immunix.com> 1.99-3_imnx
- Clear token buffer before freeing.
- Error handling cleanup.
* Fri Feb 18 2005 Steve Beattie <steve@immunix.com> 1.99-2_imnx
- Use the right command for the 32bit env on 64bit platforms
- Support for 64bit builds on systems with combined 32/64 support
* Fri Feb  4 2005 Seth Arnold <sarnold@immunix.com> 1.99-1_imnx
- Reversion to 1.99
* Mon Nov  8 2004 Steve Beattie <steve@immunix.com> 1.2-3_imnx
- Finish conversion to slack-capable infrastructure.
* Thu Oct 28 2004 Steve Beattie <steve@immunix.com> 1.2-2_imnx
- Added a 'make install' target for prelim slack support
* Tue Oct 12 2004 Steve Beattie <steve@immunix.com> 1.2-1_imnx
- Bump version after shass-1.1 branched off
* Thu Sep 23 2004 Steve Beattie <steve@immunix.com> 1.0-13_imnx
- Vastly simplify the string handling in change_hat().
* Thu Sep  9 2004 Steve Beattie <steve@immunix.com> 1.0-12_imnx
- Conditionalize group the package shows up in.
* Thu Sep  9 2004 Steve Beattie <steve@immunix.com> 1.0-11_imnx
- Fix so change_hat functions correctly even when the token is zero.
* Thu Sep  2 2004 Steve Beattie <steve@immunix.com> 1.0-10_imnx
- Added that it provides %{_prefix}/sbin/libimmunix_post_upgrade, this
  was somehow breaking yast.
* Mon Aug 30 2004 Steve Beattie <steve@immunix.com> 1.0-9_imnx
- Copyright cleanups.
* Wed Jul 21 2004 Steve Beattie <steve@immunix.com> 1.0-8_imnx
- add basis for conditional distro support
* Thu May  28 2004 Tony Jones <tony@immunix.com> 1.0-7_imnx
- Add "changehat" command word to start of string written to /proc/pid/attr

#
# spec file for package libapparmor
#
# norootforbuild
%define _unpackaged_files_terminate_build 0

Name:		libapparmor1
Version:	2.1
Release:	1
License:	LGPL
Group:		Development/Libraries/C and C++
BuildRoot:	%{_tmppath}/%{name}-${version}-build
Source0:        %{name}-%{version}.tar.bz2
BuildRequires:	swig gcc perl
Provides:	libapparmor
Provides:	libimmunix
Obsoletes:	libapparmor
Obsoletes:	libimmunix
Summary: A utility library for AppArmor

%description
-

%package -n libapparmor-devel
Requires:	%{name} = %{version}
Group:		Development/Libraries/C and C++
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
make

%install
make install DESTDIR="$RPM_BUILD_ROOT"
mkdir ${RPM_BUILD_ROOT}/%{_lib}
# this is really hacky
rm ${RPM_BUILD_ROOT}/%{_libdir}/libapparmor.so
rm ${RPM_BUILD_ROOT}/%{_libdir}/libimmunix.so
cp ${RPM_BUILD_ROOT}/%{_libdir}/libapparmor.so.1.0.0 ${RPM_BUILD_ROOT}/%{_lib}
cp ${RPM_BUILD_ROOT}/%{_libdir}/libimmunix.so.1.0.0 ${RPM_BUILD_ROOT}/%{_lib}
ln -s /%{_lib}/libapparmor.so.1.0.0 ${RPM_BUILD_ROOT}/%{_libdir}/libapparmor.so
ln -s /%{_lib}/libimmunix.so.1.0.0 ${RPM_BUILD_ROOT}/%{_libdir}/libimmunix.so

find $RPM_BUILD_ROOT -name .packlist -exec rm -f {} \;
find $RPM_BUILD_ROOT -name perllocal.pod -exec rm -f {} \;

%clean
rm -rf "$RPM_BUILD_ROOT"

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%files
%defattr(-,root,root)
/%{_lib}/libapparmor.so.1.0.0
/%{_lib}/libimmunix.so.1.0.0

%files -n libapparmor-devel
%defattr(-,root,root)
%{_libdir}/libapparmor.so
%{_libdir}/libimmunix.so
%{_libdir}/libapparmor.la
%{_libdir}/libapparmor.a
%{_libdir}/libimmunix.la
%{_libdir}/libimmunix.a
%{_mandir}/man*/*
%dir %{_includedir}/aalogparse
%{_includedir}/sys/apparmor.h
%{_includedir}/aalogparse/*

%files -n perl-libapparmor
%defattr(-,root,root)
%dir %{perl_vendorarch}/auto/LibAppArmor
%{perl_vendorarch}/auto/LibAppArmor/*
%{perl_vendorarch}/LibAppArmor.pm

%changelog
-



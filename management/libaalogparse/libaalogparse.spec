#
# spec file for package libaalogparse
#
# norootforbuild
%define _unpackaged_files_terminate_build 0

Name:		libaalogparse0
Version:	0.7
Release:	1
License:	LGPL
Group:		Development/Libraries
BuildRoot:	%{_tmppath}/%{name}-${version}-build
Source0:        %{name}-%{version}.tar.bz2
BuildRequires:	swig gcc perl

Summary: A library for parsing AppArmor log messages

%description
-

%package -n libaalogparse-devel
Requires:	%{name} = %{version}
Group:		Development/Libraries
Summary:	-

%description -n libaalogparse-devel
-

%post -n libaalogparse-devel
/sbin/ldconfig

%postun -n libaalogparse-devel
/sbin/ldconfig

%package -n perl-libaalogparse
Requires:	%{name} = %{version} 
Requires:	perl = %{perl_version}
Group:		Development/Libraries/Perl
Summary:	-

%description -n perl-libaalogparse
-

%prep
%setup -q

%build
./configure --prefix=%{_prefix} --libdir=%{_libdir} --with-perl
make

%install
make install DESTDIR="$RPM_BUILD_ROOT"

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
%{_libdir}/libaalogparse.so.0.0.0

%files -n libaalogparse-devel
%defattr(-,root,root)
%{_libdir}/libaalogparse.la
%{_libdir}/libaalogparse.a
%dir %{_includedir}/aalogparse
%{_includedir}/aalogparse/*

%files -n perl-libaalogparse
%defattr(-,root,root)
%dir %{perl_vendorarch}/auto/AppArmorLogRecordParser
%{perl_vendorarch}/auto/AppArmorLogRecordParser/*
%{perl_vendorarch}/AppArmorLogRecordParser.pm

%changelog
-



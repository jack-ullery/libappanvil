#
# spec file for package apparmor-dbus
#
# norootforbuild

Name:		apparmor-dbus
BuildRequires:	audit-devel dbus-1-devel pkgconfig libapparmor-devel
Requires:	libapparmor
Version:	1.2
Release:	0
License:	GPL
Group:		System/Management
BuildRoot:	%{_tmppath}/%{name}-%{version}-build
Source0:	%{name}-%{version}.tar.bz2

Summary:	-

%description
-

%prep
%setup -n %{name}-%{version}
%build
autoreconf --force --install
export CFLAGS="$RPM_OPT_FLAGS"
%{?suse_update_config:%{suse_update_config -f}}
./configure --prefix=%{_prefix}
make

%install
rm -rf %{buildroot}
%makeinstall

%clean
rm -rf %{buildroot}

%files
%defattr(-, root, root)
%{_prefix}/bin/apparmor-dbus

%changelog
* Thu Sep 13 2007 - sbeattie@suse.de
- Bump to revision 1.2

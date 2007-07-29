#
# spec file for package apparmor-dbus
#
# norootforbuild

Name:		apparmor-dbus
BuildRequires:	audit-devel dbus-1-devel pkgconfig libapparmor-devel
Requires:	audit dbus-1 libapparmor
Version:	1.1
Release:	0
License:	GPL
Group:		System/Management
BuildRoot:	%{_tmppath}/%{name}-%{version}-build
Source0:	%{name}-%{version}.tar.gz

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


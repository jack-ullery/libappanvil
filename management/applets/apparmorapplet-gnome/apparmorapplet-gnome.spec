# norootforbuild

Name:		apparmorapplet-gnome
Version:	0.6
Release:	1
URL:		http://forge.novell.com/modules/xfmod/project/?apparmor
BuildRequires:	gnome-common gnome-desktop-devel gnome-panel-devel 
%if %suse_version > 1010
BuildRequires:  dbus-1-glib-devel
%else
BuildRequires:  dbus-1-devel dbus-1-glib
%endif
Group:		System/GUI/Gnome
Requires:	apparmor-dbus
BuildRoot:	%{_tmppath}/%{name}-%{version}-build

%description
-

%prep
%setup -q

%build
autoreconf -f -i

%configure --libexecdir=%{_prefix}/lib/apparmorapplet
make %{?jobs:-j%jobs}

%install
%makeinstall

%clean
rm -rf $RPM_BUILD_ROOT

%post
%run_ldconfig


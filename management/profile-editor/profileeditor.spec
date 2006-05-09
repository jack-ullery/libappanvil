# norootforbuild
Name: apparmor-profile-editor
BuildRequires: wxGTK-devel gcc-c++
Version: 0.9
Release: 1
Vendor: Novell
Copyright: GPL
Summary: AppArmor profile editor
Group: Application/Editors
Packager: mbarringer@suse.de
BuildRoot:  %{_tmppath}/%{name}-root
Source: apparmor-profile-editor-0.9.tar.gz

%description
AppArmor profile editor

%prep
%setup -q -n %{name}-%{version}
%build
autoreconf --force --install
export CFLAGS="$RPM_OPT_FLAGS -DSCI_LEXER -DLINK_LEXERS -fPIC -DPIC -DWX_PRECOMP -DNO_GCC_PRAGMA -D__WX"
export CXXFLAGS="$RPM_OPT_FLAGS -DSCI_LEXER -DLINK_LEXERS -fPIC -DPIC -DWX_PRECOMP -DNO_GCC_PRAGMA -D__WX"
%{?suse_update_config:%{suse_update_config -f}}
./configure --prefix=%{_prefix} --disable-debug --enable-debug=no
make

%install
strip $RPM_BUILD_ROOT%{_prefix}/bin/* || :
rm -rf %{buildroot}
%makeinstall

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig
%files
%defattr(-, root, root)
/usr/bin/profileeditor
%doc AUTHORS COPYING ChangeLog NEWS README TODO doc/en/AppArmorProfileEditor.htb
%changelog


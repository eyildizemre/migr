Name:           migr
Version:        0.1.0
Release:        1%{?dist}
Summary:        Move your home, packages, and settings to a new Linux install
License:        MIT
URL:            https://github.com/eyildizemre/migr
Source0:        %{url}/releases/download/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  glibc-static

%description
migr moves your home folder, packages, and desktop settings from one Linux
installation to another, across distributions too: back up to a drive,
reinstall, restore.

The package also installs migr-static, a statically linked copy that
"migr backup --include-self" puts in the backup, so the new system can run
migr before it is installed there.

%prep
%autosetup

%build
%make_build migr migr-static

%install
%make_install PREFIX=%{_prefix} install-static

%check
make test

%files
%license LICENSE
%doc README.md
%{_bindir}/migr
%{_bindir}/migr-static

%changelog
* Wed Oct 14 2026 Emre Yıldız <eyildizemre@proton.me> - 0.1.0-1
- First release

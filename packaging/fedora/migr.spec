Name:           migr
Version:        0.3.1
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
* Sun Oct 18 2026 Emre Yıldız <eyildizemre@proton.me> - 0.3.1-1
- Write a changed file whole before it replaces its copy

* Sun Oct 18 2026 Emre Yıldız <eyildizemre@proton.me> - 0.3.0-1
- Go on past an item the backup cannot read, and list it

* Sun Oct 18 2026 Emre Yıldız <eyildizemre@proton.me> - 0.2.3-1
- Read a backup manifest only if migr would have written it
- Leave a backup's access times alone when listing what an update removes

* Sat Oct 17 2026 Emre Yıldız <eyildizemre@proton.me> - 0.2.2-1
- Install only plain package names from a backup
- Give a sudo backup to its user without following links

* Sat Oct 17 2026 Emre Yıldız <eyildizemre@proton.me> - 0.2.1-1
- Never remove anything outside the backup when updating it
- Speed up pointing desktop settings at the new home folder

* Sat Oct 17 2026 Emre Yıldız <eyildizemre@proton.me> - 0.2.0-1
- Move folders inside the backup instead of copying them again

* Fri Oct 16 2026 Emre Yıldız <eyildizemre@proton.me> - 0.1.2-1
- Refuse to repair a journal written with another journal version
- Speed up repairing a journal with many damaged regions
- Resume a backup that was stopped while it created its journal
- Speed up loading a journal with many unfinished items

* Fri Oct 16 2026 Emre Yıldız <eyildizemre@proton.me> - 0.1.1-1
- Ask before an update removes parts of the backup it does not select
- Make room when an update fills its destination with moved files
- Name the path --include-self needs when migr-static is missing

* Wed Oct 14 2026 Emre Yıldız <eyildizemre@proton.me> - 0.1.0-1
- First release

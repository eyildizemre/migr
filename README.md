# migr

A CLI tool for migrating between Linux distributions. Detects your distro, backs up your main directories, browser profiles, and dotfiles, exports your package list, and restores everything on the new system.

Built out of necessity — I was moving from Ubuntu to Fedora, stressing over browser configs, SSH keys, and dotfiles. This automates what I was doing by hand.

Originally written in one day for an Intro to CS final project.

## Target Distributions

`migr` targets three package-manager families:

| Family | Package manager | Examples |
|---|---|---|
| Debian | `dpkg` / `apt` | Debian, Ubuntu, Mint, Pop!_OS, elementary, Zorin |
| Fedora | `rpm` / `dnf` | Fedora, RHEL, CentOS, Nobara |
| Arch | `pacman` | Arch, Manjaro, EndeavourOS, Garuda |

Derivatives are resolved through the `ID_LIKE` field of `/etc/os-release`, so a
distribution works even if it is not named above, as long as it declares one of these
families and uses its package manager.

Distributions outside these three — openSUSE, Void, Gentoo, and others — are detected
as unknown. Files, dotfiles, and browser profiles are still backed up and restored
normally; only the package list is skipped.

## Build

```bash
make
```

To activate the pre-commit hook (runs build + tests when C/shell/Makefile changes are staged), run this once after cloning:

```bash
git config core.hooksPath hooks
```

## Usage

```bash
./migr
./migr report
./migr backup <PATH>
./migr packages <FILE>
./migr restore <SOURCE>
```

## Commands

```
report                Show backup analysis report (default when no command given)
backup <PATH>         Clone files and packages to PATH
packages <FILE>       Export installed packages to FILE
restore <SOURCE>      Restore files and packages from a backup at SOURCE
help                  Show help
```

## Options

```
-n, --dry-run         Preview actions without making changes
-v, --verbose         Verbose output
-h, --help            Show help
```

Backup scope (`backup` only, mutually exclusive):

```
--critical            Back up Documents, Downloads, Pictures, and dotfiles (default)
--comprehensive       Back up everything except system files
<PATH...>             Paths listed after the destination are backed up exactly as
                      given, with no assumptions
```

```bash
./migr backup /mnt/drive
./migr backup /mnt/drive --comprehensive
./migr backup /mnt/drive ~/Documents ~/Projects
```

## Key Features

- **Smart Resume:** Interrupted backups resume automatically — files already cloned (matching size and timestamp) are skipped.
- **Localization:** Directory names are resolved via `xdg-user-dirs` — if your Documents folder is `Belgeler`, migr finds and backs it up correctly without any configuration.

## What Gets Backed Up

**`--critical` (default):** Documents, Downloads, Pictures — the irreplaceable files most likely to exist nowhere else.

**`--comprehensive`:** Everything `--critical` covers, plus Desktop, Videos, and Music.

**Explicit paths:** Exactly what you specify — no assumptions made.

**Dotfiles (all scopes except explicit paths):** .ssh, .gnupg, .gitconfig, .bashrc, .profile

**Browser Profiles (all scopes except explicit paths):** Firefox, Chrome, Chromium, Brave, Vivaldi, Edge, Opera — only the profiles present on the system are copied.

**Packages (all scopes except explicit paths):** Full package list via dpkg/rpm/pacman (saved as packages.txt, reinstalled on restore)

## Report

Running `migr` or `migr report` scans your home directory and shows sizes for main directories, dotfiles, dev tools, and browsers — plus a critical backup size estimate.

## Under the Hood

This tool was fully refactored to eliminate all shell-based execution. It no longer calls `system()` or `popen()` anywhere in the codebase — functions that silently pass strings to `/bin/sh` and are a well-known vector for shell injection vulnerabilities.

In their place, a custom pure C POSIX engine handles all I/O and process execution:

- **`clone_recursive()`** — recursive file and directory cloning via `open`/`read`/`write`/`mkdir`/`readdir`, with full metadata preservation (`chmod`, `utimensat`) and symlink handling. Replaces `cp -r`.
- **`get_dir_size()`** — recursive directory size calculation via `lstat` and `dirent`. Replaces `du`.
- **`run_command()`** — shell-free subprocess execution via `fork`/`execvp`/`waitpid`. Replaces `system()`.
- **`run_command_capture()`** — same as above, with stdout captured into a buffer via an anonymous `pipe`. Replaces `popen()`.

Package listing and restoration commands (`dpkg`, `rpm`, `pacman`, `dnf`, `apt-get`, `xargs`) are launched directly as process arguments — no shell is ever spawned. Size reporting uses native `off_t` arithmetic throughout for correct behaviour on both 32-bit (LFS) and 64-bit architectures.

## Planned

- [x] Dry-run mode
- [x] Pure C refactor
- [x] Comprehensive vs. critical-only backup modes
- [x] Localization (xdg-user-dirs support)
- [x] Cross-locale restore mapping (manifest system)
- [ ] Logging
- [ ] Network configuration backup
- [ ] Self-contained backup (embed static binary)
- [ ] Provide pre-built .deb, .rpm, and AUR packages

## License

MIT

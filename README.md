# migr

A CLI tool for migrating between Linux distributions. Detects your distro, backs up your main directories, browser profiles, and dotfiles, exports your package list, and restores everything on the new system.

Built out of necessity — I was moving from Ubuntu to Fedora, stressing over browser configs, SSH keys, and dotfiles. This automates what I was doing by hand.

Originally written in one day for an Intro to CS final project.

## Target Distributions

- Debian / Ubuntu / Mint
- Fedora / RHEL / CentOS
- Arch / Manjaro / EndeavourOS

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
./migr -report
./migr -backup <PATH>
./migr -packages <FILE>
./migr -restore <SOURCE>
```

## Options

```
-report               Show backup analysis report (default when no arguments given)
-backup <PATH>        Clone files and packages to PATH
-packages <FILE>      Export installed packages to FILE
-restore <SOURCE>     Restore files and packages from a backup at SOURCE
-n, --dry-run         Preview actions without making changes
-v                    Verbose output (combine with any flag)
-help                 Show help
```

Backup mode flags (combine with `-backup`):

```
-critical             Back up Documents, Downloads, Pictures, and dotfiles (default)
-comprehensive        Back up everything except system files
-paths <PATH...>      Back up specific paths provided by the user
```

## Key Features

- **Smart Resume:** Interrupted backups resume automatically — files already cloned (matching size and timestamp) are skipped.
- **Localization:** Directory names are resolved via `xdg-user-dirs` — if your Documents folder is `Belgeler`, migr finds and backs it up correctly without any configuration.

## What Gets Backed Up

**`-critical` (default):** Documents, Downloads, Pictures — the irreplaceable files most likely to exist nowhere else.

**`-comprehensive`:** Everything `-critical` covers, plus Desktop, Videos, and Music.

**`-paths`:** Exactly what you specify — no assumptions made.

**Dotfiles (all modes except `-paths`):** .ssh, .gnupg, .gitconfig, .bashrc, .profile

**Browser Profiles (all modes except `-paths`):** Firefox, Chrome, Chromium, Brave, Vivaldi, Edge, Opera — only the profiles present on the system are copied.

**Packages (all modes except `-paths`):** Full package list via dpkg/rpm/pacman (saved as packages.txt, reinstalled on restore)

## Report

Running `migr` or `migr -report` scans your home directory and shows sizes for main directories, dotfiles, dev tools, and browsers — plus a critical backup size estimate.

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
- [ ] Cloud storage support (via rclone)
- [ ] Provide pre-built .deb, .rpm, and AUR packages
- [ ] Granular backup selection (interactive per-directory prompts)

## License

MIT

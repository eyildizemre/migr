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
backup <PATH>         Create a resumable backup container under PATH
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

**Packages (all scopes except explicit paths):** The list of packages you explicitly installed — not the thousands of dependencies pulled in alongside them — saved as packages.txt and reinstalled on restore. Anything the new distribution cannot resolve is written to `skipped-packages.txt` rather than silently dropped.

## Backup Containers

A successful live backup is published as:

```
migr_backup_YYYYMMDD_HHMMSS[-N]/
```

While the backup is running, migr writes to the same name with a `.partial` suffix.
A failed or interrupted backup is never published as complete; a later invocation of
the same job can resume a matching usable partial. Restore refuses `.partial`
containers. If multiple backups begin in the same second, `-1`, `-2`, and so on keep
their names distinct without replacing an existing backup.

The container root is reserved for migr-owned control files. Everything selected from
the user's filesystem lives below `data/`:

```
migr_backup_YYYYMMDD_HHMMSS[-N]/
├── manifest.txt
├── packages.txt        # present when this scope exports a package list
└── data/
    └── <logical roots>
```

`manifest.txt` records the version, representation, scope, root table, and stable source
identity when one is available. Older unversioned and manifest-less backups remain
readable through an isolated legacy restore path.

Explicit paths keep accepting valid sources both inside and outside `$HOME`. A root
proven to be inside the source home is restored automatically to the same relative
location below the target home. An external root is still captured on a native
destination, under `data/EXPLICIT_n`, but restore only reports its recorded source and
backup location; it does not guess where to write it.

The backup destination must resolve outside every selected root, including through
symlinks. Otherwise migr refuses the entire invocation before creating anything, so a
backup can never recurse into and consume its own output.

Before a live backup creates a container, migr probes the destination filesystem.
Portable capture is not implemented yet, so a destination that cannot faithfully hold
the required Linux semantics is refused rather than used with silent metadata loss.
External explicit roots also remain ineligible for future portable capture until they
have a faithful restore-address policy.

## Core Metadata Fidelity

Native backup and restore preserve the exact numeric ownership (uid/gid), permission
mode, and atime/mtime timestamps for regular files, directories, FIFOs, and symlinks.
Ownership is recorded truthfully and applied best-effort: a non-root user who cannot
`chown` sees a warning per entry, never a silent normalization, and any metadata
read-back mismatch after a reported success aborts the operation (a filesystem that
lies is refused). Restored directories and symlinks receive the exact saved atime;
the source symlink's own atime cannot be preserved across restore because Linux
`readlinkat()` perturbs it with no suppression flag — a documented kernel limitation,
not a silent degradation.

Destinations that cannot faithfully hold these semantics are detected by an
on-disk capability probe before anything is written: a filesystem that loses
metadata (for example exFAT/NTFS/FAT32) is refused for capture, not silently
degraded. Portable capture to such filesystems (with a sidecar state log preserving
the true metadata) is implemented behind a test-only seam but is not yet wired into
the public CLI; it will become available only after the remaining safety phases
(see [docs/sidecar-plan.md](docs/sidecar-plan.md)). Until then the probe refusal is
the production behaviour — a failed backup is safer than a silent metadata loss.

## Report

Running `migr` or `migr report` scans your home directory and shows sizes for main directories, dotfiles, dev tools, and browsers — plus a critical backup size estimate.

## Under the Hood

This tool was fully refactored to eliminate all shell-based execution. It no longer calls `system()` or `popen()` anywhere in the codebase — functions that silently pass strings to `/bin/sh` and are a well-known vector for shell injection vulnerabilities.

In their place, a custom pure C POSIX engine handles all I/O and process execution:

- **`backup_capture_at()` / `restore_native_at()`** — separate backup and restore walkers. Backup reads a pathname-based source into a directory-fd-anchored payload destination; restore anchors both payload and destination traversal to directory file descriptors. Both preserve permissions and timestamps, reproduce symlinks and FIFOs, and skip sockets and device nodes with a warning. Replaces `cp -r`.
- **`get_dir_size()`** — recursive directory size calculation via `lstat` and `dirent`. Replaces `du`.
- **`run_command()`** — shell-free subprocess execution via `fork`/`execvp`/`waitpid`. Replaces `system()`.
- **`run_command_capture()`** — same as above, with stdout captured into a buffer via an anonymous `pipe`. Replaces `popen()`.

Package listing and restoration commands (`apt-mark`, `dnf`, `pacman`, `apt-get`) are launched directly as process arguments — no shell is ever spawned. Size reporting uses native `off_t` arithmetic throughout for correct behaviour on both 32-bit (LFS) and 64-bit architectures.

## Design Decisions

Why things are the way they are — including what was rejected, and why — is
recorded in [docs/DECISIONS.md](docs/DECISIONS.md).

## Planned

- [x] Dry-run mode
- [x] Pure C refactor
- [x] Comprehensive vs. critical-only backup modes
- [x] Localization (xdg-user-dirs support)
- [x] Cross-locale restore mapping (manifest system)
- [x] Resumable versioned backup containers
- [ ] Backups to filesystems that cannot hold Linux metadata (exFAT/NTFS/FAT32)
- [ ] VS Code extension list backup and restore
- [ ] Logging
- [ ] Network configuration backup
- [ ] Self-contained backup (embed static binary)
- [ ] Provide pre-built .deb, .rpm, and AUR packages

## License

MIT

# migr

A CLI tool for migrating between Linux distributions. Detects your distro, backs up critical directories and dotfiles, exports your package list, and restores everything on the new system.

Built out of necessity — I was moving from Ubuntu to Fedora, stressing over browser configs, SSH keys, and dotfiles. This automates what I was doing by hand.

Originally written in one day for an Intro to CS final project.

## Supported Distributions

- Debian / Ubuntu / Mint
- Fedora / RHEL / CentOS
- Arch / Manjaro / EndeavourOS

## Build

```bash
make
```

## Usage

```bash
migr                        # show backup analysis report
migr -report                # same as above
migr -backup <PATH>         # copy critical files to PATH
migr -packages [PATH]       # list installed packages (optionally save to file)
migr -restore <SOURCE>      # restore files and packages from a backup
migr -help                  # show help
migr -v ...                 # verbose mode (combine with any flag)
```

## What Gets Backed Up

**Directories:** Documents, Desktop, Projects

**Dotfiles:** .ssh, .gnupg, .gitconfig, .bashrc, .profile

**Packages:** Full package list via dpkg/rpm/pacman (saved as packages.txt, reinstalled on restore)

## Report

Running `migr` or `migr -report` scans your home directory and shows sizes for main directories, dotfiles, dev tools, and browsers — plus a critical backup size estimate.

## Planned

- Compressed backups
- Dry-run mode
- Rollback support
- Granular backup selection (interactive per-directory prompts)
- Comprehensive vs. critical-only backup modes
- Cloud storage support
- Packaging for DNF / APT / Pacman
- Shell injection hardening

## License

MIT

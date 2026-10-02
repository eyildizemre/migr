# migr

migr moves your home folder, packages, and desktop settings from one Linux
installation to another, across distributions too: back up to a drive,
reinstall, restore.

It is not released yet: there are no packages, so build it from source.

## Why migr

- **More than files.** Besides your folders and dotfiles, it brings back the
  packages you installed, system-wide Flatpak applications, your group
  memberships, GNOME settings, and, if you ask, your network connections. What
  the new system cannot take is listed with the command to run, never dropped
  silently.
- **Any drive.** On ext4, btrfs, or xfs a backup is a plain folder you can copy
  back with `cp -a`. On exFAT, FAT32, or NTFS, which cannot store Linux owners,
  permissions, or extended attributes, migr keeps them in a journal beside your
  files and restores them exactly.
- **Safe on a running desktop.** A file that changes while it is read is read
  again, and on btrfs the backup reads a read-only snapshot; elsewhere, open
  applications' settings are backed up last. Restore closes the desktop and
  continues on a text screen, so no running program writes over what it brings
  back.
- **Resumable and updatable.** An interrupted backup continues where it
  stopped. Backing up to the same drive again updates the backup and copies
  only what changed.
- **Checked before you wipe.** For a backup on exFAT, FAT32, or NTFS,
  `migr verify` confirms that every file on the drive still matches what was
  captured, and restore reads back every file it wrote.

## Build

```bash
make
```

This needs a C compiler and `make`. Run migr from the source folder as
`./migr`. Pre-built .deb, .rpm, and AUR packages are planned.

## Quick start

```bash
./migr report                                  # what a backup takes, and what it leaves out
./migr conf                                    # optional: add or exclude paths
sudo ./migr backup /mnt/usb                    # back up to the drive mounted at /mnt/usb
./migr verify /mnt/usb/migr-$USER              # check the backup before wiping this system
```

Then install the new distribution, create your user with the same password
you use now, log in, build migr, and plug the drive in:

```bash
sudo ./migr restore /mnt/usb/migr-$USER
```

`report`, `verify`, and every `--dry-run` preview run without root.

## What gets migrated

| What | Backed up | On restore |
|---|---|---|
| Your folders | Documents, Downloads, Pictures, Desktop, found by their localized names (`xdg-user-dirs`) | Restored into the new system's folders of the same kind, whatever they are called there |
| Settings and app data | `~/.config`, `~/.local/share`, `~/.local/state`, `~/.local/bin`, and Flatpak applications' data in `~/.var/app` without their caches | Restored; open applications are handled last (see [Restoring](#restoring)) |
| Shell and tools | `.ssh`, `.gnupg`, `.gitconfig`, bash and zsh startup and history files, `.inputrc`, `.tmux.conf`, `.screenrc` | Restored |
| Browsers | Firefox, Chrome, Chromium, Brave, Vivaldi, Edge, Opera | Restored |
| VS Code, VSCodium | `~/.vscode` and `~/.vscode-oss`, with installed extensions | Restored as files |
| GNOME settings | the dconf database | Loaded into your session when you are logged in; otherwise in place for your next login |
| Packages | the packages you installed yourself, not their dependencies | Installed in one transaction; the ones the new system cannot install are listed |
| Flatpak applications | the system-wide installation's applications and their remotes | Installed from the remotes the new system has; the others are listed |
| Groups | groups you were added to, such as `libvirt`, `docker`, or `dialout` | You are added back to the ones the new system has; the others are listed |
| Network (opt-in) | NetworkManager, netplan, systemd-networkd, wpa_supplicant, and netctl configuration, and the system crypto policy | Written back; NetworkManager reloads it and the crypto policy is set, the others are left for you to apply |

That is the default scope, `--critical`. `--comprehensive` adds Videos and
Music. Listing paths after the destination (`sudo ./migr backup /mnt/usb
~/Documents ~/Projects`) backs up exactly those paths and nothing else: no
package, Flatpak, or group lists.

`migr report` shows the scope, its size, and the largest folders it leaves out:

```text
$ ./migr report
Backup Analysis · Fedora/RHEL
/home/eyildizemre

Main Directories
  Desktop                                0B
  Documents                            2.3M
  Downloads                            1.4M
  Pictures                             4.3M

Dotfiles & Config
  .bash_history                         27B
  .bash_logout                          18B
  .bash_profile                        144B
  .bashrc                              522B
  .config                              133B
  .gitconfig                            20B
  .local/bin                            31B
  .local/share                           0B
  .ssh                                  65B

  Critical estimate                    8.0M

Not included (add a path with `migr conf` to back it up):
  Games                        2.9M
```

`-v` adds each item's path and the folders under it, `--max-depth=N` limits
how deep that goes, and `-s` prints only the total.

### Changing the scope

`migr conf` opens `~/.config/migr/migr.conf` (under `$XDG_CONFIG_HOME` when
that is set) in your `$EDITOR`. The file has include and exclude sections for
`critical` and `comprehensive`. Paths are relative to your home unless
absolute; `critical` includes also apply to `comprehensive`, and an exclusion
wins over an include. `report` and `backup` read it every time; restore follows
the scope recorded in the backup instead.

## Backing up

`backup` runs as root so it can read everything in your home and keep every
owner. Under `sudo` it still backs up your home, not root's, and the
backup belongs to you: you can look at it, preview a restore from it, and
delete it without `sudo`.

```text
$ sudo ./migr backup /mnt/usb
Estimated backup size: 8.0M
Destination free space: 4.0G

Not included (add a path with `migr conf` to back it up):
  Games                        2.9M

This backup includes 1 item(s) that can carry secrets typed at a shell prompt (.bash_history). Make sure the destination is trustworthy before continuing. Continue? [Y/n]: y
Backing up /home from a read-only snapshot.
Backing up to: /mnt/usb/migr-eyildizemre.partial

Packages
Saved 362 packages to packages.txt

VS Code Extensions
  Note: no VS Code extension list was captured for this backup.

Groups
Saved 0 group memberships to groups.txt

Flatpak Applications
  Note: no system-wide Flatpak applications were found.

Finalizing (syncing to disk)...
Location: /mnt/usb/migr-eyildizemre
  OK: Backup complete: 31 items copied
```

**Before anything is written**, migr checks that the backup fits on the drive
and that the drive is not inside what it backs up. Shell history files can hold
passwords typed at a prompt, so it asks before taking them; `.ssh`, `.gnupg`,
and network configuration hold secrets too, so keep the drive somewhere safe.

**While you keep working.** A file written while it is read is read again; one
still changing after three reads is kept as last read. Files removed before
they were read, or created after their folder was scanned, are left out. The
backup still completes, lists what changed, and exits with status 1. Desktop
state that changes all the time, such as GNOME's file metadata, is only counted.
On btrfs, Fedora's default, migr reads from a read-only snapshot instead, so
nothing changes under it at all; the snapshot is removed when the backup ends.
Without a snapshot, the folders that hold an open application's settings (VS
Code, the common browsers, Flatpak applications) are backed up last: files
such as a browser's history database and its journal belong together, and
read minutes apart they may not match. If the application is still open then,
migr asks you to close it and press Enter, or to back them up as they are.

**Where it goes.** The backup is a folder named after you, `migr-<user>`. If
that name already holds another installation's backup (another computer, or
this one before a reinstall), migr asks whether to update it from this system,
so one backup can follow you from one distribution to the next. The default
is no: the new backup is named after the day, `migr-<user>-YYYY-MM-DD`, and
the old one is left alone. With more than one such backup, migr does not ask.

**Interrupted and repeated backups.** While running, the backup is called
`migr-<user>.partial`; run the same command again to continue it. Backing up
again to the same place updates the backup in place: unchanged files are
skipped, changed ones copied again, and files you deleted leave the backup. A
file whose permissions, owner, access time, or extended attributes changed but
whose content did not is not copied again; only its record is.
During an update it is called `migr-<user>.updating`, so an interrupted update
is never mistaken for a finished backup.

**Linux or non-Linux drives.** On a drive that can hold Linux metadata (ext4,
btrfs, xfs) the backup is a plain copy of your files. On exFAT, FAT32, or NTFS,
file names are encoded so the drive accepts them, and the true names, owners,
permissions, times, and extended attributes are kept in a journal next to them.
migr picks the form by testing the drive; there is no option.

**Options.**
- `--include-network-config` also backs up NetworkManager, netplan,
  systemd-networkd, wpa_supplicant, and netctl configuration, and the system
  crypto policy. These files can hold Wi-Fi passwords and VPN keys in plain
  text. With them, a restored system connects to your saved networks before
  packages install, without you typing a password.
- `--include-self` puts a static migr binary in the backup, so the new system
  can run migr before building it. Build it first with `make migr-static`,
  which needs a static C library (`glibc-static` on Fedora). FAT and exFAT
  drives may not let it run in place; copy it to your home first
  (`cp migr ~/migr && chmod +x ~/migr`).
- `--dry-run` shows what would be backed up and writes nothing.

## Checking a backup

Run `migr verify` before you wipe the old system. It reads every file in the
backup and compares it with what was captured, without restoring anything:

```text
$ ./migr verify /mnt/usb/migr-eyildizemre
Backup taken 2026-09-27 22:48
Verifying 31 items (8.0M) in /mnt/usb/migr-eyildizemre
  OK: Backup verified: all 31 items match what was captured
```

A file that went missing or changed is listed, and verify exits with status 1.
It checks backups on exFAT, FAT32, and NTFS drives, which record what they
captured; a backup on a Linux filesystem is a plain copy with no such record,
and verify refuses it.

If the journal of such a backup is damaged, for example by a failing drive,
restore refuses it. `migr repair <SOURCE> <PATH>` then rebuilds it as a new
backup under `PATH` without touching the original: damaged records are
skipped, a folder whose own record was lost gets the settings of the folder
above it, and everything that cannot be recovered is listed. The files are
copied too, so `PATH` needs room for the whole backup, and it cannot be the
folder holding the damaged one. Run `migr verify` on the copy before
restoring from it.

## Restoring

Restore runs as root, like backup, and restores into your home, not root's.
It is meant for a freshly installed system: it replaces files the new system
already has at the same paths (a new install's default `.bashrc`, for example)
with your backed-up ones; a symlink in the way is refused and named.

Before writing anything, restore checks the whole backup and the destination,
shows when the backup was taken and how much room it needs, and asks once.
Then it restores your files, writes the network configuration, installs
packages and Flatpak applications, and adds you back to your groups.

**Run from the desktop, restore continues on a text screen.** Desktops and
their applications keep writing their settings while you are logged in, and
again when you log out, after the restore. So when you start restore from a
terminal on the desktop, it closes the desktop, starts itself again on a text
screen, checks everything again, and restores there with nothing running in
your session:

```text
$ sudo ./migr restore /mnt/usb/migr-eyildizemre
Backup taken 2026-09-27 22:48
Estimated restore size: 8.0M
Destination free space: 90.2G
The restore runs on a text screen with the desktop closed; the login screen comes back when it ends.
This will restore files to your home directory. Continue? [y/N]: y
Continuing on a text screen.
```

On the text screen:

```text
Packages
Installing packages (this may take a while)...
...
  362 installed, 0 skipped.

Groups
  The backup saved no group memberships.

  OK: Restore complete: 31 items restored

Press Enter to return to the login screen.
```

Your first login then reads the restored settings. The login screen also comes
back if the restore fails. Over SSH, from a text console you logged in on, or
while another user is logged in to a desktop, restore runs where you started
it.

**Your files stay yours.** What belonged to you in the backup belongs to you
on the new system, even when it gives your account another user ID.

**SELinux labels come from the new system.** Where SELinux runs, restore gives
the restored files the labels its policy sets, as `restorecon` does. Backups
do not carry labels, so one set by hand with `chcon` is not kept.

**Open applications.** When restore runs while you are logged in to the
desktop, VS Code, the common browsers, and Flatpak applications may be open.
They rewrite their settings while they run or when they close, so their
settings are restored last. If one is still open then, restore asks you to close it and
press Enter, to skip its settings (run the same restore again later to put them
back), or to restore them anyway.

**Network before packages.** Packages and Flatpak applications are downloaded,
so restore first makes sure the system is online, by NetworkManager's own
check. If it is not, restore waits up to 90 seconds and shows which network
NetworkManager is connecting to, such as one from the restored network
configuration:

```text
Network
  Connecting to DormWifi...
  Connected to DormWifi.
```

Without a connection by then it installs nothing and lists the packages and
Flatpak applications at the end, with the commands to install them once you
are online. A Wi-Fi password kept only in your keyring is not in
the restored configuration, so that network connects only after you log in.

**GNOME settings** are loaded into the running session when you are logged in,
so the session does not overwrite them.

**Saved passwords and sign-ins** live in the login keyring, which opens with
your login password. Give your user on the new system the same password; with
a different one, the first app that needs the keyring asks for the old
password once, and without it the keyring cannot be opened. After a restore
in your desktop session brings the keyring back, log out and back in before
signing in anywhere: the running session cannot save to the restored keyring.
Backup and restore both remind you.

**From an exFAT, FAT32, or NTFS backup**, restore also leaves desktop state
that services rewrite all the time alone where the new system has already
written it, and restores it only where nothing is there yet.

**When your home path or folder names differ** on the new system, restore
rewrites them in GTK bookmarks and the recent files list, and it keeps the
new system's `~/.config/user-dirs.dirs`.

**What's left for you.** Restore ends with what it could not do: packages the
new system could not install, Flatpak applications it could not install, and
groups it does not have, each with the command to run. The same list is saved
next to the backup as `migr-<user>-todo.txt`, so nothing of migr is left in
your new home.

**Checking the result.** A restore from an exFAT, FAT32, or NTFS backup reads
back every file it wrote. A file that does not read back as it was captured
fails the restore (exit status 2); a file another program changed after restore
wrote it is listed separately and gives exit status 1. `--no-verify` skips this
read-back. `--dry-run` shows what would be restored and writes nothing.

## What migr does not do

- **System files.** Only your home is migrated, plus the network configuration
  you opt into. Other files under `/etc`, system services, and other users'
  homes are not.
- **Package names across families.** A package named differently on the new
  distribution is not translated; it is listed for you to install.
- **Unknown distributions.** Outside the Debian, Fedora, and Arch families
  (below), files are migrated but packages are not.
- **Snap** applications and their data.
- **Creating what is missing.** Groups the new system lacks are not created,
  and Flatpak remotes are not added, since adding one needs its signing key.
- **Custom locations.** `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, and
  `XDG_STATE_HOME` set elsewhere than their defaults, and zsh's `ZDOTDIR`, are
  not followed yet.
- **Paths outside your home.** Listed explicitly, they can be backed up only
  to a Linux filesystem, and restore does not put them back: it shows where
  they came from and where the backup holds them.

### Supported distributions

| Family | Package manager | Examples |
|---|---|---|
| Debian | `apt` | Debian, Ubuntu, Mint, Pop!_OS, elementary, Zorin |
| Fedora | `dnf` | Fedora, RHEL, CentOS, Nobara |
| Arch | `pacman` | Arch, Manjaro, EndeavourOS, Garuda |

Other derivatives are recognized through `ID_LIKE` in `/etc/os-release`.

## Reference

### Commands and options

```
report [SCOPE]        Show backup analysis report (default when no command given)
backup <PATH>         Create a resumable backup container under PATH
restore <SOURCE>      Restore files and packages from a backup at SOURCE
verify <SOURCE>       Check a portable backup against its capture record
repair <SOURCE> <PATH>
                      Rebuild a damaged portable backup as a new copy under PATH
conf                  Edit persistent critical/comprehensive selection rules
help                  Show this help

--critical            Personal content plus persistent user state (default)
--comprehensive       Everything --critical covers, plus Videos and Music
<PATH...>             Paths listed after the destination are backed up
                      exactly as given, with no assumptions

-n, --dry-run         Preview actions without making changes
-v, --verbose         Verbose output
-h, --help            Show this help
-s, --summary         Print only the selected report scope total
    --max-depth=<N>   Report directory breakdown depth (implies --verbose)
    --include-self    Include a validated static migr binary in the backup
                      (requires building migr-static)
    --include-network-config
                      Back up NetworkManager, netplan,
                      systemd-networkd, wpa_supplicant, and
                      netctl configuration found on this system
    --no-verify       Skip post-copy content verification (restore only)
```

### Exit status

As with GNU tar:

| Status | Meaning |
|--------|---------|
| 0 | Completed as asked (or cancelled at the confirmation). |
| 1 | Completed, but something changed or differs, and the run lists it: files that changed while a backup read them, restored items another program changed afterwards, or items `verify` found different from their capture. |
| 2 | Failed or refused, including a wrong command line. |

### Logs

A backup or restore that ends with status 1 or 2 keeps a log of the run:
everything it printed, without colors, plus the full lists the terminal only
shows examples of. The last line of the run names it.

- **Backup:** inside the backup, `logs/backup-YYYY-MM-DD-HHMMSS.log`, so it
  travels with the backup when the old system is reinstalled.
- **Restore:** `~/.local/state/migr/restore-YYYY-MM-DD-HHMMSS.log` on the new
  system.

A run that ends with status 0 keeps no log. The newest 10 logs in each place
are kept. Reports, dry runs, and `verify` keep none.

## Backup format

```
migr-<user>/
├── manifest.txt           # what was backed up, from where, and how
├── sidecar.migr           # journal of names and metadata (exFAT, FAT32, NTFS only)
├── packages.txt           # packages you installed
├── groups.txt             # your group memberships
├── flatpak-apps.txt       # system-wide Flatpak applications and their remotes
├── vs-code-extensions.txt # `code --list-extensions`, when VS Code is installed
├── network/               # with --include-network-config
├── migr                   # with --include-self
├── logs/                  # logs of backups that ended with status 1 or 2
└── data/                  # your files
    ├── Documents/         # your own folders, named as in your home
    ├── Pictures/
    └── settings/          # everything else: config, ssh, bashrc, firefox, ...
```

`data/` holds one folder per backed-up item, and `manifest.txt` records where
each came from. Your own folders keep their names, localized ones included
(`Belgeler` on a Turkish system); hidden items such as `~/.config` or
`~/.ssh` go in `settings/` without their leading dot. Two items with the same
name get `-2`, `-3`, and so on. On a Linux filesystem each is a plain copy with its owners, permissions, times, extended
attributes, and hardlinks, which you can copy back without migr (`cp -a`). On
exFAT, FAT32, or NTFS, names are percent-encoded where the drive would reject
them and the files carry no Linux metadata; `sidecar.migr` holds the true names
and metadata, so restore such a backup with migr. The list files are plain
text, one entry per line.

## Development

```bash
make test             # the test suite
sudo make test        # also runs the phases that need root
make check-strict     # gcc and clang with -Wpedantic -Werror
make check-sanitize   # AddressSanitizer and UndefinedBehaviorSanitizer
```

`git config core.hooksPath hooks` enables a pre-commit hook that builds and
runs the tests when C, shell, or Makefile changes are staged.

Why things are the way they are, including what was rejected and why, is
recorded in [docs/DECISIONS.md](docs/DECISIONS.md).

## License

MIT

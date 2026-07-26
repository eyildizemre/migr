# Decisions

Design decisions and the reasoning behind them, numbered upward from D1 in
chronological order.

The point of this file is not to record *what* was decided — the code shows that.
It is to record *why*, and what was rejected, so neither gets re-litigated later.

**Rules:**

- Numbers are append-only. They are never reused, reshuffled, or retired. A decision
  that is later reversed keeps its number; the reversal is a new entry that names
  what it supersedes. Removing reversed decisions would hide exactly the reasoning
  that makes the rest trustworthy.
- Code comments cite entries as `docs/DECISIONS.md D9`.
- Every entry carries a **Status**. `Implemented` means the code does this today.
  `Decided` means the reasoning is settled but nothing is built yet — those entries
  must not be read as descriptions of current behaviour.

---

## D1 — 2026-06-27 — Unresolvable packages are written to `skipped-packages.txt`

**Status:** Implemented

**Decision:** Packages that fail to install on restore are written to
`$HOME/skipped-packages.txt`, with a `N installed, N skipped` summary.

**Why:** The thorough solution — cross-distro package name mapping via a
Repology-like database — is a large amount of work with an unbounded maintenance
burden. Writing the failures to a file solves the actual problem (knowing what did
not make it across) at a fraction of the cost.

**Rejected:** cross-distro package name translation. Revisit only if the tool
outgrows solo maintenance.

---

## D2 — 2026-06-27 — Batch package install first, per-package fallback on failure

**Status:** Implemented

**Decision:** Build one `argv[]` containing every package and run a single install
command. Only if that exits non-zero, fall back to installing one package at a time,
recording failures per D1.

**Why:** A single transaction — one repository metadata load, one package-manager
lock, one dependency resolution pass. Per-package installs repeat all three for
every package.

**Note:** The original driver was avoiding ~2500 `fork`/`exec` calls from full
package lists. D12 later shrank exports to the explicitly-installed set (hundreds
at most), so that dramatic count is history; the single-transaction argument is why
batch remains the right default regardless of count.

**Debian detail:** the batch command includes `-m` (`--ignore-missing`) so a single
unavailable package does not abort the entire transaction.

---

## D3 — 2026-06-27 — No generic application installer

**Status:** Implemented — by omission

**Decision:** `migr` does not gain an `[Applications]` category that installs
Spotify, Brave, Steam, and similar third-party software.

**Why:** Unix philosophy — the tool migrates a user environment. A curated list of
third-party applications is unbounded scope with no natural stopping point, and
every entry is a maintenance liability tracking someone else's install method.

**Boundary case worth knowing:** packages from third-party repositories — e.g.
`brave-browser`, which lives in Brave's own repo for both apt and dnf — fail on a
fresh target system until the user re-adds that repo, and land in
`skipped-packages.txt`. Automating third-party repository setup is exactly the
application-installer territory this decision rejects.

**Note:** browsers are already covered where it matters, because `migr` clones
browser *configuration*. The user installs the browser; `migr` restores the profile.
That split is the correct one and generalizes.

---

## D4 — 2026-06-27 — VS Code extension backup is in scope; other editors are not, yet

**Status:** Decided — postponed, not yet implemented

**Decision:** `migr` backs up the VS Code extension list (`code --list-extensions`)
and replays it on restore. No other editor gets dedicated support initially.

**Why VS Code specifically:** its extension list is the rare case that is *not*
recoverable from configuration files — extensions live as installed blobs, so
listing them needs the CLI. Most editors need nothing special at all: vim/neovim
and emacs declare their plugins in config files that the dotfile backup (and the
planned conf `include` mechanism) already carries.

**Why not more editors in-tree:** only what can be tested gets shipped — the same
principle as the target-distribution table. Editors the maintainer cannot verify
would be claimed support, not real support.

**Contributions are welcome, not expected.** The door is open for other editors via
PR, and `CONTRIBUTING.md` will document the VS Code implementation as the reference
pattern. No expectation of community involvement is implied by any of this.

---

## D5 — 2026-07-19 — Cloud sync is shelved

**Status:** Implemented — removed from the README roadmap

**Decision:** Cloud storage support is off the roadmap for now.

**Why:** The feature's goal was a backup that reaches cloud storage without leaving
the keyboard. The single first-hand attempt at such a flow — uploading a
GPG-encrypted tar archive of a full backup — ran into transfer difficulties and was
eventually completed by hand, through a browser. One attempt on one machine is not
an experience base to design a backup feature on.

**Recorded for any future revisit:** cloud support without built-in encryption is
incomplete. The manual flow required GPG-encrypting the archive before upload; a
tool-integrated flow must do the equivalent itself rather than leave it to the user.

**Revisit if:** the need returns and the full flow can first be validated at
tens-of-GB scale, with encryption built in. `rclone` is the obvious candidate to
evaluate for the transfer layer.

---

## D6 — 2026-07-19 — Backups are plain file trees; a sidecar carries what the filesystem cannot

**Status:** Decided — not yet implemented

**Decision:** The primary on-disk representation of a backup is a plain file tree.
On destination filesystems that cannot represent Linux file semantics
(exFAT/NTFS/FAT32), file contents stay in the tree and everything the filesystem
cannot hold goes into a sidecar file; restore reconstructs from both.

**Why a file tree:** the user must be able to see and reach every backed-up file
directly — open the drive in a file manager, copy one document out by hand, verify
with their own eyes that the backup holds what they think it holds. An archive
cannot offer this cheaply: tar has no central index, so merely *listing* its
contents means scanning the entire archive, over what is typically the slowest link
in the chain (USB media).

**Why the sidecar:** it is what makes the tree representation faithful on lossy
filesystems. Without it, cloning silently loses everything in this table:

| Problem | Handling |
|---|---|
| Permissions, uid/gid, timestamps | Sidecar fields, replayed on restore |
| xattrs / ACLs | `getxattr` → sidecar → `setxattr` (see D7) |
| Symlinks | Stored as a regular file holding the target path, `type=symlink` in sidecar |
| Hardlinks | Track `(st_dev, st_ino)`; later occurrences recorded as `type=hardlink` |
| Illegal filenames (`: * ? " < > \|`) | Percent-encoded on destination, true name in sidecar |
| Case collisions | Same encoding plus a disambiguating suffix |
| Sparse files | `SEEK_HOLE`/`SEEK_DATA` extent map stored alongside data extents |

**Side benefit — resume:** the sidecar records true source size+mtime, which is a
more reliable resume oracle than the destination's degraded metadata (exFAT
timestamps have 2-second granularity, causing false mismatches and needless
re-copies). An archive, by contrast, cannot practically be continued after an
interruption.

**tar is not rejected — it is not the default.** An opt-in archive mode (`--tar`,
possibly `--tar-and-gpg`, which would pair with D5's encryption requirement) remains
a plausible future feature. This decision only fixes the default representation.

**Format:** NUL-separated records, append-only. NUL because a filename may legally
contain commas and newlines but never `\0` — this is why CSV was rejected.
Append-only so an interrupted backup resumes by replaying what was recorded.

---

## D7 — 2026-07-19 — Nothing distro-specific enters the codebase

**Status:** Standing principle. The generic xattr mechanism it prescribes is part of
the sidecar work (D6) and not yet implemented.

**Decision:** `migr` contains no code path that exists for one distribution's
benefit. A distro-hopping tool with distro assumptions contradicts its own purpose.

**Worked example — SELinux contexts:** `restorecon -R ~` would be the cheap way to
repair them after a restore, and it was rejected on exactly this principle:
`restorecon` is an SELinux-only utility, which makes it Fedora/RHEL-specific.
Instead, extended attributes are read generically with `getxattr`, stored in the
sidecar, and replayed with `setxattr`. The code never asks which security framework
is running — files without a given attribute return `ENODATA` and are skipped, so
the same code is correct on SELinux systems, AppArmor systems, and systems with
neither.

---

## D8 — 2026-07-19 — Document that ext4/btrfs destinations need none of this

**Status:** Decided — not yet written into README

**Decision:** README should state that formatting the backup drive as ext4 or btrfs
gives full fidelity with no encoding and no sidecar.

**Why:**

1. It is the fast path — the backup is a plain, browsable mirror.
2. It prevents false bug reports — a user who sees `meeting%3Anotes.txt` on their
   exFAT drive will otherwise conclude the file was corrupted.
3. **Exit rights.** A backup must never depend on any single tool — including this
   one — to be readable. On a POSIX filesystem the backup can be recovered with
   `cp -a` on any Linux system, no `migr` required. This is not a hedge against
   `migr`'s quality; it is a property good backups have by definition. D9's
   embedded static binary covers the complementary case, where `migr` itself
   travels with the backup.

---

## D9 — 2026-07-19 — `--include-self` ships a separate static binary

**Status:** Decided — not yet implemented

**Decision:** Packaging produces two binaries: the dynamically-linked
`/usr/bin/migr` for daily use, and a static build shipped inside the same package
as a data file. `--include-self` copies the static one into the backup.

**Why the running binary cannot be used:** `/proc/self/exe` is the
dynamically-linked daily binary; on a fresh system without the shared libraries it
fails precisely when it is needed. And static-versus-dynamic is fixed at link time —
no runtime mechanism can turn a running dynamic binary into a static one.

**Why the daily binary stays dynamic:** shared-library security updates. A static
`/usr/bin/migr` would freeze its libc: every glibc CVE would remain open until the
package is rebuilt, where a dynamic binary is healed by the system update alone.
Distribution packaging conventions expect dynamic linking for the same reason. The
cost of shipping both is a few hundred kilobytes.

**Known caveats:**

- Static glibc breaks NSS functions (`getpwnam`, `getpwuid`). Not currently an
  issue — only `getenv("HOME")` is used. An NSS fallback would require building the
  static binary with musl instead.
- The exec bit is lost on FAT/NTFS destinations, so restore instructions must
  include `chmod +x migr`. Not fixable from inside the tool.
- The manifest must record the architecture, so an x86_64 binary restored on ARM
  fails with an explanation rather than `cannot execute binary file`.

---

## D10 — 2026-07-20 — Subcommand CLI, clean break from flag syntax

**Status:** Implemented

**Decision:** `migr backup <PATH>` replaces `migr -backup <PATH>`. The old
single-dash syntax is removed entirely, not kept as a deprecated alias.

**Why:** Matches the `git`/`docker`/`cargo` convention users already expect. It also
removes two workarounds that existed only to make commands-as-flags behave: the
manual `argv[optind]` peek for `-packages`, and the hand-rolled loop collecting
`-paths` arguments. GNU getopt's argv permutation handles both for free once
commands are words.

**Why a clean break:** No distro has packaged `migr` yet, so the installed base is
small enough that a compatibility layer would cost more than it saves. Doing this
*after* packaging would mean maintaining two parse paths forever. Interface changes
are cheapest before distribution, not after.

---

## D11 — 2026-07-20 — Backup scope is inferred from positional count, not a `--paths` flag

**Status:** Implemented

**Decision:** `migr backup <DEST> [PATH...]`. If extra positionals follow the
destination, that is explicit-paths mode. No `--paths` flag.

**Why:** The positional count already determines the mode without ambiguity:

```
migr backup /mnt/drive                     → 1 positional  → critical (default)
migr backup /mnt/drive ~/Documents         → 2 positionals → explicit-paths mode
migr backup /mnt/drive --comprehensive     → 1 positional  → comprehensive
```

Requiring a flag to announce "multiple arguments follow" is not a convention
established tools follow — `cp SRC... DEST`, `rsync src1 src2 dest/`,
`git add f1 f2`, `tar -cf archive f1 f2` are all variadic without one.

**Consequence:** Combining `--critical`/`--comprehensive` with explicit paths is
contradictory and is rejected with an error rather than silently resolved. The two
scope flags also reject each other, instead of the last one silently winning.

---

## D12 — 2026-07-23 — Only explicitly-installed packages are exported

**Status:** Implemented — verified on real systems: Fedora (host), Ubuntu and Arch (VMs)

**Decision:** Package export lists only explicitly-installed packages, one bare
name per line, identically on every distribution:

```
Debian  apt-mark showmanual
Fedora  dnf repoquery --userinstalled --qf '%{name}\n'
Arch    pacman -Qeq
```

**Why:** Full package lists (`dpkg --get-selections`, `rpm -qa`) include every
transitive dependency — 2457 packages versus 432 on the same Fedora 44 workstation.
That dependency bulk is where cross-distro name mismatch is worst (`lib*`,
`*-devel`, `python3-*`), and reinstalling it is unnecessary anyway: the target
package manager resolves dependencies itself. The explicit set is small and made of
top-level names that agree far better across distributions, which is what makes
package restore worth attempting at all. Measured explicit sets: Fedora
workstation 432, fresh Ubuntu desktop 35, minimal Arch 12.

**Consequence for D2:** batch installs now handle hundreds of names, not thousands;
the single-transaction rationale carries the decision from here on.

**Implementation records:**

- dnf's queryformat requires the two-character escape `\n`; a literal newline byte
  is copied through uninterpreted and collapses the entire output into one record.
  In C source the format literal is therefore `"%{name}\\n"`.
- Package export works offline on all three families, verified with networking
  disabled (`nmcli networking off`, DNS resolution confirmed dead first): `apt-mark
  showmanual` and `pacman -Qeq` produced their full lists on the Ubuntu and Arch
  VMs, and `dnf repoquery --userinstalled` gives identical output with
  `--cacheonly` (~0.2 s) on the Fedora host.
- Restore keeps the dpkg tab-status filter for backups made before this change:
  their `pkg\tstatus` format contains `deinstall` entries, and dropping the filter
  would reinstall packages the user had deliberately removed.
- `test_packages` asserts the format contract — line count, no whitespace within a
  line, no blank lines, no run-together records, architecture suffixes below a
  proportion threshold (an outright ban is impossible: `kmod-nvidia` on Fedora
  genuinely embeds kernel version and arch in its package *name*).

---

## D13 — 2026-07-26 — Sparse-file support is deferred out of the sidecar

**Status:** Decided — deferred

**Decision:** The sidecar (D6) will not preserve file sparseness in its initial
implementation. A sparse file is backed up and restored as a full, non-sparse file of
the same visible size and contents; only the on-disk hole structure is lost.

**Why:** Of every dimension the sidecar handles, sparse files are the lowest value and
the highest complexity. They are rare in a home directory — the main producers are VM
disk images and similar, which are large enough that users typically exclude them
anyway. Preserving sparseness needs `SEEK_HOLE`/`SEEK_DATA` extent mapping on backup
and `ftruncate` + positioned `pwrite` on restore, a materially more involved code path
than any other dimension. The cost/value ratio does not justify carrying it in the
first version.

**Consequence:** restoring a sparse file inflates it to its full allocated size on
disk. For the rare large sparse file this can be a surprising space cost, which is the
main reason to revisit.

**Revisit if:** sparse files turn out to matter in practice, or once the higher-value
dimensions (metadata, symlinks, filenames, xattrs) are complete and stable.

See docs/sidecar-plan.md for the full implementation plan.

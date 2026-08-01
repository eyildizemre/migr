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

---

## D14 — 2026-07-27 — Backup representation is selected empirically, without a production override

**Status:** Implemented

**Decision:** Before a live backup creates its dated container, `fsprobe()` measures the
destination filesystem and produces a per-capability profile, and a separate pure
`select_representation()` reduces that profile with fail-closed precedence:

- all required capabilities supported → native representation;
- any capability unavailable, with no operational error → portable representation;
- any operational error or invalid result → refuse the backup.

The production CLI, environment, and configuration cannot force a representation or
replace the measured profile. Until portable capture exists, a portable verdict is
refused before the container is created — a temporary implementation boundary, not a
rejection of lossy filesystems.

**Why:** A false native verdict silently loses the exact metadata the sidecar exists to
protect, so a user-facing force-native path would turn a safety check into an opt-out
from data integrity. For the same reason an unexpected probe failure is refused, not
read as "portable": it could equally mean a full, read-only, or damaged destination.

Keeping measurement (`fsprobe`) separate from policy (`select_representation`) makes both
reviewable — the selector's whole native/portable/refuse matrix is deterministic under
synthetic profiles, so no production override is needed to test it, while mounted
filesystems validate that the probe observes reality. That covers the selector, not
portable orchestration; when that pipeline exists, a narrowly scoped test-only seam may
drive it on a native development filesystem, but it must not be reachable through a
release binary, CLI, environment, or configuration, and never replaces real
exFAT/NTFS/vfat tests.

**Rejected:** filesystem-name allowlists in place of empirical checks; production
force-native/force-portable controls; treating an operational probe failure as a request
for portable mode.

**Revisit if:** a real user workflow requires portable representation on a filesystem
that passed the native profile — a product decision with its own safety contract, not a
testing shortcut.

**Relationship:** Refines D6 by defining how migr chooses its native or portable
representation.

---

## D15 — 2026-07-28 — Versioned backup containers isolate payload and finalize atomically

**Status:** Implemented — container namespace and lifecycle

**Decision:** A versioned backup container reserves its root for migr-owned control
artifacts (`manifest.txt`, `packages.txt`, `sidecar.migr`, and the shipped binary when
requested). Every user-derived filesystem object lives below `data/`.

A live backup writes to:

```
migr_backup_YYYYMMDD_HHMMSS[-N].partial/
```

Candidate allocation considers both partial and final names and atomically claims a
unique partial directory. Success atomically renames it to the same name without
`.partial`; finalization must never replace an existing final container. A failed or
interrupted backup therefore cannot look complete.

The versioned manifest records the representation, normalized logical-root set, and a
stable source identity for resume matching. The source identity is the machine id plus
numeric uid when both are available; an invocation that cannot establish identity does
not adopt an existing partial. A timestamp or scope label alone never proves that two
invocations are the same job.

**Why:** A payload named `manifest.txt` must not overwrite format state, and a second
backup in the same second must not merge with either an in-progress or completed
container. The `data/` boundary makes ownership visible instead of maintaining an
ever-growing reserved-name list. Partial-to-final publication gives completion a single
observable boundary while preserving interrupted work for resume.

**Rejected:** flat control and payload names; reserved-name pre-scan; date-only
containers; check-then-rename finalization that can replace a concurrent result; UUIDs
in user-facing container names.

**Relationship:** Supports D6's resume contract and follows D14's requirement that
representation be selected before the container is created.

---

## D16 — 2026-07-28 — Explicit roots keep arbitrary capture, with bounded restore policies

**Status:** Implemented

**Decision:** `migr backup <DEST> <PATH...>` continues to accept valid filesystem paths
both inside and outside the source `$HOME`; being outside `$HOME` is not itself an
error. Each root receives an ordinal identity (`EXPLICIT_0`, `EXPLICIT_1`, …), a
separate payload location below `data/`, and one manifest restore policy:

- **`HOME_RELATIVE`:** when component-aware resolution proves that the selected object
  is below the source `$HOME`, the manifest records its normalized home-relative path
  and restore recreates it at the same relative address below the target `$HOME`.
- **`MANUAL_NATIVE`:** every other valid root is captured on a native destination and
  remains directly accessible in its `data/EXPLICIT_n` tree, but automatic restore does
  not choose a destination for it. Restore must list every such root and its recorded
  source path rather than silently ignoring it.

Classification is not a string-prefix check. A selected symlink is the object being
backed up and is not followed merely to classify it; ancestor traversal must not make an
external object appear home-relative. All roots are validated before container creation.
A missing, invalid, duplicate, or overlapping root rejects the whole invocation rather
than silently producing less than the user requested. Existing unversioned explicit
backups have no trustworthy root mapping and remain legacy/manual; restore does not
guess.

`MANUAL_NATIVE` is also a representation gate: portable capture must refuse an
invocation containing such a root before writing payload until a faithful external-root
restore policy exists. This is currently automatic because all portable capture is
unimplemented and refused; later portable work must preserve the narrower gate rather
than creating an encoded tree that migr cannot replay.

**Why:** Explicit mode exists precisely to make no scope assumptions, so an arbitrary
source path should not be rejected merely because automatic placement is undefined.
Home-relative roots have one safe, locale-independent destination. External roots do
not: restoring to the original absolute path may require privilege, overwrite unrelated
state, or target a path that has different meaning on the new distribution. Native
backups retain D8's `cp -a` exit right; portable backups do not, hence the representation
gate.

**Rejected:** rejecting every `$HOME`-external source; restoring external roots to their
original absolute paths without an explicit safety contract; silently skipping invalid
inputs; treating a restore-addressless portable tree as a usable backup.

**Revisit if:** a concrete external-root workflow justifies a staging root, an explicit
source-to-destination mapping, or a guarded original-location restore contract.

**Relationship:** Refines D11's explicit-path syntax with root addressing and applies
D8's native exit-right boundary.

---

## D17 — 2026-08-01 — Sidecar v1 and the core metadata contract are frozen

**Status:** Decided — Phase B implementation pending

**Decision:** Phase B uses a versioned, NUL-framed, append-only sidecar as the
authoritative state log for portable capture and resume. The sidecar and its payload
form one committed state, and native metadata handling adopts the same exact numeric
ownership, mode, and timestamp contract. This entry freezes the wire grammar,
interruption rules, metadata policy, and the boundaries that remain outside Phase B.

### Committed state and resume

For a new entry, the writer completes and closes the payload before writing its
`ENTRY` and `XATTR` records; `ENTRY_COMMIT` is the only operation that makes the group
live. When replacing an already committed entry, the writer first commits a `DELETE`
for the old key, then replaces the payload, then writes and commits the new entry
group. An interruption after payload mutation therefore cannot leave old metadata
describing incomplete new bytes.

The reader applies **last committed state wins** per key: a later committed group for
the same key supersedes the earlier group, and a committed `DELETE` removes the key's
live state. Committed group order is the implicit generation. Because the writer
always `DELETE`s before replacing, a duplicate committed `ENTRY` without an
intervening `DELETE` is a reader-side last-wins case, not corruption.

Portable resume reconciles the previous committed live-key set with the keys visited
by the new source walk. Each stale key is deleted from the sidecar and its physical
payload is removed without following symlinks; any cleanup or final inventory failure
blocks finalization. A crash after a `DELETE` but before payload unlink leaves the key
non-live, so a later resume can remove the orphan safely. This guarantees process
interruption recovery, not power-loss durability; `fsync` is outside the contract.

Native resume still has a separate stale-entry gap: without a committed key log, a
source entry deleted between runs can remain in the native payload. That is explicitly
owned by Phase H, whose acceptance criterion is that deleted files/subtrees do not
survive a successful resumed final backup and that deletion failure blocks
finalization.

### Core metadata and ownership preflight

Atime, mtime, mode, and numeric uid/gid are core metadata. Native v1 and legacy
restore read the desired ownership from the payload tree; portable restore reads it
from committed sidecar state, while portable backup records true ownership without
applying it to the destination. Required metadata capture, apply, or readback failure
is fatal: backup returns nonzero and does not finalize, and restore leaves the
destination unchanged on its rejection path. UID remapping and current-user
normalization are not performed.

Metadata application is ordered and verified as:

```text
fchown -> fchmod -> futimens -> fstat readback
```

The ownership preflight is read-only during inventory and uses an anonymous
`O_TMPFILE|O_EXCL|O_RDWR|O_CLOEXEC` inode for each distinct privilege-relevant
profile. A profile is privilege-relevant when any of the following is true:

- the desired uid differs from the effective uid;
- the desired gid is outside the effective and supplementary groups;
- setuid or setgid is requested; or
- an existing destination object has an initial uid different from the effective
  uid, or an initial gid outside the effective and supplementary groups (including
  the case where the desired uid happens to equal the effective uid).

The probe applies the exact sequence above and verifies the resulting metadata. For
an existing destination profile, it first models the observed initial uid/gid on the
anonymous inode; failure there is itself a refusal because the real destination could
not be transitioned safely either. A failure of any required profile rejects the whole
invocation; no partial success is published. Self-owned, setid-free profiles do not
need this write probe and rely on the POSIX ownership guarantee.

The probe anchor is the actual destination root, or the nearest existing parent when
that root does not yet exist. It is not the mount point. Mount identity is retained
only as the uid-mapping domain in the profile key; a mount-wide identity must not make
an unwritable mount root stand in for a writable descendant. The metadata profile
limit is `MAX_METADATA_PROFILES = 65536`: exceeding it rejects the invocation before
mutation, so the probe and report budgets stay bounded. Diagnostic path examples are
bounded by `MAX_PREFLIGHT_EXAMPLES = 16`.

If a privilege-relevant anchor cannot perform `O_TMPFILE`, migr has no mutation-free
proof of the required authorization and refuses that invocation; there is no named
scratch fallback. Dry-run performs only read-only inventory and may report which
profiles require a live probe, but it must not claim that the live verdict is known.
Probe success is evidence for that anchor and profile at that instant only; a later
apply/readback failure remains fatal and is not silently reclassified.

### Timestamp and resume policy

Phase B adds a new destination capability, `FS_CAP_TIMESTAMPS`, which is supported
when both regular files and directories preserve atime and mtime at second granularity
and preserve the ordering of two distinct round-trip samples. Filesystem names and
guessed resolutions are never used as evidence. Nanosecond round-trip equality is
recorded separately in the destination capability profile as `nsec_exact` (it is a
probe measurement, not a sidecar field) and does not affect the representation
verdict.

When `nsec_exact` is false, metadata application writes the canonical
`{source_seconds, 0}` value for atime and mtime and verifies both the seconds and the
zero nanoseconds. Native content resume-skip is allowed only when `nsec_exact` is true
and `size + mtime_sec + mtime_nsec` matches. Otherwise regular-file content is copied
again; metadata is always reapplied and verified. Portable resume uses committed
sidecar state rather than destination timestamps.

### Source and restore safety

Native and portable capture use the same source snapshot contract: final objects are
opened with `O_NOFOLLOW` and the type-appropriate flags, payload-readable regular
files and directories are opened with `O_NOATIME` so migr's own reads do not perturb
the captured source atime. If `O_NOATIME` is refused (a non-owner without
`CAP_FOWNER`), capture fails closed before reading the payload rather than silently
falling back to a read that would change atime. Metadata is captured from the open
descriptor, and a post-copy `fstat` must match the pre-copy device, inode, type, size,
mode, uid/gid, timestamps, and ctime. A source change is fatal; there is no retry that
could silently join two different source states.

Native restore reads its own source (the payload tree it is restoring from) under the
same discipline, not only capture's read of the user's original files. The entry-gate
tests added ahead of the native metadata-fidelity work surfaced a concrete instance of
why this matters: `restore_entry_at()`'s directory branch always recurses during
`RESTORE_VALIDATE` (unlike the FIFO/regular branches, which return before touching
content), so its own `readdir()` perturbs the source directory's atime before
`RESTORE_APPLY` takes its metadata snapshot -- restored directory (and symlink) atime
is not currently exact. The fix is a single read-only metadata snapshot taken once per
source object, before `RESTORE_VALIDATE` runs, reused by `RESTORE_APPLY` rather than
re-read from a second, later open. This is preferred over merely adding `O_NOATIME` to
restore's reads (which would stop the atime corruption but leave the redundant
double-read in place) because it is the same "read-only inventory before mutation"
shape already required above for the ownership preflight, done in the same pass rather
than deferred to a later one.

Portable restore performs a global read-only preflight and then per-entry
fd-anchored, component-by-component revalidation with `O_NOFOLLOW`. Absolute paths,
`..`, empty interior components, symlink redirects, two distinct logical entries that
resolve to the same physical address, file-as-ancestor relationships,
manifest-external roots, unsupported types, and nonzero xattr counts before their
respective phases are rejected before persistent destination mutation. (A repeated
logical key across committed groups is collapsed by last-committed-wins, so it never
becomes two entries.) Confirmation precedes the live probe, and a probe rejection
guarantees no changed user payload, named scratch entry, or descriptor residue.

The Phase B file-kind policy is:

- regular files: content plus exact core metadata;
- directories: children first, then exact post-order metadata;
- symlinks: native no-follow behaviour remains; portable handling waits for Phase C;
- FIFOs: native exact metadata, portable handling remains fail-closed;
- sockets and device nodes: warning and skip, with an earlier committed state deleted
  before the skip can leave stale payload visible.

### Sidecar v1 wire grammar

The file begins with the byte sequence `MIGR_SIDECAR\0` followed by canonical version
`1\0`. Record tags are `ENTRY\0`, `XATTR\0`, `ENTRY_COMMIT\0`, and `DELETE\0`.
Every field except the xattr value is a NUL-terminated byte sequence: NUL-free byte
strings (root id, logical path, physical path, object kind, and xattr name) and
numeric fields alike end at their NUL. Xattr values are arbitrary bytes and are
encoded as a canonical length field followed by exactly that many raw bytes. Numeric
fields use canonical ASCII decimal with fixed signedness (timestamp seconds are
signed; nanoseconds, mode, uid, gid, size, and count are unsigned), explicit upper
bounds, and checked overflow; host `long`, `uid_t`, and `off_t` representations never
appear on disk. Nanoseconds are restricted to `0..999999999`.

The field order is fixed:

```text
ENTRY:
  tag, root_id, logical_path, physical_path, object_kind,
  mode, uid, gid,
  atime_sec, atime_nsec, mtime_sec, mtime_nsec,
  size, xattr_count, kind-specific fields

XATTR:
  tag, name, value_length, value_bytes

ENTRY_COMMIT:
  tag

DELETE:
  tag, root_id, logical_path
```

`mode` contains permission and special bits; object type is carried separately by
`object_kind`. `size` is meaningful for regular files. File, directory, and FIFO
records have no type-extra field. Symlink target bytes and hardlink references have
reserved type-specific positions in the v1 grammar, but their writers remain disabled
until their respective phases, and portable restore refuses them meanwhile.

An `ENTRY` must be followed by exactly its declared number of `XATTR` records and an
`ENTRY_COMMIT`. A standalone `DELETE(root_id, logical_path)` becomes committed at the
end of its path field. Unknown record, object-kind, or version; opening a second
group before the first is committed; and illegal record order are fatal. An
incomplete final record at EOF is a truncated tail and is discarded. A complete group
without `ENTRY_COMMIT` produces no live state; malformed data in the interior of the
file makes the sidecar unusable. A complete record whose content is invalid (unknown
tag, out-of-range value) is corruption wherever it sits, including at EOF — only a
record whose declared extent runs past EOF at the file's end is a truncated tail. The
parser returns the last valid boundary after the header or the latest complete
`ENTRY_COMMIT`/`DELETE`; adoption may truncate only to that boundary after proving
there is no interior corruption.

Resource ceilings cover root ids, logical/physical paths, xattr names and values,
xattrs per entry, live entries, total sidecar bytes, parser allocation, numeric
timestamps, uid/gid, mode, and regular-file size. Every length and arithmetic
operation is checked before allocation or casting. The implementation must publish
the concrete sidecar ceiling constants before the sidecar codec is implemented; this
decision fixes the categories and fail-closed behaviour without making a
host-dependent limit part of the wire format.

### Boundaries and relationships

Production portable dispatch remains disabled through Phase B. Portable symlink/FIFO
handling, xattrs/ACLs, illegal-name encoding, case collisions, hardlinks, and sparse
preservation remain in their designated later phases; D13's sparse-file boundary is
unchanged. D17 refines D8 by defining what “full fidelity” means for the accepted
contract and does not claim that the implementation is already complete.

**Why:** Sidecar state is both a format and a crash-recovery protocol. Freezing the
commit boundary, metadata semantics, and rejection policy before writing the parser
prevents an apparently valid partial backup from being published with stale metadata,
silently degraded ownership, or an ambiguous tail. Keeping the grammar byte-oriented
and resource-bounded also makes untrusted restore input reviewable and portable across
architectures.

**Rejected:** power-loss durability via `fsync`; silent UID/GID normalization; named
probe scratch files; mount-point substitution for the actual destination anchor;
atomic sidecar rewrite as an alternative to `DELETE` + last-committed-wins;
timestamp-based content skipping when nanoseconds are not exact; treating probe
errors as portable mode; production portable dispatch before the later safety phases;
and preserving sparse layout in the initial sidecar.

**Relationship:** D17 refines D6's append-only sidecar direction and D8's native
fidelity promise, applies D13's sparse boundary and D14's empirical fail-closed
representation policy, and records the Phase H native stale-reconciliation debt.
Relative to D6's sketch, D17 supersedes the "symlink stored as a regular file holding
the target path" representation in favour of reserved inline target bytes in the
record; D6 keeps its number and this entry names the reversal, per the append-only
rule.

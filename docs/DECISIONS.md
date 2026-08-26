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

**Status:** Implemented — the no-encoding/no-sidecar/exit-rights claim is now stated
explicitly in README's "Core Metadata Fidelity" section (2026-08-15). Substantively
satisfied well before this date by the accumulated native-fidelity work in Phases
B/E/G/H; only the explicit statement in these terms had never actually landed.

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

**Consequence (2026-08-26):** `migr` has no standalone `packages <FILE>` command;
package export is reachable only through `backup`. The path-based and production
entry points have different trust models: the former would open an arbitrary
user-supplied path, while the latter writes `packages.txt` beneath an anchored
container directory fd under the same single-component safety rules as the rest
of the backup. A standalone export adds no user-facing role that backup does not
already cover, so keeping only the production path removes a redundant,
weaker-trust interface rather than preserving it as a compatibility alias.

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

**Status:** Implemented (Phase B closed 2026-08-04; as-built notes in "Restore atime exactness" and "Relationship" below)

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

The live-state map's lookup and insert must not be a linear scan per operation once
this log is wired into production capture/restore: a backup can hold up to
`SIDECAR_MAX_LIVE_ENTRIES` (2^20) objects, and O(n) work per object makes the whole
walk O(n^2) over the entry count -- not acceptable at that ceiling, regardless of
which data structure eventually replaces the scan. The first state-log implementation
uses one because it is not yet reachable from production and its own tests run with
small fixture counts; that is the only reason it is tolerable today, and it must not
reach production in that shape.

The replacement is a hash table (open addressing, tombstoned deletes, salted
FNV-1a over `(root_id, logical_path)`), not a balanced tree. The two access
patterns this map actually serves -- capture is insert-heavy, restore is
lookup-heavy -- are both O(1) amortized on a hash table; a sorted array's
O(n) `memmove` per insert would leave capture at O(n^2) regardless of its
O(log n) lookup, so it does not solve this on its own. A real balanced tree
(red-black, AVL, B-tree) would give a guaranteed O(log n) bound with no
insert-side gap, but its only structural advantage over a hash table --
ordered iteration -- is never used: nothing here needs the live-state map
itself to produce entries in any particular order. Insertion order for
prioritized capture (e.g. backing up `--critical` paths first even when
`--critical` was not passed) is a walk-scheduling concern that belongs to
the caller enumerating source roots, not to this map, and is unaffected by
which structure holds committed state. A hand-written balancing
implementation is also simply more failure-prone in C than open addressing,
in exactly the code that already carries the highest memory-safety bar in
this codebase.

The hash is seeded per process (using `getrandom()` when available, with a
best-effort non-cryptographic fallback derived from the monotonic clock, pid,
and a process-local address value) even though no realistic attacker scenario
exists for `migr` today: adopting a resumed backup or reading a restore source
is a single-user, single-machine, on-demand operation, not a shared, always-on
service parsing anonymous input, and `SIDECAR_MAX_LIVE_ENTRIES` already bounds
the worst case a crafted collision could produce. The randomized seed is kept
anyway for three reasons, none of them a defence against a threat that does not
exist yet: it costs nothing wire-format-side (the hash lives only in memory,
never on disk, so it cannot bump the sidecar format); it costs only a few lines
because the codebase already has an established pattern for obtaining
process-local randomness; and it keeps faith with this document's own
"sidecar and payload are untrusted input" posture, which the fixed-seed
alternative would have been the one place to quietly abandon.

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

Backup metadata preflight accumulates these source-safe-read blockers independently
from destination ownership profiles and reports bounded path examples before the
destination probe. An unopenable directory is also counted as an uninspected subtree;
its descendants are not represented as a precise affected-object count. The capture
pass preserves the same strict refusal if ownership changes after preflight.

Native restore reads its own source (the payload tree it is restoring from) under the
same discipline, not only capture's read of the user's original files. The entry-gate
tests added ahead of the native metadata-fidelity work surfaced a concrete instance of
why this matters: `restore_entry_at()`'s directory branch always recurses during
`RESTORE_VALIDATE` (unlike the FIFO/regular branches, which return before touching
content), so its own `readdir()` could perturb the source directory's atime before
`RESTORE_APPLY` took its metadata snapshot. The fix adopted -- a single read-only
metadata snapshot taken once per source object, before `RESTORE_VALIDATE` runs,
reused by `RESTORE_APPLY` rather than re-read from a second, later open -- is
implemented. This is preferred over merely adding `O_NOATIME` to restore's reads
(which would stop the atime corruption but leave the redundant double-read in place)
because it is the same "read-only inventory before mutation" shape already required
above for the ownership preflight, done in the same pass rather than deferred to a
later one. The remaining symlink-atime limitation, and the additional preflight fix
it required, are described in "Restore atime exactness (as-built)" below.

### Restore atime exactness (as-built)

Implemented as described above, with one kernel limitation now made explicit:
destination symlink atime is exact (the pre-mutation snapshot is recorded before
`RESTORE_VALIDATE` reads the target, and `RESTORE_APPLY` applies that recorded value),
but the *source* symlink's atime cannot be preserved across restore. On Linux,
`readlinkat()` itself updates the symlink's atime and no flag suppresses it —
`O_NOATIME` applies only to `open()`, and `O_PATH` descriptors do not help — so any
restore that must read a symlink target perturbs the source symlink's atime. This is
outside migr's control (barring a `noatime` mount, which migr cannot assume), and the
restore contract does not promise source-symlink atime preservation. To keep the
destination exact, no walk may read a symlink target before the real restore's
snapshot: the metadata-ownership preflight (`restore_native_metadata_inventory_at`)
skips symlink target reads entirely (`skip_symlink_target_read`), while the dry-run
preflight and the real `RESTORE_VALIDATE`/`RESTORE_APPLY` passes still perform
ordinary target validation.

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
operation is checked before allocation or casting. This decision fixes the
categories and fail-closed behaviour without making a host-dependent limit part
of the wire format.

The concrete constants, published here before the sidecar codec is implemented:

| Constant | Value | Basis |
|---|---|---|
| `SIDECAR_MAX_ROOT_ID` | 64 | `MANIFEST_ID_MAX` (D16) -- a sidecar root id names a manifest root table entry |
| `SIDECAR_MAX_PATH` | 4096 | `PATH_MAX`, logical and physical paths alike |
| `SIDECAR_MAX_SYMLINK_TARGET` | 4096 | `PATH_MAX`; the type-specific field reserved above, not yet written |
| `SIDECAR_MAX_XATTR_NAME` | 255 | Linux `XATTR_NAME_MAX` |
| `SIDECAR_MAX_XATTR_VALUE` | 65536 | Linux `XATTR_SIZE_MAX`; `setxattr`/`getxattr` accept nothing larger |
| `SIDECAR_MAX_XATTRS_PER_ENTRY` | 256 | generous relative to `XATTR_SIZE_MAX`/`XATTR_NAME_MAX`, still bounded |
| `SIDECAR_MAX_LIVE_ENTRIES` | 2^20 (1,048,576) | resource-exhaustion ceiling, not an expected count -- same role as `MANIFEST_MAX_ROOTS`/`METADATA_MAX_PROFILES` |
| `SIDECAR_MAX_TOTAL_BYTES` | 4 GiB | consistent with the live-entry ceiling at a generous per-entry average |
| `SIDECAR_MAX_ALLOC_BUDGET` | 1 GiB | the parser's own heap use, live-state map included; the sidecar is streamed, never loaded whole, so this is smaller than `SIDECAR_MAX_TOTAL_BYTES` on purpose |
| timestamp seconds | signed, full range | already fixed above ("timestamp seconds are signed") |
| timestamp nanoseconds | `0..999999999` | already fixed above |
| uid / gid | unsigned, 32-bit | matches `uid_t`/`gid_t` width; wire stays unsigned per the field above |
| mode | unsigned, `0..07777` | permission and special bits only, per the field above |
| regular-file size | unsigned | a file's size is never negative; this does not revisit "size... are unsigned" above, only gives it no further ceiling beyond the wire's own width |

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

As-built (Phase B, 2026-08-04): the sidecar codec, portable capture/resume core,
portable restore preflight/replay/orchestration, and the native core-metadata
fidelity work are all implemented and gated (host `make check` matrix, Ubuntu/Arch
VM matrix, Fedora parity with the known Phase E xattr gap). Production portable
dispatch remains disabled, per "Boundaries and relationships" above. Two
source-safe-read refusal classes surfaced by the VM matrix (restore-side and
backup-side `O_NOATIME`/EPERM) are reflected in the "Source and restore safety"
section; the restore symlink-atime limitation is reflected in "Restore atime
exactness (as-built)".

---

## D18 — 2026-08-04 — Portable symlink handling: placeholder node + record

**Status:** Implemented (Phase C closed 2026-08-06; as-built notes below)

**Decision:** Portable symlinks use a payload placeholder and a sidecar record.
The placeholder is an empty regular file (`size=0`) at the symlink's payload
path; it never contains the target and is never read as the target. The sidecar
entry has `kind=symlink` and carries the target plus the symlink's core metadata
(`mode`, `uid`, `gid`, `atime`, and `mtime`). This preserves the invariant that
every live sidecar key has a corresponding payload node.

### C-1 — Symlink representation

The target is read from the source link and stored only in the sidecar record;
the placeholder's bytes are always empty and its type is always regular.

### C-2 — Symlink metadata

- Mode is recorded, but portable replay never calls `chmod` for a symlink,
  because a path-based mode change follows the link. Replay applies ownership
  with `fchownat(..., AT_SYMLINK_NOFOLLOW)`, applies timestamps with
  `utimensat(..., AT_SYMLINK_NOFOLLOW)`, and verifies the result by readback.

### C-3 — Source-change detection

- Capture takes an `lstat` snapshot before `readlinkat`, reads the target, then
  checks `metadata_symlink_unchanged` against a second no-follow metadata read.
  A changed link is a fatal source-change error; capture does not retry it.

### C-4 — Ownership preflight

- Portable capture does not run an ownership preflight or call `chown` for a
  source symlink; the source's true ownership is recorded in the sidecar.
  Portable restore includes symlink entries in the ownership profile and applies
  ownership with the no-follow operation above.

### C-5 — Lossy destinations

- If `FS_CAP_SYMLINK` is unavailable, representation selection already chooses
  portable. If replay's `symlinkat` fails with `EOPNOTSUPP` or `EROFS`, the entry
  is rejected fail-closed; it is never silently dropped or degraded.

### C-6 — Portable FIFO boundary

- Portable FIFO handling remains outside Phase C and fail-closed. Its
  placeholder-versus-record policy is left open for a later decision.

### C-7 — Test-only boundary

- All Phase C orchestration is exposed only through D14 test-only seams.
  Production portable dispatch remains disabled until the later safety gates.

### C-8 — Symlink xattrs

Symlink xattrs are collected with the no-follow path APIs `llistxattr` and
`lgetxattr`; a symlink has no readable fd on which the regular fd-based xattr
APIs could operate. Until Phase E implements replay, a symlink entry with
`xattr_count != 0` is rejected fail-closed. Xattrs are never silently omitted
or rewritten as an empty set.

### Scope boundary

The C-1 through C-8 rules apply to portable symlink handling only; native
no-follow behaviour is covered by the existing metadata contract and its entry
gate. Operational probe errors remain fatal under D14 rather than becoming a
portable verdict.

### As-built (Phase C, 2026-08-06)

The D14 test-only portable capture and replay seams were exercised against real
vfat loopback containers on Arch and Ubuntu. Both systems round-tripped a
symlink byte-for-byte: capture wrote an empty regular placeholder in the
container and replay recreated the destination link with the exact target.
On Fedora, the same real-filesystem round-trip reached the deliberate Phase E
boundary: the symlink carried an automatic `security.selinux` xattr, so replay
refused it fail-closed and left no destination residue rather than silently
discarding the xattr. Production portable dispatch remains disabled and still
refuses lossy vfat destinations before creating a container, also without
residue. FIFO handling was not changed by Phase C and remains fail-closed.

**Why:** These rules freeze the representation and rejection boundaries before
the symlink parser, capture walker, and replay walker are written. A
payload-less representation was rejected because it would make the universal
"every live key has a payload node" invariant exceptional in the capture,
reconciliation, and restore-inventory paths. Keeping a placeholder preserves
that invariant without putting target bytes in the payload, while the
fail-closed rules prevent unsupported metadata or filesystem operations from
becoming silent data loss.

**Rejected:** payload-less symlink entries; silently writing `xattr_count=0`
for a symlink with xattrs; bringing portable FIFO handling into Phase C;
opening production portable dispatch in Phase C; and promising source-symlink
atime preservation, which Linux `readlinkat` cannot guarantee under the
no-atime discipline.

**Relationship:** D18 keeps D17's replacement of D6's target-storage sketch:
the target lives in the sidecar record, not in payload content. It settles the
question D17 left open by retaining D6's payload node as an empty placeholder,
so the live-key-to-payload-node invariant remains universal. It extends D7's
fail-closed xattr rule to symlinks, remains subject to D14's empirical
representation and test-only-dispatch boundary, and leaves hardlinks to Phase
G, illegal-name encoding to Phase D, and xattr replay to Phase E.

---

## D19 — 2026-08-06 — Portable illegal-filename handling: encode on disk, true name in the record

**Status:** Implemented (Phase D closed 2026-08-07; as-built notes below)

**Decision:** A portable payload node is written under a percent-encoded name,
while the sidecar keeps the true name. The logical path contains the original
bytes and is the only path restore writes to the destination; the physical path
contains the encoded name and exists only inside the payload tree. A mandatory
read-only pre-scan reports every name that cannot be represented before any
payload bytes are written. An unrepresentable name refuses the run by default;
it is never silently skipped.

### N-1 — Component safe set

The encoding scheme is byte-oriented and injective: every byte outside the
safe set becomes `%XX` with uppercase hexadecimal, and `%` itself is always
encoded as `%25`. The payload safe set differs from the manifest's because it
describes filename validity rather than line-parsing safety:

- `/` is never safe. It cannot occur in a single `readdir` name, but allowing
  it through would create an unintended directory component in the physical
  path.
- `.` is safe inside a component, but a component whose last byte is `.` has
  that byte encoded as `%2E`. Encoding only the final byte prevents a
  destination that strips trailing dots from changing the name.
- Well-formed UTF-8 sequences pass through unencoded. Invalid UTF-8 is
  escaped, including overlong forms, lone continuation bytes, truncated
  sequences, surrogates, and code points beyond U+10FFFF.

### N-2 — Encoded names and `NAME_MAX`

The length limit applies to the encoded component, because escaping can
triple its byte length. A component whose encoded form exceeds `NAME_MAX`
refuses the run by default; it is never silently skipped, since a skipped
entry would make the backup appear complete while being incomplete.

### N-3 — Logical and physical paths

The logical path is the original name and is the only path restore writes to a
destination; POSIX destinations accept every byte. The physical path is the
encoded name and is meaningful only relative to the payload tree. Visited-set
and live-map keys remain logical, so encoding does not change resume or
reconciliation identity.

### N-4 — Binding physical to logical

Replay re-encodes the logical path and verifies that the result is byte-for-byte
identical to the recorded physical path, refusing the entry otherwise. The
sidecar is untrusted input: path validation alone proves only that a physical
path remains below the payload root, not that it names the node corresponding
to the logical path. Because the encoder produced the physical path, malformed
escapes are covered by this equality check and replay needs no decoder; the
destination name always comes from the logical path.

### N-5 — Mandatory pre-scan

Before capture writes anything, a read-only pass maps every name and produces
an unrepresentable-name report. The report contains a total and a bounded set
of examples, each identifying the violated limit and the amount by which it is
violated. The pass cannot be disabled. A later interface may suppress a
confirmation prompt, but it may not suppress the scan.

### N-6 — One encoding scheme, two safe sets

The encoder and decoder live in one shared module used by both the manifest and
the portable payload. The safe set is selected by an explicit mode argument;
there is no implicit default. One implementation prevents the two copies from
drifting apart, while the explicit mode prevents a caller from accidentally
inheriting the wrong safe set.

### N-7 — Test-only boundary

All Phase D encoding and pre-scan behaviour remains behind the existing
test-only portable seam. Production dispatch to the portable representation
stays closed.

### N-8 — Encoded paths and `PATH_MAX`

A tree whose individual components fit `NAME_MAX` can still exceed `PATH_MAX`
after encoding and joining. Capture checks the complete payload path, including
the payload root, and refuses by default on overflow. This is a separate
refusal class from the encoded-component `NAME_MAX` limit and is reported
separately.

### N-9 — The written name is verified, not predicted

After creating a payload node, capture reads the name back from its parent
directory and compares it byte-for-byte with the intended physical name. This
verification makes UTF-8 pass-through safe without expanding the capability
probe's raw-name corpus: it catches Unicode normalisation and any other
destination-side name transformation that was not anticipated.

### N-10 — Case folding is measured, not predicted

A case-insensitive destination's non-ASCII folding rule cannot be predicted
from mount options or filesystem format; it must be measured. The pre-scan finds
candidate siblings cheaply with an ASCII-lowercased skeleton that replaces every
non-ASCII byte with one placeholder. This is sound because a filesystem's
case-folding table cannot change a name's length, so names with different
skeletons cannot collide under any folding rule. Only real candidate groups are
then probed by creating their encoded names in a destination scratch directory
and reading back which names survived. Collision attribution uses the
destination's directory listing rather than a by-name lookup: real vfat showed
that a losing name's `open(..., O_CREAT|O_EXCL)` detects the collision reliably,
while a subsequent `stat()`/`fstatat()` of that same byte string is not reliable
for non-ASCII names. This directional inconsistency in the Linux vfat driver's
`utf8` NLS handling was confirmed across three independent kernels. ASCII
folding remains an in-memory check; only genuine non-ASCII candidates reach the
destination probe, so an all-ASCII tree pays no extra I/O.

### Scope boundary

Native capture and restore are untouched: native destinations accept every
byte, and no native path is encoded. Case-insensitive destinations may still
map two distinct encoded names onto one node; the pre-scan detects that case
collision and refuses by default, while resolving it with a disambiguating
suffix remains part of the case-collision work. Encoding interacts with xattrs,
hardlinks, and sparse files, but those concerns remain in their respective
phases. A user-confirmed path that proceeds past an unrepresentable name is
out of scope; supporting it would require the container to record its own
incompleteness so restore could report it.

**Why:** Portable payloads need names that survive filesystems with stricter
filename rules without losing the original names that users must see on
restore. Keeping logical and physical paths separate lets the payload use a
validated, injective representation while the sidecar remains authoritative
for the destination name. The mandatory pre-scan and fail-closed refusal keep
an unsupported tree from being published as a complete backup, and read-back
verification checks the destination's actual behaviour rather than assuming
that a capability label predicts every name transformation.

**Rejected:** reusing the manifest's safe set unchanged, because it leaves a
trailing `.` untouched and escapes every non-ASCII byte, turning an ordinary
28-character Japanese name into a `NAME_MAX` overflow (three bytes per
character, three characters per escaped byte); adding a non-ASCII case to the
raw-name capability corpus, because that corpus selects the representation and
would turn a probe result into a blanket refusal while portable dispatch is
closed; and skipping unrepresentable names with a final warning, because the
resulting container would look complete while silently omitting data.

**Relationship:** D19 builds on D17's grammar, where logical and physical paths
are already separate fields (which capture has so far kept identical), and
applies D14's test-only boundary and fail-closed representation policy. It
follows D18's rule that a representation gap refuses rather than silently
dropping data, while making the physical-name encoding and mandatory pre-scan
explicit for the portable payload. Native metadata, xattrs, hardlinks, sparse
layout, and production portable dispatch remain governed by their existing
decisions and later phase boundaries.

### As-built (Phase D, 2026-08-07)

The mandatory pre-scan now refuses an encoded component over `NAME_MAX` or an
encoded payload path over `PATH_MAX` before writing any payload byte. Real vfat
loopback runs in the VM gate proved both refusal paths and left no container
residue. The same matrix exercised ASCII and non-ASCII case collisions on Arch,
Ubuntu, and Fedora: `Foo`/`foo` was refused on case-insensitive destinations,
and `café`/`CAFÉ` was refused where the destination actually folded those
names. A resume that would otherwise overwrite an existing captured file is
also refused, with the existing payload left byte-for-byte unchanged.

The VM gate exposed the concrete kernel behaviour behind N-10: the create-time
`EEXIST` result and a later `fstatat()` lookup can disagree for a non-ASCII name.
Non-ASCII folding also varied by kernel, not only by mount option. Kernel
`7.1.5-arch1-2` folded non-ASCII case for an `iocharset=iso8859-1` mount,
whereas `7.0.0-28-generic` and `6.19.10` did not. Measuring the destination on
each run handled both outcomes without a code change. Production portable
dispatch remains disabled under D14; all of this behaviour is reachable only
through the existing test-only seam. Fedora's plain regular-file/directory
portable round-trip still meets the same automatic `security.selinux` xattr
wall already recorded for symlinks in D18, so that Phase E boundary is neither
new nor a Phase D regression.

---

## D20 — 2026-08-07 — Portable and native xattr/ACL handling: generic capture and replay, no framework-specific code

**Status:** Implemented (Phase E closed 2026-08-08; as-built notes below)

**Decision:** Both portable and native destinations capture and replay
every extended attribute through the generic `getxattr`/`setxattr` family,
with no framework-specific code path for SELinux, AppArmor, or any other
xattr consumer (D7). POSIX ACLs are not a separate mechanism: they travel
as the `system.posix_acl_access`/`system.posix_acl_default` xattrs like any
other extended attribute. Both capture and replay reconcile an **exact**
set, not an additive one: an attribute present at the destination but
absent from the source is removed, not left stale. Replay applies
ownership, then mode, then the exact extended-attribute set, then
timestamps; a destination that cannot hold a captured namespace or object
kind at all is detected and refused before any payload mutation, and a
`setxattr`/`lsetxattr`/`fsetxattr`/`removexattr` failure discovered after
that refuses the affected entry fail-closed, the same way an
unrepresentable name or a case collision already does.

### E-1 — Namespace scope

Every namespace is captured and replayed with no exception: `user.*`,
`security.*`, `system.*`, `trusted.*`. D7's framework-agnosticism means no
namespace question is asked at capture time; whatever `getxattr` returns is
stored, and whatever the destination's `setxattr` accepts is written. A
namespace an environment doesn't support is not a silent omission -- it
surfaces through E-9's capability gate or E-3's fail-closed write rule,
never through a quiet capture-side filter.

### E-2 — Apply order and the POSIX ACL mask

Extended attributes are applied **after** mode, not before:
`chown → chmod → xattr → times`. A POSIX ACL's `mask` entry is recomputed
by the kernel as a side effect of `chmod` whenever the file already carries
an ACL. Writing the ACL before `chmod` would let the following `chmod`
silently overwrite the mask that was just restored; applying it after
`chmod` makes the captured ACL bytes the final, authoritative state.
`rsync -A` and `cp --preserve=xattr` order their own ACL restore the same
way, for the same reason -- this is not a migr-specific choice, it is what
POSIX ACL semantics require.

### E-3 — A failed read, write, or removal refuses the entry, never drops it

A capture-side read failure, a replay-side `setxattr`/`lsetxattr`/
`fsetxattr` failure, or a stale-attribute `removexattr` failure (other than
`ENODATA`, which is an idempotent success when removing something already
gone) refuses the affected entry fail-closed -- for every object kind,
including symlinks, with no exception for any namespace. Backup cannot
finalize over such a failure. If a replay/TOCTOU failure surfaces after
E-9's capability gate has already passed, the invocation does not silently
succeed and does not promise to roll back what was already applied: it
returns non-zero with an honest applied/failed count, the same contract
D17 already established for restore in general. This is the same rule D18
and D19 established for a representation the destination cannot hold:
refuse and say so, never silently omit the data.

### E-4 — Symlinks are an ordinary case, not an exception

`lsetxattr`/`lgetxattr`/`llistxattr`/`lremovexattr` are real, standard
Linux syscalls -- portable capture has used the read side
(`lgetxattr`/`llistxattr`) for symlinks since Phase C (D18 C-8). Symlink
extended attributes are captured and replayed with the same `l*` family
under the same E-3 fail-closed rule as every other kind; they are not
collected-but-unwritable, and D18 C-8's own text already expected this
("Until Phase E implements replay").

### E-5 — Apply order is shared

`create → chown → chmod → (remove stale, then set) extended attributes →
times → readback` is the same sequence for both native and portable
replay, extending D17's existing `chown → chmod → times` order (see D17's
"Restore atime exactness" and its as-built notes) with one inserted step
rather than replacing it.

### E-6 — Ceilings are unchanged

`SIDECAR_MAX_XATTRS_PER_ENTRY`, `MAX_XATTR_NAME`, and `MAX_XATTR_VALUE`
stay exactly as D17 froze them. Phase E does not touch these limits.

### E-7 — Test-only boundary

All of Phase E's capture and replay behaviour remains behind the existing
D14 test-only seam. Production portable dispatch stays disabled.

### E-8 — Exact-set reconciliation, both directions

Capture is not read-only with respect to the payload/destination's
extended attributes: an attribute the destination already carries but the
source no longer has is removed, not left behind. This applies symmetrically
-- native capture reconciles the payload object's attribute set against the
live source on every run (not only on first capture), and native/portable
replay reconciles the destination object's set against the sidecar's
recorded set. Resume equivalence for an entry is not size/mtime alone: an
entry whose extended-attribute set no longer matches byte-for-byte is not
eligible to be skipped as unchanged.

**`security.*` stale removal tolerates, but still attempts, the LSM's own
refusal.** A destination object gets a `security.*` value (typically
`security.selinux`) assigned automatically by the kernel/LSM at creation
time, independent of anything migr writes -- so a payload whose source
never carried a `security.*` value (for example, one captured on a
non-SELinux system, then restored onto an SELinux-enabled one) makes exact-
set reconciliation see a destination attribute that "shouldn't" be there.
Removing it requires privilege (`CAP_MAC_ADMIN` or an equivalent LSM
grant) an ordinary restore does not have, so this specific removal
tolerates `EACCES`/`EPERM` the same way removal already tolerates
`ENODATA` for an attribute that's already gone -- an idempotent-style
non-failure, not a silent skip. The removal is still attempted every time,
not bypassed by namespace name: a caller that genuinely holds the
privilege to remove a stale `security.*` value still does, and E-8's
exact-set guarantee still holds wherever it's actually achievable. Only
the specific, expected-for-most-callers privilege failure is tolerated,
mirroring E-9's own `security.*` carve-out (that gate's probe is excluded
entirely because no synthetic value can generalize the policy-specific
accept/reject decision; this is the same underlying fact -- `security.*`
is LSM-owned, not filesystem-owned -- showing up in the reconciliation
step E-9 itself defers to).

### E-9 — A pre-mutation capability gate, tightly scoped

Before either native or portable replay mutates any user payload, a
capability gate checks whether the destination can hold what the sidecar
requires, and refuses the whole invocation before any mutation if not.
Its scope is deliberately narrow, fixed here rather than left to whoever
implements it:

- **Once per invocation, not once per entry.** Namespace support is a
  property of the destination, not of any individual file.
- **Name only, not the captured value.** The gate attempts to set and
  remove one representative attribute name per required namespace, in an
  isolated scratch fixture that is always cleaned up. It does not write
  the actual captured value. A value-specific rejection (for example a
  destination's own per-value size ceiling) is not this gate's concern --
  it surfaces later through E-3's ordinary replay-time fail-closed check,
  since `MAX_XATTR_VALUE` is already a value ceiling migr enforces on its
  own side regardless.
- **One check per object kind actually present.** Regular/directory
  objects (`f*` family) and symlinks (`l*` family) reach the destination
  through mechanically different syscalls, so each required combination of
  object kind and namespace is checked independently.
- **`security.*` is out of this gate's probe, by name.** Unlike the other
  three namespaces, `security.*` writes are validated by the destination's
  loaded LSM policy (SELinux, AppArmor), not by generic filesystem/
  namespace support. An invented probe name has no universally-valid
  placeholder value the way `system.*`'s POSIX ACL wire format does --
  whether a given `security.*` value is accepted is inherently policy- and
  value-specific, exactly the class of rejection this gate's own
  name-only design already excludes above ("a value-specific rejection
  ... is not this gate's concern"). Probing it anyway would make the gate
  refuse essentially every restore of a payload sourced from an
  SELinux-enabled system, regardless of whether the destination genuinely
  supports `security.*` (it almost always does -- it's using the
  namespace on every file already). This is E-10's written, accepted
  cross-policy boundary surfacing in the gate's own mechanism shape, not a
  new exception. `security.*` presence is still tracked for the kind ×
  namespace matrix's bookkeeping; it is simply never fed into the probe.
  Its actual acceptance on replay remains E-3's ordinary fail-closed
  check, same as any other value-specific rejection.

A failure discovered after this gate has already passed (a race, a
mid-replay policy change, anything the gate could not have observed) is
not this gate's failure to catch -- it falls to E-3's ordinary fail-closed
rule with an honest partial result, not a broken promise from the gate.

### E-10 — The `security.*` semantic-transplant risk is a written boundary, not a filter or a runtime warning

`security.*` is captured and replayed like any other namespace (E-1) --
there is no default filter excluding it. But a successful `setxattr` of a
`security.*` value does not mean the transplanted label is correct on the
destination's own security policy; a label can be written successfully and
still be semantically wrong on a system with a different policy, a class
of error no syscall-failure check can ever catch, because the write itself
does not fail. This decision does not solve that -- it is written down
here as a known, accepted boundary, not a runtime warning (D14's test-only
seam has no real runtime user to warn), and not resolved by silently
excluding `security.*` from capture, which would leave the backup quietly
incomplete for that namespace. A future, not-yet-designed user-confirmed
omission mechanism is where this eventually gets a real answer.

**Why:** D8's full-fidelity promise has stood with an acknowledged, empty
gap for native xattrs since before Phase B; Phase C and Phase D's own
capture code already collects xattrs on every portable entry, so the
remaining work is replay, exact-set reconciliation, and the native side,
not new collection logic. Ordering extended attributes after mode rather
than before is required by POSIX ACL semantics, not a preference.
Fail-closed on a write failure, and a pre-mutation capability gate ahead of
it, keep a destination's real limitations from becoming silent data loss or
a half-applied backup -- the same discipline D18 and D19 already
established for symlink xattrs and unrepresentable names respectively. The
capability gate's scope is fixed narrowly (E-9) rather than left
open-ended, following the precedent D-10/N-10 already set: a
measure-rather-than-predict mechanism's shape belongs in the decision, not
rediscovered per-implementation.

**Rejected:** a framework-specific code path for SELinux or any other xattr
consumer, and calling `restorecon` or an equivalent, both ruled out by D7;
treating symlink extended attributes as permanently unwritable, which is
factually wrong (`lsetxattr` exists) and contradicts D18 C-8's own text;
silently excluding the `security.*` namespace from capture by default to
avoid cross-policy transplant risk, rejected because it would make the
backup quietly incomplete for that namespace with no visible record, the
same failure shape D16, D18, and D19 have consistently refused to allow
elsewhere in this project; and a capability gate that probes captured
values rather than names alone, rejected as unnecessary cost for a class of
failure E-3's ordinary fail-closed replay-time check already covers.

**Relationship:** D20 makes D7's framework-agnosticism concrete for
extended attributes and ACLs. It keeps D17's `chown → chmod → times` apply
order intact, inserting extended attributes as one more step rather than
restructuring it, and shares that order between native and portable. It
extends D18's C-5/C-8 and D19's N-2/N-5/N-8/N-10 rule -- a representation
gap is measured and refused fail-closed, never silently dropped or
predicted from a table -- to every extended attribute namespace and every
object kind, and to the pre-mutation capability gate's own existence.
Hardlink xattr-sharing remains Phase G's concern, and the `security.*`
cross-policy semantic risk noted in E-10 is left to a future, not-yet-
designed user-confirmed skip mechanism rather than solved here.

### As-built (Phase E, 2026-08-08)

Native capture, native restore, portable capture, and portable replay now
reconcile the destination's extended-attribute set exactly against the
source's in both directions, including removal of an attribute present only
at the destination. The pre-mutation capability gate refuses an invocation
before any payload write when a required object-kind and namespace combination
is unusable at the destination. The host suite and `make check` (strict GCC
and Clang, sanitizers, Valgrind, and `-fanalyzer`) passed on Arch, Ubuntu, and
Fedora against `f563623`, with no compiler diagnostics and no Valgrind errors.

The VM gate also exercised a real ext4 loopback destination: `user.*` values
round-tripped byte-for-byte for both a regular file and a directory, and a
stale destination attribute was removed by the next replay. A payload carrying 
extended attributes was refused before any mutation against a real vfat loopback
destination, leaving zero destination residue. On Fedora, an automatic
`security.selinux` label round-tripped byte-for-byte, including on a symlink;
this proved E-4's ordinary-symlink rule against a real label rather than a
synthetic host fixture.

E-8's two halves were both proven in the VM gate. Running as root, a stale
`security.*` attribute absent from the payload was genuinely removed, while
Fedora's own `security.selinux` remained non-removable even for root and was
tolerated as the documented `EACCES` case. The test first established that
root could set, read, and remove an arbitrary `security.*` name on ext4 and
tmpfs on all three distributions, so the removal proof was measured rather
than assumed. Production portable dispatch remains disabled under D14; all
of these paths are reachable only through the existing test-only seam.

This implementation supersedes D18 C-8's temporary rule that a symlink entry
with `xattr_count != 0` is rejected until Phase E. Symlink extended attributes
are now replayed through the no-follow `l*` family under E-3's ordinary
fail-closed rule; D18 C-8 and the Phase C/D as-built records remain unchanged
as historical entries.

### E-11 — `security.*` apply refusal is visible, measured, and non-fatal

The first implementation of E-8's tolerance covered only stale
`security.*` removal. The set loop still treated an unprivileged
`EACCES`/`EPERM` from `fsetxattr` or `lsetxattr` as an entry-fatal error.
That asymmetry was exposed by the real migration workflow this project must
serve: a backup captured on Fedora with SELinux labels was carried on a
physical exFAT USB device and restored unprivileged on Arch without SELinux.
The first file's `security.selinux` write refused, and the restore stopped
before applying any of the remaining files.

The correction keeps E-1's capture fidelity and E-10's framework agnosticism,
but makes this value-specific cross-policy limitation explicit to the user.
The restore preflight counts entries carrying `security.*` values and folds a
warning into the existing single confirmation prompt. The warning explains
that an unappliable attribute will be skipped while that entry's other
content and metadata continue to restore. There is no second confirmation
gate and no silent tolerance: a second prompt could leave an operation
waiting after the user believed it had started, while a silent skip would
violate D8's visible-loss rule.

After confirmation, only `security.*` set or removal failures with
`EACCES`/`EPERM` are tolerated, exactly matching E-8's existing removal
exception. Each tolerated attribute is counted at apply time and the final
restore summary reports the actual count; the preflight and dry-run messages
report presence only and do not predict which values the destination policy
will accept. All other namespaces and errno values retain E-3's fail-closed
behaviour. The rule is shared by native and portable restore because both
paths use `metadata_apply_xattrs_target()`.

---

## D21 — 2026-08-08 — Portable case-collision resolution: deterministic suffix

**Status:** Implemented (Phase F closed 2026-08-10; as-built notes below)

**Decision:** Portable capture resolves case collisions in the payload namespace
with a deterministic, `readdir`-order-independent suffix while preserving D19
N-10's destination-backed measurement discipline. The suffix is a structural
`collision_suffix` field in the sidecar v2 `ENTRY` record, present for every
entry; an empty field means that the entry has no suffix. The **real physical
path contains the suffix** when one is assigned, but the suffix is never carried
to the restore destination, where the logical name is written.

### F-1 — Deterministic assignment order

Encoded sibling names are ordered by unsigned byte-wise lexicographic order,
independent of `readdir()` order. Each candidate first tries an empty suffix;
later members of a collision group begin with canonical `N=1,2,...`. If a
destination reservation or readback rejects a candidate, the allocator advances
to the next canonical suffix. Therefore the first sorted candidate is preferred
without being promised a suffix-free name under every measured destination
state.

### F-2a — Structural wire field

In sidecar v2, every `ENTRY` contains `collision_suffix` in a fixed position
immediately after `physical_path`. The empty value is the semantic
no-collision case; writing the field only for colliding entries is not a valid
wire encoding because the NUL-separated grammar would become ambiguous.

### F-2b — Canonical suffix form

The suffix is `%7E` followed by a decimal `N` (`%7E1`, `%7E2`, ...). `N` is at
least one, has no leading zeroes, uses an uppercase `E`, and is bounded before
allocation by the sidecar, component, and path ceilings. The form stays inside
D19's encoded on-disk alphabet because the raw `~` byte is encoded as `%7E`.

### F-2c — Physical path carries the suffix

`SidecarEntry.physical_path` is the actual payload path, including its suffix.
The suffix is stored separately so restore can authenticate the relationship;
it is not a reason to omit the suffix from the payload name and it is never
re-derived from the logical name. A collision candidate's physical leaf is
`encode_component(logical_leaf) + collision_suffix`.

### F-2d — Destination authority for candidate allocation

The source-set ordering and candidate numbering are deterministic, but final
candidate names are verified on the destination with the existing probe and
readback discipline. Reservation and attribution are hash-based and must not
reintroduce a wall-clock dependency or an O(n^2) scan. On resume, a name owned
by the current container/sidecar for the same logical entry is not an external
collision; stale owned names and foreign names are handled explicitly rather
than silently overwritten.

An ASCII suffix alone cannot prove how an encoded candidate relates to every
non-ASCII name on a particular filesystem. For example, a raw `foo~1` becomes
`foo%7E1` and may still fold with another candidate. The destination, not a
filesystem-name prediction, remains authoritative.

### F-3 — Parent-prefix physical/logical invariant

The restore invariant is not entry-local. Because capture derives a child's
physical path from its parent's physical path, a directory suffix is embedded
in every descendant physical path. For a non-root entry, the recorded
`physical_path` must equal the **immediate parent's recorded `physical_path`**,
then `/`, then `encode_component(logical_leaf) + collision_suffix`. A root-level
entry uses the manifest root's `payload_path` as its parent and performs no
parent-entry lookup. A missing parent entry is malformed and is refused. This
single parent-prefix check inductively covers all ancestor suffixes without
guessing them from logical paths.

### F-4 — Complete assignment plan

The pre-scan produces a bounded plan keyed by `(root_id, logical_path)` and
containing the actual `physical_path`, `collision_suffix`, and reservation data.
Fresh and resume capture contexts consume this plan; walkers never invent a
fallback suffix. A source-set change between pre-scan and capture (including a
new or missing entry) is a fail-closed source-plan mismatch rather than an
opportunity to silently choose a different name.

### F-5 — Root payload namespace

`ManifestRoot.payload_path` addresses are a separate namespace. Overlapping,
duplicate, or case-equivalent root payload paths are rejected before mutation;
F does not introduce a root suffix field. Where non-ASCII equivalence cannot
be inferred, the same destination probe/readback authority is used.

### F-6 — Limits and report semantics

`NAME_MAX` and `PATH_MAX` checks include the suffix. A suffix-induced overflow is
fatal. The pre-scan's fatal count contains only unresolved violations; resolved
collisions are tracked separately (with bounded diagnostics where useful) and
must not be allowed to make the old `total_count != 0` gate reject a successful
resolution.

### F-7 — Resume and reconciliation

Each invocation recomputes the plan from the complete current source set. Adding
or removing a sibling can renumber a collision group and therefore changes
physical paths; that is an explicit replacement, not an unchanged-entry skip.
The old physical nodes must be reconciled and must not survive as stale payload
after a successful finalization. The same rule applies when an interrupted
partial is adopted.

### F-8 — Source-change fail-closed behaviour

If capture observes a logical entry outside the plan, a planned entry disappears,
the source object no longer matches its snapshot/identity, or the reserved
physical name no longer passes the final destination check, capture fails
without fallback allocation and publishes no final container. Same-invocation
source drift is not silently reconciled.

### F-9 — Test-only boundary

The planner, assignment seams, and probe counters remain behind D14's test-only
boundary. Production portable dispatch stays disabled; no production override,
environment switch, or broad callback framework is introduced for testing.

### F-10 — Wire version

`SIDECAR_VERSION` advances from 1 to 2. The sidecar header, manifest
`sidecar_version`, writer, reader, state map, and restore path use the same v2
contract; `MANIFEST_CURRENT_VERSION` does not change. A legacy v1 sidecar is an
unknown version and is refused rather than being guessed into the new grammar.

**Why:** These decisions must be fixed before the codec and collision planner
are implemented. The wire field, the root namespace boundary, destination
measurement, and parent-prefix restore rule are format and safety contracts,
not implementation details that can be rediscovered independently in each
walker. Keeping the plan a pure function of the ordered source set gives fresh
and resume captures the same logical-to-physical mapping, while target-backed
candidate verification prevents a convenient ASCII assumption from becoming a
silent data-loss path.

**Rejected:** target-independent, computation-only suffix allocation, because an
ASCII suffix cannot prove non-ASCII folding; a suffix kept only in the sidecar
and omitted from the physical payload path, because payload lookup must use the
actual path on disk; an entry-local restore invariant, because an ancestor's
suffix is embedded in the entire descendant subtree; carrying the suffix to the
restore destination, because restore writes the logical name; and backward
compatibility with v1, because no released containers exist and v1 is explicitly
refused by the v2 grammar.

**Relationship:** D21 preserves D19 N-10's destination-backed measurement and
extends D19's N-2/N-8 `NAME_MAX`/`PATH_MAX` limits to include the suffix. It bumps
D17's sidecar v1 grammar to v2, generalizes N-4's physical/logical invariant to
the parent-prefix form, and remains subject to D14's test-only boundary. Root
payload paths remain governed by the manifest/root policy, hardlinks are deferred
to Phase G, and sparse-file layout remains deferred under D13.

### As-built (Phase F, 2026-08-10)

The host suite and `make check` (strict GCC and Clang, sanitizers, Valgrind, and
`-fanalyzer`) passed on Arch, Ubuntu, and Fedora against `c7896a0`, with no
compiler diagnostics, Valgrind errors, or sanitizer errors.

The VM gate exercised a real case-insensitive vfat destination. ASCII
`Foo`/`foo` and measured non-ASCII `café`/`CAFÉ` collisions were resolved with
deterministic suffixes. A real source `foo~1` file forced the plan to skip to
`%7E2`, and descendants (including a symlink) of a suffixed directory were
placed beneath the correct physical parent. A capture declaring
`case_sensitive=1` invented no suffixes.

Resume renumbering was also verified: adding a new sibling that sorts before an
existing owner released the owner's old physical name and moved it to its new
suffix-bearing name without changing its content. That path exposed and fixed
a real bug (`6e43026`, amended through `c7896a0`), and the correction was
verified on real vfat.

The F-5 root-payload namespace probe detected a measured root-pair collision on
a real case-insensitive destination, closing a gap that host tests could not
prove. Host-only scale tests kept collision-plan work within linear bounds for
4,000 entries and measured risk-11 renumbering cost for both a single entry and
a nested directory with 2,000 descendants.

Production portable dispatch remains disabled under D14; all of these paths are
reachable only through the existing test-only seam.

---

## D22 — 2026-08-11 — Hardlink handling: group reference, placeholder node, sticky-seed representative

**Status:** Implemented (Phase G closed 2026-08-13; as-built notes below)

**Decision:** Portable capture records the first-seen member of each `(st_dev,
st_ino)` group as a regular file and later members as hardlink records carrying
a group reference; every record still owns a payload node, with hardlink nodes
represented by empty placeholders. Portable restore replays the group with
`link()`. Native fresh capture preserves hardlink identity with real `link()`,
while native restore continues to duplicate because it reads no sidecar; resume
representatives are sticky-seeded from the existing sidecar state before the
walk.

### G-1 — Portable payload node: placeholder (D18 pattern)

Every hardlink record owns its own zero-byte payload node. The first-seen
representative carries the regular-file bytes; later hardlink members carry
empty placeholders, and restore creates the links between those nodes. This
keeps D18's live-key-to-payload-node invariant universal. Node-less records are
rejected because they would require a separate restore branch and break that
invariant. The rule does not alter D21 F-5's separate root-payload namespace.

### G-2 — Restore ordering: capture's first-seen-first order

The sidecar record order is authoritative: capture writes the first-seen
representative as `REGULAR` before its hardlink members. Restore trusts that
order, and a `HARDLINK` record whose referenced `REGULAR` record is absent is
malformed and refused fail-closed. A two-pass restore is rejected as replay
architecture bloat; deferred binding is rejected because it adds memory and
postpones an unresolved-reference failure until the end.

### G-3 — Cross-root reference validation

`hardlink_root_id` may refer to a different manifest root. Restore must verify
that the referenced root is present in the same container manifest before
following the group reference. A missing root makes the group malformed and is
refused fail-closed rather than guessed or silently copied.

### G-4 — Xattr only on the representative member

Capture collects extended attributes only for the first, `REGULAR` member; a
`HARDLINK` record carries no xattrs. Because restore's `link()` shares the
representative inode, its xattrs arrive automatically, so a second
`setxattr` on the linked member is unnecessary and introduces avoidable risk
under SELinux. A hardlink record with `xattr_count != 0` is malformed and is
refused. This closes the hardlink xattr-sharing debt left by D20 E-10.

### G-5 — Native fresh capture links; native restore duplicates

Native fresh capture preserves hardlink identity with a real `link()`: a later
occurrence of an already-seen `(st_dev, st_ino)` group links to the captured
representative instead of recopying its bytes. Native restore continues to
duplicate, as recorded by the sidecar plan's native column, because it has no
hardlink record and reads no sidecar; a manifest v2 for native restore is out
of scope. Native resume's stale/deleted handling remains Phase H's debt because
native capture keeps no committed-key log.

### G-6 — Resume representative stability: sticky-seed

`readdir()` order is not stable across runs, and the Phase F resume-renumbering
bug (`6e43026`) demonstrated the cost of treating a resumed walk as fresh. At
the point where `portable_owned_paths_load` already scans the sidecar once,
resume also reads each live entry's kind. A live `REGULAR` path that still
carries the same inode seeds that inode's representative in the map before the
walk, so other members encountered later become `HARDLINK` records
automatically. If the former representative is gone from the source, the map
starts empty for that inode and G-2's first-seen rule is the fallback. This
follows the proven `prepare_collision_relocations` pattern: read current state
from the sidecar first, then steer the walk.

**Why:** Hardlink identity is part of filesystem fidelity, so portable capture
must preserve one inode group without creating a second copy of its bytes or
silently losing the relationship. Empty placeholder nodes preserve D18's
universal payload invariant while record order gives restore a single-pass,
bounded binding rule. Manifest roots and representative-only xattrs keep
references and metadata explicit and fail-closed. Native capture can preserve
the relationship directly with `link()` without expanding native restore into
a sidecar reader, and sticky seeding prevents an unchanged resumed source from
being needlessly rewritten merely because directory enumeration order changed.

**Rejected:** node-less hardlink records, because they break D18's payload-node
invariant; two-pass restore, because it bloats the replay architecture; deferred
binding, because unresolved references would be discovered only after the walk;
rebuilding an empty inode map on every resume, because unstable enumeration can
flip the representative and force needless rewrites; and a manifest v2 for
native restore, because native restore does not consume sidecar state and that
compatibility expansion is outside G-5.

**Relationship:** D22 preserves D17/D18's metadata and payload-node invariant,
extends D19's encoded physical-path rules to hardlink groups, and closes the
xattr-sharing debt explicitly left by D20 E-10. D21's collision suffixes and
hardlink groups both shape the physical payload paths, while D14's test-only
boundary remains in force through Phase G. Native stale-entry reconciliation is
left to Phase H, and sparse-file handling remains governed by D13.

### As-built (Phase G, 2026-08-13)

The host suite and `make check` (strict GCC and Clang, sanitizers, Valgrind,
and `-fanalyzer`) passed cleanly against `2f6327f`, with no compiler
diagnostics, Valgrind errors, or sanitizer errors.

G-2's decision text states that restore "trusts" capture's first-seen-first
record order. Implementation-time investigation (G.3) found this assumption
does not hold: `sidecar_log_foreach` iterates the sidecar's state map in
hash-bucket order — a pure function of each entry's key hash, unrelated to
append order — and `replay_run`'s own pre-apply sort orders entries by path
depth then name, also unrelated to hardlink structure. No such order exists to
trust; reverting to a single ordered pass broke `test_hardlink_orchestration`
outright ("alias" sorts before "representative"). The as-built fix is not the
"two-pass restore" G-2 rejected — a wholesale second pass over the entire
entry set — but a targeted second pass restricted to `HARDLINK`-kind entries
only: `replay_run` applies every `REGULAR`, `SYMLINK`, and directory-prep
entry exactly as designed, then filters the same already-collected set for
`HARDLINK` entries and applies those once every representative is guaranteed
to be on disk. This costs one `O(n)` filter over data already in memory, not an
additional traversal. G-2's fail-closed missing-reference rule and its
rejection of deferred binding both hold as decided: reference resolution
happens eagerly during collection, before `replay_run` runs at all, so an
unresolved or malformed reference is refused before any hardlink-kind entry
is ever considered for application.

G-1, G-3, G-4, G-5, and G-6 matched their locked text with no corrections
needed at implementation time; G-6's sticky-seed fallback was specifically
traced across all four representative/member presence combinations across a
resume boundary and found to already cover every one without additional code.

The VM gate exercised real hardlink pairs on Arch, Ubuntu, and Fedora: a
native capture (real `link()`) and a portable capture+replay (real sidecar
`HARDLINK` record + `linkat()`) both correctly shared one inode across two
separate manifest roots on a real ext4 destination
(`hardlink-native-portable-seam`); a portable `HARDLINK` record replayed onto a
real vfat destination — which cannot `linkat()` — failed with an honest
partial count rather than a silent fallback or a false success
(`portable-hardlink-vfat-dest`); and on Fedora specifically, a native
hardlink alias's `security.selinux` label was confirmed genuinely automatic
through the shared inode, with no second `setxattr` call
(`hardlink-selinux-xattr-sharing`; correctly a no-op on Arch/Ubuntu, which
carry no automatic security labelling). A full regression pass of every
existing VM-gate scenario also ran clean on all three VMs alongside these
three.

Host-only scale tests (5,000 real hardlink pairs) kept the pre-scan inode set,
the capture-time inode map, and the resume sticky-seed pass within their
linear probe budgets; mutating the inode map's hash function to a constant
confirmed the O(n²) guard actually fires (~25 million probes, four assertions
broken).

Production portable dispatch remains disabled under D14; every path above is
reachable only through the existing test-only seam.

---

## D23 — 2026-08-13 — Native stale reconciliation without a new log format

**Status:** Implemented (Phase H closed 2026-08-14; as-built notes below)

**Decision:** Native resume keeps the existing nsec-gated content-resume
oracle and reconciles stale destination entries by scanning the destination
tree directly after a clean capture of every root. The destination tree is
the complete record of what was captured; no additional committed-key log or
wire format is introduced.

### H-1 — Native resume-skip remains nsec-exact

Native content resume-skip is allowed only when `nsec_exact` is true and the
source and destination agree on size, `mtime_sec`, and `mtime_nsec`. Otherwise
the content is copied again. The existing nsec-exact-gated comparison in
`src/fileops.c` remains unchanged. A destination that cannot prove
nsec-granular timestamp round-trip therefore cannot take the skip path and
falls back to a safe recopy.

### H-2 — Reconcile stale entries by scanning the destination tree

After all roots' capture completes cleanly, each root's destination subtree is
scanned directly with the established `openat`/`fstatat`/`O_NOFOLLOW`
discipline. Every relative path absent from the walk's visited-set is stale
and is deleted. Native `data/<root>` has no percent-encoding or collision
suffix, so its destination tree is a lossless one-to-one mirror of the
captured source. There is no committed-key log, new wire format,
truncation rule, or log commit-ordering requirement.

A deletion interrupted halfway through is found again on the next resume:
the destination tree is rescanned, and deletion is idempotent because an
already-absent entry is tolerated as `ENOENT`.

### H-3 — Deletion safety and fail-closed boundaries

Deletion is permitted only for destination entries absent from the visited-set
and only after a clean walk. Although a root that completes cleanly has its own
complete visited-set, deletion is withheld for every root until all roots
succeed, as a deliberate additional safety margin rather than something the
incomplete root's data alone would require. The capture path therefore keeps a
single cumulative error flag across all roots; only when it is clear does the
scan-and-delete phase begin.

The per-root scan is safe because source `capture_path` overlap is already
rejected by `validate_no_duplicates_or_overlap` in `src/backup_plan.c`, while
destination `payload_path` uniqueness is guaranteed structurally by the root
naming scheme rather than checked as a runtime overlap condition.

Sockets and device nodes are skipped by native capture with a warning rather
than failing the enclosing directory, and are not recorded in the visited-set.
If a source path is now a socket or device node, the corresponding destination
path must therefore be absent after reconciliation; an older regular file at
that path must not be preserved as visited.

Only user-derived objects below `data/` are eligible for this reconciliation;
the container root remains migr-owned. Deletion uses `unlinkat`/`rmdir` with
`AT_SYMLINK_NOFOLLOW` and never follows a symlink. Directories are deleted
post-order. Any deletion failure sets the cumulative error flag and blocks
finalization, so deleted files or subtrees cannot survive a successfully
resumed final backup.

### H-4 — No commit-ordering discipline

There is no log whose records must be ordered against payload mutation. The
destination tree is, at every moment, the complete and consistent record of
what was actually captured. A half-finished deletion is handled by H-2's
next-run rescan and does not require a separate commit protocol.

The "committed key log" wording in D17 and D22 G-5 denotes a
state-comparison capability, not a literal file format. D23 satisfies that
requirement with the visited-set compared against the destination tree and
introduces no new on-disk format.

**Why:** Native capture already has a lossless destination namespace and a
resume oracle for content. A post-walk comparison against a visited-set makes
stale-entry removal explicit while preserving interruption safety: an
incomplete walk cannot authorize deletion, and an interrupted deletion is
rediscovered on the next run. The nsec-exact gate prevents a coarse timestamp
filesystem from being treated as safely resumable.

**Rejected:** A committed-key log plus a destination diff is rejected because
it would add another file format, writer and reader, truncated-tail recovery
rules, and commit-ordering discipline without providing information the
destination tree does not already contain. Deleting each stale entry during
the capture walk is rejected because it is more invasive and can leave a
half-deleted tree when the process is interrupted.

**Relationship:** D23 preserves D6's resume-oracle rationale: the sidecar has
the true size and mtime, while native resume takes its skip path only under
the measured `nsec_exact` gate. It assigns the native stale-entry gap noted in
D17 to a direct destination-tree comparison, keeps D17's nsec-exact skip
unchanged, and supplies the deletion acceptance condition described there.
It uses D15's container ownership and `data/` boundary, and gives the same
"without a committed key log" wording in D22 G-5 its concrete visited-set
meaning. D14 continues to keep portable dispatch test-only; H's reconciliation
is native production-path work, while direct portable dispatch remains
disabled.

### As-built (Phase H, 2026-08-14)

The host suite and `make check` (strict GCC and Clang, sanitizers,
Valgrind, and `-fanalyzer`) passed cleanly against `bbdcc02`, with no
compiler diagnostics, Valgrind errors, or sanitizer errors.

H-1 through H-4 matched their locked text with no corrections needed at
implementation time -- unlike D22's G-2, nothing decided here turned out to
rest on a false premise once built.

One narrow, deliberately-unaddressed edge case was found and left as
recorded debt rather than fixed: `native_reconcile_stale_at` (`fileops.c`)
returns an error, rather than treating it as a no-op success, when a root
is both absent from the visited-set *and* absent from the destination
entirely (`fstatat` `ENOENT`). The only way to reach that combination is a
root whose source object changes to a socket or device node between plan
validation and actual capture -- a TOCTOU race outside this project's
stated threat model (D17's "no realistic attacker scenario" reasoning),
since `root_type_allowed` (`backup_plan.c`) already refuses to construct a
socket/device-node root in the first place. The existing "a root that was
never part of this run's own capture fails closed rather than being treated
as empty" behavior is deliberately conservative and a real test locks it in
on purpose; a clean fix would need the caller to distinguish "genuinely
attempted and skipped this run" from "never part of the plan," which the
current API does not do.

The VM gate (Arch, Ubuntu, Fedora) exercised native stale reconciliation on
real ext4 and btrfs (Arch's minimal image ships no btrfs-progs; recorded as
not-applicable there, not a failure): a file deleted from source between a
captured run and its resume is absent from the resumed final backup on
both filesystems. A real `SIGKILL` mid-resume -- interrupting a run that
had both fresh content still to capture and stale content still to
reconcile -- specifically verified H-2/H-4's central claim that an
interrupted deletion needs no commit protocol: the next clean resume
converged to the fully correct final state (every stale survivor gone,
every fresh file present) with no special recovery path, exactly as H-4
predicted. A full regression pass of every existing VM-gate scenario also
ran clean on all three VMs alongside these.

Host-only scale tests (20,000 captured objects) kept the visited-set's
insertion and reconciliation's lookup within linear probe budgets in both
directions; mutating the visited-set's hash function to a constant
confirmed the O(n²) guard actually fires (~200 million probes, all four
assertions broken).

Unlike the D14 test-only seam every portable-representation paragraph in
this file and the README is gated behind, this phase's reconciliation is
native production-path work: it runs on every real backup today, not only
through a test-only entry point.

---

## D24 — 2026-08-19 — Production portable dispatch enablement

**Status:** Implemented

### As-built (2026-08-22)

The atomic activation commit `383d338` opened production portable dispatch:
`backup()` and `restore()` now route a `CLONE_PORTABLE_SIDECAR` verdict through
the portable engines, live and dry-run paths use the real destination probes,
and package handling stays in the shared control slot, with restore invoking it
only after a complete file replay. At the current `8e70c0d` HEAD, `make clean
&& make test`, `make check-strict` under GCC and Clang, `make check-analyze`,
and `make check-valgrind` all pass; the root-gated real-vfat smoke was skipped
here because loop/mount setup requires root, alongside the suite's expected
privilege- and fixture-dependent skips.

The Arch/Ubuntu/Fedora libvirt matrix exercised the production CLI against real
loopback vfat for resume and SIGKILL recovery, dry-run/live parity for case
collisions and unresolvable names, package install/restore, and a real Fedora
SELinux label round-trip. A physical exFAT USB drive was then moved between the
three running VMs: the cross-machine Arch → Ubuntu → Fedora → Arch chain and
Fedora, Arch, and Ubuntu same-distro round trips each restored all 23940/23940
items, with file counts and sizes checked after every leg.

Three narrow bugs found during that live testing are fixed in the history:
`f6bbbe7` resolves `ROOT_POLICY_XDG` destinations instead of flattening them
into `$HOME`; `e66eb4f` makes cross-policy `security.*` apply refusals visible
and non-fatal (D20 E-11); and `8e70c0d` names HOME-relative/XDG anchor failures
with their offending logical path instead of using a generic preflight example.

**Decision:** D14's refusal of a portable verdict is lifted for production
`backup()` and `restore()`. Once the activation commit (I.2, below) lands, a
destination that `select_representation()` classifies as
`CLONE_PORTABLE_SIDECAR` is captured and restored through the portable engine
built across Phases B–H, instead of being refused. This entry locks the
adapter contract that connects that already-built, already-tested engine to
the production CLI; it introduces no new sidecar or manifest wire format, and
does not reopen `select_representation()`'s own decision matrix (D14).

### I-1 — Backup dispatches inside `backup()`

The container reserve/adopt/finalize lifecycle stays representation-agnostic,
exactly as D15 established it. The native/portable split is confined to
manifest and payload-namespace ownership and to the capture engine invoked;
there is no separate `backup_portable()` duplicating the shared lifecycle.

### I-2 — Restore dispatches inside `restore()`

When the manifest is valid and its representation is portable, native payload
validation, native metadata inventory, native timestamp-anchor probing, and
native confirmation do not run; the portable branch never re-enters the
native preflight chain. Fd/cleanup code may be shared where genuinely common;
the two preflight chains, being semantically distinct, are never interleaved.

### I-3 — `packages.txt` is representation-independent

Portable backup writes the package list into the same control slot native
backup already uses. Portable restore applies packages only after file
replay has completed fully successfully; a cancelled confirmation or a
replay error never reaches the packages call.

### I-4 — Representation and case behavior are measured, never predicted

Both a live run and a dry-run run the real `fsprobe()`, and — on a portable
verdict — the real destination-backed case-collision probe, against the
actual destination. A resolvable case collision is recorded but not fatal; a
violation counted in `PortablePrescanReport.unresolved_count` (an
unrepresentable name, an oversized path, a root-namespace collision) is
fatal. `total_count` alone never refuses a capture.

### I-6 — Dry-run runs the real pre-mutation probe gates

Dry-run creates no container, payload, or package list, but it runs the same
temporary, self-cleaning filesystem round-trips a live run would, so its
report is actually true rather than assumed: the full destination capability
probe on backup; the privilege-relevant `O_TMPFILE` ownership probe on a
native backup profile; the timestamp-anchor and metadata-ownership probes on
native restore; the timestamp and ownership probes on portable restore; the
destination-backed case/root-namespace probe on a portable backup. Dry-run
never asks for confirmation. A probe refusal produces the same nonzero
result a live run would produce for the same destination. This is a
measurement of the current, real state only: it makes no promise about a
later source TOCTOU, a later I/O error, or data that changes between the
dry-run probe and a subsequent live capture.

### Destination identity is fd-anchored, never re-resolved by path

The capability probe, the prepared portable plan, and the container
reservation/adoption claim all consume one destination-root file descriptor
opened once, not a path string resolved independently by each step. A
path-based `fsprobe(path, ...)` and path-based container reserve/adopt remain
as compatibility wrappers around the fd-anchored primitives, but production
`backup()` calls the fd-anchored form. This closes a real gap: today
`fsprobe(target)`, `container_adopt(target)`, and `container_reserve(target)`
each re-resolve `target` from its path independently, so a symlink swap
between calls could let a destination the probe measured as native silently
diverge from the destination the container is actually written into.

### Portable capture prepares a complete, exact plan before any container reservation

The mandatory pre-scan and the expected manifest (built once, from the
portable capture request, through the one builder portable capture already
uses) are produced together, against the destination or its nearest existing
parent, before `container_reserve`/`container_adopt` runs. Fresh capture,
resume comparison, and container adoption all consume that same prepared
object; none of them constructs a second, independent copy of the expected
manifest. This closes two related gaps: first, the manifest `backup()` itself
has always built for resume comparison hard-codes `sidecar_version = 0`
(correct for native, wrong for portable, since the portable engine's own
manifest carries the current sidecar wire version), which would make a
portable partial's identity never match on resume; second, running the
portable engine's own deterministic pre-scan only after `container_reserve`
has already claimed a `.partial` directory would leave a manifest-less,
unadoptable partial behind on every deterministic refusal (an
unrepresentable name, for instance), since a container is only resumable
once its manifest has been written.

### Portable restore reports one of four distinct outcomes

Portable restore orchestration distinguishes completion, a dry-run preview, a
user's cancellation, and a preflight/probe/replay error as four separate
results — not, as today's direct API does, the same return value for a
genuine success and a user declining the confirmation prompt. `restore()`
owns interpreting that outcome, dispatching packages only on completion
(previewing them only on dry-run), and printing the one final summary; the
portable engine itself never prints a second "complete" line. Restore's
destination timestamp policy is measured for real, by the same fd-anchored
timestamp probe the engine's own tests already exercise, run by the
orchestration itself after confirmation and before the first persistent
mutation — production never accepts an injected or predicted timestamp
policy, matching D14's standing prohibition on any override.

### Commit discipline: one atomic activation, no partial public dispatch

The adapter contracts above are built and proven in commits that change no
CLI-visible behavior (the portable and native refusals stay in place while
the underlying primitives are readied and independently tested). Production
dispatch itself — backup, restore, dry-run, packages, and the minimal
public-surface correction (`--help`, README, and the two source comments in
`portable.h`/`portable_restore.h` that currently and correctly say production
never calls these entry points) — opens together, in one commit. No
committed state exists in which `migr backup` can write a portable container
that `migr restore` cannot yet read back, or in which dry-run's preview and
backup's live behavior disagree about representation.

### Dry-run's persistent-effect claim is scoped honestly

Dry-run's probes create and remove real, named scratch objects on the
destination (or its parent, for a destination that does not yet exist);
every one is removed on every success and failure path. What is guaranteed
is that no persistent container, `.partial`, manifest, sidecar, payload, or
package file is left behind — not that the destination filesystem is
completely unaffected, since a probe's own create/remove pair can still
change a parent directory's ctime. Documentation states the former, not the
latter.

**Why:** The portable engine has been built and tested end to end since
Phase B, entirely behind D14's test-only seam; the sidecar branch's own
stated purpose (D6) is not complete until a user can actually reach it.
Locking the adapter contract before writing it prevents exactly the class of
defect a live-code review of the naive integration surfaced: a
resume-identity field silently left at its native default, a native-only
preflight applied where it does not belong, a success path with no way to
report what it did, and container/probe/plan identity resolved by path more
than once. Requiring one atomic activation commit, after readiness work that
changes nothing observable, is the same "an incomplete state must never look
complete" discipline D15 already applies to the container itself, applied
here to the commit history around it.

**Rejected:** Separate `backup_portable()`/`restore_portable()` functions
duplicating the container lifecycle, rejected as unnecessary copying once
that lifecycle is confirmed representation-agnostic. Landing backup dispatch
and restore dispatch as two separate, individually-green commits, rejected
because the intermediate state is a green build that cannot read back what
it just wrote. Treating `fsprobe(path)`/`container_adopt(path)`/
`container_reserve(path)`'s independent path re-resolution as acceptable,
rejected once it was shown to open a real TOCTOU window between what was
measured and what is written. Continuing to build a second, independent
expected-manifest copy in `backup()` itself, rejected in favor of one shared
builder, once the existing `sidecar_version` default was shown to break
portable resume identity silently. A blanket "dry-run never touches the
destination" claim, rejected as stronger than what the implementation
actually provides once dry-run began running real probes to keep its
preview honest.

**Relationship:** D24 lifts D14's production-disabled boundary for the
`CLONE_PORTABLE_SIDECAR` verdict once the activation commit described here
lands; D14's own text is unchanged, per this file's append-only rule, and
its selector logic (`fsprobe`/`select_representation`) is not reopened by
this entry. It reuses D15's `data/`-namespace and atomic-finalization
container lifecycle without modification and depends on D16's
root-addressing policy for the `MANUAL_NATIVE` refusal, which portable
capture continues to enforce. It relies on D17's resume-identity comparison
(extending its exactness to the sidecar-version field for a portable
partial) and on D19–D23's already-locked portable capture, illegal-name,
case-collision, hardlink, and native-reconciliation contracts, none of which
this entry revisits. Native restore's own hardlink-identity duplication
(D22 G-5) remains open and is not touched by this entry; closing it, if it
happens, is separate work.

## D25 — 2026-08-20 — Portable resume uses write-ahead ownership claims

**Status:** Implemented

### As-built (2026-08-21)

On the Fedora Linux 44 host, the complete suite passed with `make clean &&
make test`, `make check-strict` (GCC and Clang), `make check-analyze`, and
`make check-valgrind`. `make check-sanitize`, the sanitizer stage of `make
check`, was also run; its first test stopped before any assertion because
LeakSanitizer cannot run under this host's ptrace execution environment. An
equivalent ASan/UBSan full-suite run with `detect_leaks=0` passed; that confirms sanitizer
execution but does not provide leak validation. The 15-row D25 acceptance
matrix is fully evidenced: codec and tail boundaries; replay/state transitions;
per-kind fresh and SIGKILL recovery, including the nested three-CLAIM
ancestor case; replacement, stale cleanup, collision and hardlink recovery;
repeated interruption; zero-claim capture and restore gates; and foreign-node
refusal. Production portable dispatch is already active on this branch through
D24; D25 changes neither representation selection nor dispatch. The real-vfat
SIGKILL/resume VM gate remains separate, deferred host/VM smoke-test work.

**Decision:** Portable capture closes the interval between payload mutation and
the sidecar's normal live-state commit with a standalone, write-ahead
`CLAIM` record. A claim is durable ownership proof for one payload node; it is
not a live restore entry, evidence that the payload is complete, permission to
skip source or payload validation, preliminary directory metadata, or a
replacement for the normal post-order directory entry. `ENTRY_COMMIT` remains
the only operation that makes an `ENTRY` group live. Directory metadata and
xattrs remain post-order, and this decision adds no new process-interruption
or power-loss durability guarantee: the existing no-`fsync` boundary remains
unchanged.

### Wire record

Sidecar version 3 retains the v2 grammar and adds exactly one standalone
record; no parallel spelling or alias is supported:

```text
CLAIM:
  tag, root_id, logical_path, physical_path, object_kind
```

The tag is `CLAIM\0`. Every field uses the existing NUL-framed string rules,
field ceilings, allocation ceilings, and total-byte ceilings. `root_id` is
non-empty; root logical and physical paths may be empty as they are elsewhere
in the grammar. Valid claim kinds are the four portable payload-producing
kinds: `regular`, `directory`, `symlink`, and `hardlink`. FIFO remains
unsupported by portable capture and is not made claim-capable by this
decision. Socket and device nodes publish no portable payload and receive no
claim.

`physical_path` already contains any D21 collision suffix; `CLAIM` does not
duplicate `collision_suffix`. A complete claim becomes committed at the end of
`object_kind` and advances `last_valid_boundary`. A claim cut short by EOF is
a truncated tail. No payload mutation may follow a writer call that did not
finish the claim. A malformed complete claim, an unknown tag or kind, or a
claim interleaved inside a pending `ENTRY`/`XATTR`/`ENTRY_COMMIT` group is
corruption.

The append-only file retains historical consumed claims. “Zero outstanding
claims” refers to replayed state, not to the absence of `CLAIM` bytes in the
file.

### Claim state machine

The protocol specifies semantic transitions, not whether the implementation
uses one map or separate live and claim maps:

| Current semantic state | Record | Required result |
| --- | --- | --- |
| No live entry and no claim, or a tombstone with no claim | `CLAIM(C)` | `C` becomes the one outstanding claim for the key; an older tombstone may remain as history. |
| Live entry exists | `CLAIM` | Invalid/corrupt. The writer must first perform D17's `DELETE`. |
| A claim is already outstanding | another `CLAIM` | Invalid/corrupt, even if byte-identical. Resume reuses the matching claim. |
| Matching claim `C` and a completed matching `ENTRY(E)` group | `ENTRY_COMMIT` | Consume `C`, replace prior tombstone state, and make `E` live. |
| No claim, or a claim mismatching the pending entry | `ENTRY_COMMIT` | Invalid/corrupt; no live state is produced. |
| Live entry, no claim | `DELETE(key)` | Existing D17 transition: the live entry becomes tombstoned. |
| Outstanding claim | `DELETE(key)` | Cancel the claim without creating a live entry; any older tombstone remains. |
| No live entry or claim | `DELETE(key)` | Existing idempotent no-op behaviour. |

A claim and its consuming entry must match byte-for-byte on:

```text
root_id, logical_path, physical_path, object_kind
```

At most one outstanding claim may exist per logical key. Active physical
ownership must also remain unambiguous: a claim cannot authorize a physical
path currently owned by a different logical key. Claims consume the existing
path, total-byte, allocation, and live-entry resource ceilings; outstanding
claim cardinality is bounded by the existing live-entry ceiling.

D17's reader tolerance for a duplicate committed entry without an intervening
`DELETE` does not authorize a claimless v3 commit. Every v3
`ENTRY_COMMIT`, including a same-key replacement, requires its own matching
outstanding claim.

### Claim cancellation and cleanup

No `CLAIM_CANCEL` or `ABORT` record is introduced. `DELETE(root_id,
logical_path)` is also the committed transition that cancels an outstanding
claim when no `ENTRY_COMMIT` will follow, including when the source node
disappears or changes kind, or when the current collision plan assigns a
different physical path.

Because a claim is ownership proof, cleanup follows this order:

1. Remove the exact claimed payload node while the claim is still outstanding.
2. Append `DELETE` to cancel the claim.
3. If either step fails, return failure and leave the partial resumable.

This order ensures that a successfully cancelled claim cannot leave its
payload node unowned. If removal succeeds but interruption occurs before
`DELETE`, the surviving claim safely authorizes an idempotent retry against an
absent node.

A directory claim owns the directory node, not arbitrary contents beneath it.
Directory cleanup therefore reconciles known live and claimed descendants
deepest-first and removes the directory non-recursively. An unknown or foreign
child blocks cleanup; recursively deleting everything merely because the
parent is claimed is forbidden by D21's ownership rule.

### Capture ordering

For every capture path that will mutate a payload, the required order is:

1. Derive and validate the current source kind and collision-plan assignment.
2. Reconcile any existing mismatching or stale claim.
3. Before writing a new claim, establish that the destination is absent or is
   already owned by the same logical node through a matching live entry,
   tombstone, or exact outstanding claim.
4. If replacing live state, commit D17's `DELETE` first.
5. Append a new exact `CLAIM`, or reuse an already-outstanding exact claim.
6. Only then perform the first mutation of the claimed payload path.
7. Complete source-stability checks and payload work.
8. Append the normal `ENTRY`/`XATTR`/`ENTRY_COMMIT` group; the commit consumes
   the claim.

Writing a claim never legitimizes a pre-existing foreign node. The foreign-node
check precedes creation of a new claim. D17's old-path deletion remains valid:
mutation that removes an old live physical path is authorized by its committed
tombstone; the claim authorizes mutation of the new/current physical path.

The node-specific consequences are:

- **Directory:** the claim precedes `ensure_directory_leaf()`/`mkdirat()` and
  remains outstanding throughout child traversal. The normal directory entry
  remains post-order and consumes the claim.
- **Regular file:** the claim precedes removal, creation, truncation, or write
  of the destination regular file.
- **Symlink:** the claim kind is `symlink`, although portable payload is an
  ordinary placeholder; the claim precedes placeholder replacement.
- **Hardlink:** the claim kind is `hardlink`; the claim precedes empty
  placeholder replacement.
- **Unchanged live entry:** an existing no-mutation fast path needs no new
  claim.
- **Socket/device and FIFO:** these publish no new portable payload entry and
  gain no claim; FIFO remains fail-closed.

### Resume and stale-claim reconciliation

A claim is acceptable ownership proof only when it exactly matches the current
`root_id`, `logical_path`, `physical_path`, and `object_kind`, and the current
D21 collision plan still assigns that physical path to the same logical node.

For an exact claim:

- an absent payload node is valid and resume recreates it;
- an existing payload node is considered owned and may be replaced or
  completed;
- payload content is not assumed complete and normal capture validation still
  runs;
- resume reuses the claim instead of appending a duplicate.

A mismatching or stale claim is never transferred to another logical identity.
The current plan remains authoritative; a claim does not pin or override an
obsolete collision assignment. Its old physical node is cleaned using the
claim as ownership proof, `DELETE` then cancels the claim, and only afterward
may a new claim be written for the current assignment.

Reconciliation includes outstanding claims, not merely the live entries
currently traversed by the sidecar live-entry iterator. This is required for
source deletion and collision renumbering when the new source walk will never
visit the old claimed node.

### Completion and restore gates

A structurally valid log with outstanding claims is a valid resumable partial,
not generic sidecar corruption. Therefore adoption exposes outstanding claims,
and closing a failed capture is allowed to leave them in a resumable partial.
Claims are excluded from live-entry iteration and from
`sidecar_log_live_count()`.

Successful capture requires exact payload inventory **and zero outstanding
claims**. The zero-claim check is global, after all roots and their
reconciliation have completed, and before the prepared fresh or resume entry
point returns success or reports `live_count`. It is not enforced inside an
individual root capture because a resumed multi-root container may still carry
legitimate claims for roots not yet processed.

Portable restore preflight refuses a sidecar with any outstanding claim before
destination probing or mutation. `portable_restore_replay_at()` independently
enforces the same condition before its capability probe or replay, because it
is callable separately from orchestration. Consumed historical claims are
ignored; only outstanding replay state is fatal for restore.

### Version boundary

D25 advances `SIDECAR_VERSION` from 2 to 3. The header writer, parser, state
loader, manifest `sidecar_version`, capture path, and both restore paths move
together. `MANIFEST_CURRENT_VERSION` does not change.

There is no v2 compatibility layer: completed v2 containers are refused by
the v3 reader, v2 partials are not resumed as v3, and no dual reader,
migration path, or guessed recovery is introduced. Manifest resume identity
already includes `sidecar_version`. This is an intentional pre-release format
replacement: the branch has not merged to `main`, no release tag or real user
base exists, and an unsafe v2 partial cannot supply the missing ownership
proof.

### Acceptance boundary

Implementation is not complete until tests prove, at minimum:

- claim codec round-trip, field ceilings, supported-kind validation, and
  illegal ordering;
- complete, mid-record, and truncated-claim tail behaviour;
- adoption retaining an outstanding claim;
- matching commit consumption;
- claims with missing or mismatching entries being refused;
- duplicate and conflicting claim refusal;
- `DELETE` cancellation and restart-idempotent cleanup;
- fresh directory, regular, symlink, and hardlink interruption recovery at
  every applicable mutation boundary;
- empty-directory and nested traversal recovery with multiple active ancestor
  claims;
- replacement with a committed predecessor;
- source deletion, kind change, and collision renumbering with an outstanding
  claim;
- repeated SIGKILL/resume cycles;
- capture success/finalization refusal while any claim remains;
- portable restore preflight and standalone replay refusal without destination
  mutation;
- a genuinely foreign existing node without matching live, tombstone, or claim
  proof remaining refused.

Shared codec boundaries need not be multiplied mechanically when one state test
proves the common primitive, but each node kind must directly prove that its
first applicable payload mutation occurs only after a committed claim. The
real-vfat SIGKILL/resume scenario remains part of the later VM gate.

**Why:** D17's payload-first/live-last ordering is necessary to prevent
incomplete bytes from becoming restore-visible metadata, but it leaves a
window in which a newly created payload has no durable ownership proof. A
positive write-ahead claim closes that ownership window without relaxing the
foreign-node safety rule: the destination is still checked before a new claim
is written, and a claim authorizes only its exact logical/physical identity.
The normal post-order entry remains the completeness and restore boundary.

**Rejected:** Directory-only tracking or an early normal `DIRECTORY` entry is
rejected because it leaves regular, symlink, and hardlink gaps and conflates
ownership with completeness. Treating every existing directory or payload
node as safe is rejected because it permits foreign-node overwrite and
collision-plan cross-contamination. Inferring ownership from descendants or
from the current collision plan is rejected because it fails for empty or
fresh nodes, and a desired mapping is not evidence of who created an existing
node. Relying on collision relocation or final inventory alone is rejected
because both occur too late to authorize the first mutation and currently
begin from live state. Reusing normal `ENTRY_COMMIT` before payload completion
is rejected because it reverses D17 and can expose incomplete bytes as live
metadata. Extending v2 in place, temporary multi-version negotiation, and a
test-only version path are rejected because they would make the on-disk
boundary ambiguous. A new cancellation record is rejected because existing
`DELETE` can cancel a claim safely. Power-loss durability via `fsync` remains
outside D17 and is not introduced here.

**Relationship:** D25 refines D17's process-interruption and commit protocol
without changing its live-state, metadata, or no-`fsync` boundaries. It
advances D21's v2 grammar to v3 while preserving collision suffixes and
destination authority, including D21's refusal to overwrite unowned names.
It covers D22's regular and hardlink placeholder model without changing
restore ordering or sticky representatives. It completes D24's now-production
portable path without changing representation selection or D15's
representation-agnostic finalization lifecycle. It has no effect on native
capture or native restore.

---

## D26 — 2026-08-22 — Native hardlink resume seeding and restore relinking

**Status:** Implemented

**Decision:** Native capture and restore both preserve hardlink identity without
introducing a native sidecar or manifest extension. When resuming an adopted
native partial, capture performs a read-only source/destination pre-seed of the
existing resume-matching regular payloads into the existing `(st_dev, st_ino)`
inode map before the live walk. Native `restore()` unconditionally performs
the same read-only pre-seed for every automatically restored root, then owns
one inode map for the whole apply phase; the first successfully applied member
of a source inode group becomes its destination representative, and later
members are created with `linkat()` to that representative.

### Native capture resume

The old native capture map was process-local and empty on every invocation. If
the resumed walk visited a missing sibling before the member written by the
interrupted run, it could select a new representative and then fail against
the old independent destination file. Adopted native capture now walks the
source and existing destination addresses without mutation before capturing.
Every existing regular destination whose size and nsec-gated mtime prove the
completed-work resume oracle seeds the source inode's representative. A seed
failure aborts the resumed native capture before payload mutation; fresh
capture remains unchanged, and no wire-format state is added.

### Native restore resume

A new restore process used to start with an empty inode map, so a hardlink
group split by interruption could be visited in the opposite order on the
next invocation: the new sibling became an independent representative and
the already restored member then failed the identity check. Before any native
apply walk, restore now scans the existing destination state for every
auto-restored v1 or legacy root and seeds the same source-inode map. This is
unconditional because restore has no reliable adopted-destination bit; the
scan is read-only and uses the destination root's preflighted timestamp
precision when deciding whether an existing regular payload proves completed
work. Nested destination paths and an already existing destination root are
resolved without creating or following intermediate symlinks. Dry-run and
validation still leave the map unused and mutation-free.

### Native restore apply contract

Validation and metadata inventory never mutate the inode map. During apply,
the first regular member is copied or resumed normally and enters the map only
after its payload and metadata succeed. A later member with the same source
inode is linked to that representative; it receives no second content,
metadata, or xattr write because the shared inode already carries the
representative's state. An existing destination at the sibling address is
accepted only when it is already the same inode; an independent or wrong-type
object is a failure, never an unlink-and-replace opportunity.

If a representative fails, no map entry is installed. The current recursive
walk stops its failed subtree; if a caller later retries another member with
the same map, that member may become a new independent representative rather
than linking to an unproven destination. This is fail-closed and prevents a
failed or partial representative from poisoning subsequent links.

This applies only to native payloads that still carry real shared inodes. A
native payload whose hardlinks were already flattened by another tool remains
indistinguishable from genuinely independent files and cannot be reconstructed
without additional format metadata. Portable capture and restore remain on
D22/D25's sidecar protocol.

**Why:** Native capture already preserves the relationship with `link()` and
the destination tree already supplies the only resume evidence needed; a
read-only sticky seed closes the process-boundary/order gap without a new
format. Native restore can use the source payload's inode identity directly,
and its pre-seeded process-wide apply map makes the same guarantee hold across
interrupted invocations while keeping representative-only metadata and xattrs
safe.

**Rejected:** Re-deriving hardlink groups from content, size, or timestamps is
rejected because independent files can share those values. A native sidecar or
manifest extension is rejected because native payload inode identity is already
available and native restore does not need portable state. Mutating the map
during validation is rejected because dry-run/preflight must remain
mutation-free. Replacing an independent sibling destination is rejected as
unsafe; it is reported as a collision instead.

**Relationship:** D26 closes D22 G-5's native-restore duplication debt and
extends D22 G-6's sticky-representative principle to the native destination
tree. It preserves D15's fd-anchored native walkers, D17's source-stability
checks, D23's nsec-gated native resume oracle, and D25's independent portable
claim protocol. The host interruption, restore identity/metadata/xattr, and
representative-failure tests cover the new invariants; the external VM gate
must additionally run a real native capture interruption/resume and a real
restore of a cross-root hardlink pair, checking `dev/ino/nlink`, mode,
uid/gid, and xattrs on both names.

---

## D27 — 2026-08-24 — Destination free-space preflight

**Status:** Implemented

**Decision:** Before reserving a backup container, backup estimates the
selected plan's source bytes and compares that estimate with the destination
filesystem's user-available free space. The check runs for live and --dry-run
invocations and is independent of backup mode, so critical, comprehensive, and
explicit-path plans all use the same preflight. A fitting backup prints both
the estimated size and available space; a plan that clearly does not fit is
refused before a container, manifest, or payload is written. If the estimate
cannot be completed because of a real source-side measurement error, the
preflight is skipped with a warning and the backup proceeds.

The comparison is exact: needed > available refuses, with no invented
percentage margin. The estimate remains approximate because sparse-file
allocation, filesystem metadata, xattr overhead, and representation details
can differ from the sum of source logical sizes. A guessed margin would add an
unexamined policy without making that approximation more truthful; tuning it
remains a separate evidence-based change.

The available-space calculation uses statfs.f_bavail, not statfs.f_bfree.
f_bavail reflects blocks available to migr as an unprivileged process,
whereas f_bfree also includes blocks reserved for root and can therefore
overstate what this invocation can consume. The filesystem fragment size is
preferred when reported; the block size is the fallback when the fragment size
is zero.

**Why:** The check is a cheap, destination-local guard against a clearly
undersized target while preserving the existing fail-open posture for an
incomplete advisory estimate: report.c already treats measurement failures
as an incomplete report rather than converting them into a hard refusal.
Running it in both live and dry-run paths follows D24's established rule that
dry-run performs the same destination preflight checks needed for an honest
preview.

**Rejected:** A safety-margin percentage is rejected because it would be a
guess layered on an already approximate estimate. f_bfree is rejected
because root-reserved blocks are not available to the ordinary process.
A bypass flag is not added; if operational evidence shows that users need one,
it is a separate decision rather than an implicit escape from this guard.

---

## D28 — 2026-08-24 — Interactive backup progress is informational and backup-only

**Status:** Implemented

**Decision:** A live backup counts successful regular-file content bytes and,
when stdout is an interactive terminal, periodically displays those bytes
against the D27 estimate together with freshly measured destination free space.
The callback is installed only behind the `isatty(stdout)` gate; it is not
installed for redirected, piped, or scripted output. Progress is sampled at
most every 500 ms and is driven from the byte-copy loops, so one large file
cannot make the display appear stalled until the next file. The free-space
re-read is informational only: a low observation does not create a second
abort path, and an actual write failure remains the authoritative ENOSPC
failure. This feature covers backup capture, not restore.

**Why:** Installing the callback only for an interactive terminal keeps the
existing machine-readable and test-captured output byte-stable while still
making the user-facing terminal useful. Chunk-level sampling is the smallest
granularity that gives honest movement for large files, and the 500 ms throttle
prevents terminal I/O from becoming hot-loop overhead. Reusing D27's estimate
keeps the denominator consistent with the preflight, while re-reading free
space exposes concurrent destination consumption without pretending that an
observation is a reservation.

**Rejected:** Installing the callback unconditionally and merely suppressing
its print calls is rejected because it would still add clock and callback
machinery to redirected/test runs and could leak carriage-return fragments
into captured output. A new free-space refusal based on periodic observations
is rejected because only the real write result can authoritatively determine
whether the copy fits. Restore progress is deferred as a separate feature.

---

## D29 — 2026-08-24 — Finalized containers cross a durable publication boundary

**Status:** Implemented

**Decision:** `container_finalize()` flushes the destination filesystem with
`syncfs(container->partial_fd)` before renaming a `.partial` container to its
final name. The pre-rename flush is fail-closed: a failure returns
`CONTAINER_ERR_IO`, does not attempt the rename, and leaves the partial and its
handle in the existing valid `CONTAINER_STATE_PARTIAL` contract. After a
successful `RENAME_NOREPLACE`, the handle becomes
`CONTAINER_STATE_FINALIZED`, and `fsync(container->dir_fd)` flushes the
destination directory so the publication rename itself reaches durable
directory metadata. A failure of that post-rename directory flush does not
turn the call into an error: the rename already succeeded and the payload was
confirmed durable before publication, so reporting an incomplete backup would
be false. At worst, a crash in that narrow window can make the durable payload
reappear under its resumable `.partial` name.

**Why:** The payload must be durable before a final-looking container is
published; otherwise a crash after rename could expose a completed-looking
backup with missing or truncated data. The rename then needs its own directory
flush because file-data durability does not make directory-entry metadata
durable. This gives users a meaningful boundary: after `Backup complete` is
printed, the destination has passed both flushes, while an interrupted run
before that point is still governed by the existing partial/resume protocol.

This decision does not make copying periodically durable and does not reduce
the in-flight loss window of a process interruption during capture. Periodic
syncing is a separate follow-up; D29 guarantees durability at successful
finalization, not at every intermediate point.

**Rejected:** Flushing only after the rename is rejected because it can expose
a final-named container before its payload is durable. Failing after a
successful rename when the directory flush fails is rejected because it would
misreport a real publication as incomplete and would not undo the already
durable payload. A new status value is unnecessary for that narrow metadata
durability edge.

**Relationship:** D29 refines D15's atomic container publication with a
durable publication sequence. It supersedes D25's earlier no-`fsync` boundary
for the container-finalization step only; D25's claim/replay protocol and its
interrupted-capture semantics remain unchanged. Restore finalization and
periodic capture syncing are outside this decision.

---

## D30 — 2026-08-24 — Periodic capture sync smooths backup writeback

**Status:** Implemented

**Decision:** During every live native or portable backup, migr accumulates
successful regular-file content bytes in the capture's shared
`BackupCaptureReport`. Once the accumulated amount reaches 8 MiB, it calls
`syncfs()` on the destination filesystem and resets the counter. The report
defaults to an interval of zero for direct/test callers, while production
live backup unconditionally enables `BACKUP_SYNC_INTERVAL_BYTES`; the setting
does not depend on whether stdout is a terminal. A periodic `syncfs()` failure
is an ordinary capture I/O failure and aborts the backup.

**Why:** `syncfs()` covers dirty pages belonging to the whole destination
filesystem, not only the file that happened to trigger the check. That matters
for both a single large file and the common many-small-files workload: a
per-file `fdatasync()` would not bound the accumulated dirty data across files.
The 8 MiB interval is a fixed compromise between keeping each writeback stall
small and avoiding enough sync calls to make their overhead significant on
slow removable media. The byte counter persists across files and roots so the
interval describes the whole capture rather than resetting at arbitrary file
boundaries.

The sync is unconditional because it changes backup behavior, not presentation.
Piped, redirected, and unattended backups receive the same reduced in-flight
loss window as interactive backups; `isatty()` remains appropriate only for
D28's informational progress display. No user-facing "syncing" message or
configuration flag is added.

**Relationship to D29:** D29's final `syncfs()` and post-rename directory
flush establish the durable publication boundary before `Backup complete` is
printed. D30 only smooths writeback during capture and reduces the amount of
data exposed to a mid-copy interruption; it does not make intermediate data
durable at every instant and does not replace D29's finalization sequence.

**Rejected:** Calling `fdatasync()` on each destination file is rejected
because it does not cover dirty pages accumulated across previously completed
files. Gating the sync on terminal output is rejected because the behavior is
correctness/reliability-related rather than UI-related. A configurable
interval remains deferred; the evidence here supports correcting the fixed
default rather than exposing an operational setting.

**Revision (2026-08-26):** Live testing on a real exFAT USB destination
showed that the original 8 MiB interval was too aggressive for a
metadata-heavy workload: more than 10,000 small files spent much of their
time in exFAT directory and FAT metadata work, while an independent sequential
write measured 45.3 MB/s, so the device's raw throughput was not the
bottleneck. The interval was roughly two orders of magnitude below the
system's typical dirty-page throttling scale
(`vm.dirty_ratio`/`vm.dirty_background_ratio`, hundreds of MiB to a few GiB
on the tested host) and caused `migr` to force writeback far more frequently
than necessary. `BACKUP_SYNC_INTERVAL_BYTES` is therefore raised from 8 MiB
to 256 MiB, moving the trigger closer to the kernel's natural scale while
retaining periodic smoothing for large captures. This reduces how often
`migr` enters a sync wait; it does not make an individual `syncfs()` wait
shorter or interruptible, so a metadata-heavy filesystem can still leave the
process in kernel-uninterruptible sleep during one sync.

---

## D31 — 2026-08-25 — Destination-allocation-aware, hardlink-deduplicated estimate

**Status:** Implemented

**Decision:** `backup_plan_estimate_size()` accepts a caller-supplied
destination allocation block size. Its backup-specific walker rounds each
regular file upward to that unit and counts a `(st_dev, st_ino)` hardlink group
once across the entire plan, including when the group crosses root boundaries.
Values <= 1 disable only the rounding; hardlink deduplication remains active.
The rounded estimate feeds D27's free-space preflight for native and portable
capture alike. D28's progress denominator uses a separate raw source-byte
estimate so the display describes transferred source content rather than
destination allocation.

The block size is read by `backup()` from the destination fd with the existing
`f_frsize`, then `f_bsize`, preference. The estimator itself remains entirely
source-side and deterministic for its inputs; it never performs destination
I/O. This adds one block-size `fstatfs()` beside the existing free-space
preflight's own query, rather than coupling the planner to a destination fd.

Only regular files receive allocation rounding. Symlinks and directories keep
their existing raw `st_size` contribution, while FIFOs, sockets, and device
nodes contribute zero. This is deliberate: regular-file allocation is the
representation-independent correction evidenced on large-cluster removable
media, whereas non-regular allocation can vary with the eventual native or
portable representation and was not part of that evidence.

**Why:** A live exFAT destination with 128 KiB clusters consumed materially
more space than the raw source-byte counter suggested, consistent with
per-file allocation rounding. A completed hardlink-heavy backup also reported
more estimated bytes than it physically copied because `get_dir_size()` counted
each linked name independently, while capture writes the shared content once.
Both errors affect the destination fit check, and both are independent of the
representation selected later in `backup()`.

The estimate uses a new local walker rather than changing `get_dir_size()`.
`get_dir_size()` remains the deliberately simple, raw, non-deduplicated walker
used by report output; `report.c`'s separate `measure_report_tree()` is the
established precedent for keeping a second walker when the accounting contract
differs. The estimate's small linear `(dev, ino)` set is retained for the whole
call, not reset per root, and entries from a root that fails measurement are
rolled back so an incomplete root cannot suppress a later contribution.

**Relationship to D27:** D31 refines only the per-file estimate formula. D27's
exact `needed > available` comparison, no-margin policy, and fail-open behavior
when source measurement is incomplete remain unchanged. D31 also makes D28's
progress denominator use raw source bytes; it does not change progress
presentation or D30's periodic durability sync.

**Rejected:** Retrofitting `get_dir_size()` is rejected because report's raw
logical-size contract is unrelated to backup destination allocation. A
representation-specific estimate is rejected because both allocation rounding
and hardlink sharing are established before native/portable selection and are
valid for either representation. Symlink/directory rounding is deferred until
their actual destination allocation semantics justify it.

**Revision (2026-08-26):** Allocation rounding is retained only for the
internal D27 free-space fit check. The user-facing `Estimated backup size`
line and D28's live `Progress` total now use the raw source-byte total instead
of destination-allocation-rounded bytes. This follows live testing on the same
Ventoy exFAT destination with 128 KiB clusters: a roughly 100M source backup
was displayed as 200.7M and a 646M source backup as 1.6G under the reverted
rounded-progress approach, inflating the apparent source size by roughly
2--2.5x.

---

## D32 — 2026-08-26 — Sidecar directory sizes are estimate-only

**Status:** Implemented

**Decision:** Sidecar `ENTRY` records may carry the source directory's
`st_size` in `size`. Native and portable restore free-space estimates include
those directory values alongside regular-file bytes and symlink target lengths.
The v1 wire encoding and directory restore semantics do not change; hardlinks
and symlinks continue to carry zero in `size`.

A recorded directory size is source-filesystem metadata, not portable directory
content. Restore must never compare it with a destination directory's
`st_size` during payload inventory or replay: directory layout and filesystem
representation make that value inherently non-reproducible. It is used only
to make the destination-space estimate consistent with backup's directory
accounting. This extends D17's core `size` contract without requiring a
`SIDECAR_VERSION` bump.

**Why:** The backup estimate already includes directory `st_size`, and omitting
it on restore makes the same captured tree use different space models in the
two directions. Allowing the recorded value through the writer, parser, and
state map preserves that accounting without turning a filesystem artifact into
an integrity claim.

**Rejected:** Comparing a restored directory's `st_size` with the recorded
source value is rejected because a correct restore can legitimately produce a
different directory representation. Directory sizes are not used as resume or
payload-content keys; only the free-space estimate consumes them.

**Relationship:** D32 extends D17's `size` rule for directory entries and
refines D27's restore-side estimate parity. D17's directory metadata and
post-order restore requirements remain unchanged.

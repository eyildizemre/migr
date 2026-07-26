# Sidecar — Implementation Plan

Working design document for the sidecar feature (see DECISIONS.md D6). This is
scaffolding: phases get checked off and details shift as reality pushes back. The
durable rationale lives in DECISIONS.md (D6, D13, and more as they are decided); this
file is the how, not the why.

This plan has been through three rounds of a longer, more maximalist external design
review. The review's architecture is declined (see "Declined" at the end), but it
earned its place: by dogfooding the current code it found **two verified
data-integrity bugs**, and by reading this plan closely it found real modelling errors
and design gaps. The throughline of every revision: **adopt what the review found,
decline the scale it assumes.** This is a full rewrite rather than a patch, because
incremental patching left the previous version self-contradictory.

---

## The central architectural fact

Before Phase A, `clone_recursive(src, dest)` was **symmetric and direction-agnostic**: both
backup and restore called it — backup.c in 2 places, restore.c in 3 — just copying a tree from
src to dest, the same code in both directions.

The sidecar is **inherently asymmetric**, and there is no single "one recursion with a
direction flag." There are **three orchestrations**, sharing low-level helpers (byte
copy, metadata apply/capture, encode/decode) but not one loop:

- **backup** — walk the source tree, capture each entry, write payload; in portable
  mode also write the sidecar;
- **native restore** — walk the backup tree, copy to home (today's behaviour, once
  brought up to full fidelity — see "Native mode" below);
- **portable restore** — **sidecar-driven**: iterate the sidecar and replay, because
  the physical names are encoded and the sidecar is authoritative.

Direction is an **explicit enum** (`CLONE_BACKUP` / `CLONE_RESTORE`) carried in a
`clone_ctx` struct, alongside the destination mode (native / portable), the roots, the
sidecar handle, capability flags, and hardlink state. No "null-ish" context is allowed
to imply behaviour by its absence. A "sink hierarchy" was proposed to express the three
orchestrations and is declined — three explicit loops over shared helpers achieve the
same separation without the class machinery.

---

## Prerequisites — data-plane bugs, fixed on `main` first

These are **not sidecar work.** They are real defects in the current copy engine,
verified by testing, that must be fixed before a sidecar is built on top — a format
layered over an engine that corrupts the source or hides errors is built on sand. Each
lands on `main` as its own commit with a regression test.

1. **Backup mutates the source through a symlink** (critical, security). `preserve_metadata`
   calls plain `chmod(dest, ...)` on a symlink path; `chmod` follows the link. For an
   absolute symlink, `dest` points at the real source file, so its mode is overwritten
   with the symlink's own `0777`. **Verified:** a source `target.txt` went `0600 → 0777`
   through a backup. For `.ssh` this both breaks the key and exposes it, and it violates
   the invariant that backup never modifies the source. Fix: type-aware metadata — never
   `chmod` a symlink path; use `fchmodat`/`AT_SYMLINK_NOFOLLOW` or skip mode on symlinks.
2. **Failed copies report success.** A recursive copy failure propagates a `-1` that
   `backup()` ignores; it still prints `Backup complete` and exits `0`. **Verified**
   with a FIFO. Sidecar finalization cannot be trusted until errors reach the CLI and
   prevent a "complete" verdict. Fix: propagate copy/metadata failures to the backup
   result and the exit code.
3. **Explicit-paths basename collision loses data.** Two explicit paths sharing a
   basename both clone to the same name; files overwrite, directories merge. **Verified:**
   `migr backup /dst ~/a/foo.txt ~/b/foo.txt` kept only one `foo.txt`, yet reported
   `2 items copied`. Explicit-paths mode also writes no manifest, so there is no
   disambiguation at all. Fix: detect the collision and refuse (or deterministically
   disambiguate) rather than silently overwrite.
4. **Unchecked `snprintf` path assembly.** `PATH_MAX` buffers are filled without checking
   for truncation, silently producing wrong paths. Low severity now, but filename
   encoding (Phase D) can expand a name past the buffer. Fix: check `snprintf` returns;
   consider `openat`/`fstatat` traversal longer term.
5. **Special files break the copy.** `clone_recursive` handles symlink/regular/directory
   and returns `-1` for anything else. A FIFO or socket — `.gnupg` contains sockets —
   aborts its subtree. **This fix needs the native/portable FIFO policy decided first**
   (see "Open decisions"): on `main` there is no portable mode, so the fix is native-only
   (skip sockets with a warning; `mkfifo` for FIFOs where the destination supports it;
   reject device nodes). The portable representation comes with the sidecar.

Items 1–4 can start immediately. Item 5 waits on one small policy decision.

---

## What still breaks on a lossy destination (the sidecar's job)

Beyond the bugs above, on exFAT/NTFS the engine loses metadata silently: `chmod`/
`utimensat` fail with their returns ignored, so permissions and timestamps vanish with
no error. `.ssh` restores as `0644` instead of `0600`. That silent loss is what the
sidecar repairs — in portable mode by recording it, and in native mode by actually
applying it (which today it does not; see below).

---

## Native mode is not "full fidelity" today — it must become so

D8 promises that a native (ext4/btrfs) backup is fully faithful and recoverable with
`cp -a`. But today's copy engine, even on a capable filesystem:

- does **not** copy UID/GID;
- does **not** copy xattrs/ACLs;
- does **not** preserve hardlink identity (it duplicates).

So a migr backup to ext4 is currently *less* faithful than `cp -a`, and D8's claim does
not yet hold. Therefore this is not "add a portable branch to a working engine." It is
"bring the engine to full fidelity, with a **native and a portable representation for
every dimension**." Each dimension below carries both columns:

```
xattr:     native  -> setxattr on the destination file
           portable -> record in sidecar
hardlink:  native  -> create a real hardlink
           portable -> dense copy + sidecar relation
```

For a single-user home backup some native gaps are low impact (UID/GID is usually
uniform), but they are cheap to close and D8's promise requires it. Two boundaries of
that promise — whether atime is preserved, and whether D13 defers sparse preservation in
native mode as well as portable mode — remain explicit product decisions. Until they are
settled, "full fidelity" means every dimension in the accepted contract, not an
unqualified claim that all filesystem state is already preserved.

---

## Capability probe (Phase A, grows per phase)

At backup start, on the destination root, empirically create a temp dir and exercise
what migr depends on, cleaning up after. Phase A covers the basics (mode round-trip,
symlink, an illegal char, a `user.*` xattr); each later phase extends the bitset with
what it needs (timestamp precision, case sensitivity, hardlink, filename classes,
ownership behaviour). Refinements:

- **Distinguish ENOTSUP from EPERM.** `chown` always fails for a non-root user — a
  privilege issue, not a lossy-filesystem signal — and must not by itself trigger
  portable mode.
- **Do not silently fall back.** If a destination that should be POSIX fails the probe
  for an unexpected reason, report the failure rather than quietly switching to portable
  mode; a silent switch could hide a broken environment.
- The verdict is not "POSIX filesystem" but "verified every native semantic migr
  implements." Only then is native mode selected.

**Testability:** mode selection accepts an injected/forced capability profile, so the
portable path is testable on the dev machine's btrfs without a mounted lossy filesystem.
The probe is the single most correctness-critical piece — a wrong native verdict loses
silently — so it is tested hardest.

---

## Sidecar format

D6 fixes the direction (NUL-separated, append-only). The previous sketch conflated
object *types* with *attributes* and could not encode binary values; this is the
corrected model. The exact byte grammar is finalized at the **start of Phase B**, but
the model is settled now because it constrains the parser/writer.

The format distinguishes **record kind** from **filesystem object kind**:

- record kinds are `ENTRY`, `XATTR`, `ENTRY_COMMIT`, and, provisionally, `DELETE`;
- an `ENTRY` carries an object kind: `file`, `dir`, `symlink`, or `hardlink` (and
  possibly `fifo` once that policy is settled).

There is one **logical entry group** per filesystem object:

1. `ENTRY` starts the group and declares its logical key and expected xattr count;
2. zero or more `XATTR` sub-records follow;
3. `ENTRY_COMMIT` makes the entire group valid.

A reader ignores an entry group without its final commit. This is necessary because an
entry with three xattrs must not become valid after only one or two were appended before
an interruption. It also gives resume replacement semantics: a later committed group is
the complete new state of the entry, so xattrs that disappeared from the source do not
leak in from an older group. No explicit generation number is needed; committed group
order is the implicit generation.

`ENTRY` contains:

- its logical root plus true relative path;
- its physical relative path when that differs because of encoding, collision
  disambiguation, or length handling;
- object kind;
- base metadata for **every** kind including directories: `mode`, `uid`, `gid`,
  `mtime_sec`, and `mtime_nsec`;
- true source **size** for regular files, required by D6's resume oracle;
- type extras such as symlink target bytes or a hardlink group reference;
- the number of associated `XATTR` sub-records.

Whether atime joins the base metadata is an open fidelity decision before Phase B, not
settled by this plan. If it is omitted, D6/D8 must record that boundary explicitly.

An xattr **value is arbitrary binary and can contain NUL**, so it cannot be
NUL-delimited. Xattr names are NUL-terminated byte strings; values are
**length-prefixed** raw bytes with a strict maximum checked before allocation. Each
`XATTR` belongs to the immediately open entry group.

Deletion semantics must exist for resume. The D6-aligned recommendation is a `DELETE`
record with "last committed state wins"; atomic sidecar rewrite remains an alternative
until the exact grammar is frozen at the start of Phase B. `DELETE` is therefore a
reserved/provisional record kind in this plan, not a settled choice pretending the open
decision has already been made.

**Framing / crash safety:**

- a magic value + format version open the file; an unknown version is rejected, not
  guessed;
- the grammar is byte-oriented, never assuming UTF-8; paths and symlink targets cannot
  contain NUL, xattr values are length-prefixed;
- **truncated-tail rule:** a record whose schema is not fully satisfied at EOF is
  discarded on read, and any otherwise complete `ENTRY`/`XATTR` sequence without its
  `ENTRY_COMMIT` is ignored as an uncommitted group.

**Size reality:** one small entry group per object; 432 objects remain tiny, and a
200k-object backup remains on the order of tens of MB plus its encoded xattr values.

---

## Payload / sidecar commit ordering (process-interruption safety)

Truncated-tail alone does not make resume safe. The commit order must be:

1. write the payload fully;
2. close the payload descriptor successfully;
3. append `ENTRY` plus all of its `XATTR` sub-records;
4. **then** append `ENTRY_COMMIT`, which is the sidecar commit point.

If the sidecar group became valid before the payload was complete, a crash in between
would let resume mistake a half-written payload for a finished one. The reverse order is
safe: a complete payload with no committed sidecar group is simply rewritten on resume.
This is a process-interruption guarantee only — **no `fsync`/power-loss ordering is
promised** (declined as out of scope).

**Source changing mid-copy:** `fstat` before and after copying detects whether the
sidecar metadata and copied bytes may represent different moments of the source. Whether
v1 retries, fails, or completes with an explicit warning is an open decision before
Phase B; silent acceptance is not an option.

---

## Restore metadata ordering

1. create the entry and write content;
2. apply ownership (uid/gid);
3. apply xattrs / ACL-related metadata;
4. apply mode;
5. apply timestamps **last**.

Directory metadata is applied **post-order**, after children exist — traversal mutates
directory timestamps, and a restrictive mode applied too early blocks child restoration.

---

## Restore-path safety (required, not preferred)

The sidecar and manifest are untrusted input, even when normally written by migr. A
corrupt or crafted record **must not** write outside the restore root:

- reject any relative path containing a `..` component or a leading `/`;
- validate before mutating;
- **require** root-relative traversal that refuses symlinks in **every** path component,
  not merely the final component. `O_NOFOLLOW` on one `openat()` protects only its final
  component. Walk component-by-component using directory fds and
  `openat(..., O_DIRECTORY | O_NOFOLLOW)` (with `AT_SYMLINK_NOFOLLOW` where `fstatat()` is
  used), or use `openat2()` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` when the minimum
  supported kernel permits it.

migr restores into `$HOME`; a record with `../../.ssh/authorized_keys` is a real risk.
A full fuzzing harness is deferred, but the negative tests — absolute path, `..`,
truncated/oversized record, payload-symlink redirect — are **mandatory**, not optional.

---

## Roots and addressing

Records are keyed by `(logical root, relative path)`, never by a persisted absolute
source path.

- **XDG roots** reuse the existing manifest keys (`XDG_DOCUMENTS_DIR`, …), which already
  carry canonical cross-locale identity — no `xdg:documents`-style scheme is needed.
- **Explicit-paths roots** get ordinal ids (`EXPLICIT_0`, `EXPLICIT_1`, …), which fixes
  the backup-side basename collision (prerequisite bug #3).

But ordinal ids only solve the **backup** side. **Where does `EXPLICIT_0` restore to?**
This is an unresolved product decision (see "Open decisions"): the original absolute
path? a basename under `$HOME`? prompt the user? exclude explicit backups from automatic
restore? Note the related pre-existing gap: today's `restore()` looks for XDG dirs,
dotfiles, browser configs, and packages — it has **no path for arbitrarily-named
explicit items**, so explicit-paths backups are effectively not restorable now. Each
ordinal root therefore needs a minimal recorded source/destination policy, not the full
logical-root framework.

---

## Manifest evolution and legacy detection

The current manifest has no version and records only XDG basenames. The new container
needs it to carry at least:

- a manifest format version;
- native/portable mode and container layout;
- source scope/identity fields used to match a partial job for resume;
- logical-root mappings, including the eventual `EXPLICIT_n` policy;
- the sidecar format version when a sidecar is present.

This is required even for native backups, which deliberately have no sidecar and
therefore cannot use the sidecar magic to identify their layout. Phase A introduces the
versioned manifest reader/writer together with explicit legacy detection:

- a recognized new version is parsed according to that schema;
- an unknown new version is rejected rather than guessed;
- the existing unversioned XDG-key manifest, and the older manifests-absent layout, use
  an isolated legacy restore path.

The exact textual manifest grammar can stay small; versioning and an unambiguous legacy
boundary are the requirements.

---

## Backup container

A backup is written to a unique partial directory and **atomically renamed** on success:

```
migr_backup_YYYYMMDD_HHMMSS[-N].partial/   ->   migr_backup_YYYYMMDD_HHMMSS[-N]/
```

The date-only name was insufficient: it could not represent a second backup on the same
day, a rename onto an existing final directory, or a clean resume identity. `HHMMSS[-N]`
is enough — no UUID. The manifest additionally records at least the source scope/identity
needed to match a resume to its job.

**Mandatory invariant — control names never collide with payload:** a payload item must
never be able to overwrite `manifest.txt`, `packages.txt`, or `sidecar.migr`. This is
non-negotiable in backup software; "rare" is not an acceptable defence for silent data
loss. The mechanism may be a `data/` payload namespace (cleanest) or reserved-name
pre-scan rejection (lighter) — but *some* mechanism is required. This reverses an earlier
draft that called it optional.

---

## The dimensions

Each carries a native and a portable behaviour.

| # | Dimension | Native | Portable | Phase |
|---|---|---|---|---|
| 1 | mode/uid/gid/mtime; atime pending | apply accepted timestamp contract | sidecar record | B |
| 2 | symlink | recreate symlink, no-follow meta | placeholder file + `SYMLINK` record | C |
| 3 | illegal filename | n/a (native accepts it) | encode on disk, true name in record | D |
| 4 | xattr / ACL | `setxattr` on destination | `XATTR` sub-records (length-prefixed) | E |
| 5 | case collision | n/a (native preserves case) | deterministic suffix | F |
| 6 | hardlink | real `link()` | dense copy + group reference | G |
| 7 | sparse file | open: preserve holes or document a D8 exception | dense copy; reconstruction deferred | D13 gate |

---

## Phase plan

Prerequisite bug fixes land on `main` first. Everything below is the sidecar branch.
Phases are dependency milestones, **not commit boundaries**: each phase is split into
the atomic commits it actually requires, and each increment is tested green before the
next. Native fidelity is **not** front-loaded into one phase; each dimension's Native
column is delivered in that dimension's phase (mode/uid/gid in B, xattr in E, hardlink
in G), so no single phase carries "make everything faithful at once."

- **Phase A — Structural foundation (no behaviour change).** `clone_ctx` refactor into
  the three orchestrations; empirical probe with forced-profile injection and mode
  selection wired, but the portable path stubbed so a capable destination behaves exactly
  as today. All existing tests pass **unchanged** — this is the regression-safe baseline
  everything else builds on, and its whole value is that it changes nothing observable.
- **Phase A2 — Versioned container.** `.partial` + atomic rename + control/payload
  non-collision; versioned manifest + legacy detection. The first observable format
  change, kept separate from the refactor so it is reviewed on its own: tested that
  legacy backups still restore through the isolated legacy path and new backups adopt the
  new layout.
- **Phase B — Format + core metadata.** Finalize the byte grammar; sidecar writer/reader
  with magic+version, committed entry groups, truncated-tail and precedence; finalize the
  deletion representation needed by H; mode/uid/gid/mtime plus the atime decision; file
  size for resume; payload→entry-group commit ordering; source-change and metadata
  failure behaviour; restore ordering.
- **Phase C — Symlinks.** Native no-follow metadata (bug #1 already fixed on main);
  portable placeholder + record.
- **Phase D — Illegal filenames + pre-scan.** Encode on disk, true name in record;
  `NAME_MAX` handling for expanded names; the up-front unrepresentable-name report.
- **Phase E — xattrs / ACLs.** Native `setxattr`; portable sub-records; distinguish
  absent / unsupported / denied / error.
- **Phase F — Case collisions.** Deterministic, `readdir`-order-independent suffix.
- **Phase G — Hardlinks.** `(st_dev, st_ino)` grouping; native `link()` / portable dense
  copy; space accounting in the pre-scan.
- **Phase H — Resume.** Sidecar as the comparison oracle (true size+mtime+type); the
  deletion/precedence algorithm selected in B; drop stale entries. Commit-ordering is
  already in place from B.
- **Deferred — sparse files** (D13).

---

## Pre-scan

Before copying, walk the source read-only and, in portable mode, compute the **mandatory**
mapping: encoded names, case-collision suffixes, `NAME_MAX` fits, and the dense-copy space
estimate for hardlinks/sparse. It also detects unsupported special entries up front. The
mapping pass is required for portable correctness and **cannot** be disabled. No
`--no-prescan` option is planned: an eventual UX switch that suppresses only a
report/confirmation must be named for that behaviour (for example `--no-confirm`) and
should not be added until such a user-facing need exists.

---

## Testing strategy

- **Unit (any filesystem, dev machine):** probe, percent-encode/decode roundtrip, sidecar
  record write/parse roundtrip (including file size, length-prefixed binary xattr values
  containing NUL, incomplete entry groups, truncated tail, precedence, xattr removal on
  replacement, unknown version), versioned/unversioned/unknown manifest handling, and
  `user.*` xattr roundtrip. Separate test binaries in the `tests/test_detect.c` mould.
- **Forced-portable integration (dev machine):** inject a capability profile forcing
  portable mode, run full backup→restore fixtures on btrfs. Proves control flow without a
  mounted lossy filesystem.
- **Interruption boundaries:** inject interruption after payload close, during `ENTRY`,
  between `XATTR` sub-records, before/after `ENTRY_COMMIT`, and around deletion handling;
  resume must either redo the entry or use one complete committed state, never a partial
  metadata set.
- **Adversarial restore (mandatory):** absolute path, `..`, oversized/truncated record,
  decoded separator/NUL attempts, intermediate and final payload-symlink redirects,
  duplicate roots, malformed hardlink group.
- **Real-filesystem integration:** `mkfs.vfat` + loopback is fine for quick dev iteration,
  **but vfat is not a proxy for exFAT or NTFS** — they differ in name limits and
  capabilities. The final matrix must include **real exFAT and the actual Linux NTFS
  driver** (D6 names all three families), run in the VMs (mount needs root).
- **Roundtrip is mandatory** for every dimension: encode-then-decode must equal the
  original.
- **Regression:** existing 45+14 assertions stay green from Phase A on.
- **Durable error-propagation fixture:** the regression for prerequisite #2 must not
  permanently rely on FIFO being unsupported, because prerequisite #5 changes that
  behaviour. Use a failure that remains a failure after special-file support lands.

---

## Open decisions (settle at the stated gate, not later)

- **Portable-mode special files (deferred to the sidecar phases):** the native policy is
  settled by prerequisite #5 — FIFO recreated via `mkfifo`, socket and device node skipped
  with a warning (no `had_error`). What a *lossy* destination does (a FIFO placeholder+record
  vs skip; sockets/devices always skipped) is still open and belongs to Phase C/D, not the
  current engine.
- **Before Phase A:** the control/payload non-collision mechanism (`data/` vs reserved-name
  rejection); the container naming (`HHMMSS[-N]`) and its resume-identity fields.
- **Before Phase A:** explicit-root restore semantics — where `EXPLICIT_n` restores to,
  or whether explicit backups are marked manual-restore.
- **Before Phase B:** the exact record byte grammar and the resume record semantics
  (`DELETE` + last-wins vs atomic rewrite; append-only per D6 favours the former).
- **Before Phase B:** whether atime is part of the fidelity contract; if not, record the
  D6/D8 limitation explicitly.
- **Before Phase B:** source-change behaviour (retry, fail, or explicit warning) and the
  operation result when required metadata cannot be captured or replayed. Phase E extends
  the same result policy to xattrs/ACLs.
  - *Existing precedent (`main`):* a `packages.txt` / `manifest.txt` write failure is a
    warning, not a backup-level error — the payload copy is what "backup" means, these are
    aids. The sidecar result policy should stay consistent with this and not silently promote
    such failures to errors.
- **Before declaring D8 implemented:** reconcile D13 with native sparse files — preserve
  holes in native mode, or document that "full fidelity" has a sparse-file exception.

---

## Declined from the review

Adopted: the verified bugs, the three-orchestration framing, explicit direction enum,
`EXPLICIT_n` ordinal roots, committed entry groups, truncated-tail,
payload→sidecar commit ordering, versioned manifest + legacy detection, native-mode
fidelity per dimension, `HHMMSS` container + mandatory non-collision invariant,
deletion semantics reserved before format freeze, restore ordering, component-safe
no-follow traversal + mandatory negative tests, real exFAT/NTFS in the final matrix,
probe ENOTSUP/EPERM + no-silent-fallback.
Declined, with reasons:

- **The `LogicalEntry` / sink hierarchy.** Enterprise abstraction for a ~300-line C file;
  three explicit loops over shared helpers do the same job.
- **The full logical-root framework** (per-root destination-policy tables, richer than the
  minimal ordinal roots + per-root policy actually needed).
- **Per-entry checksums / integrity fields**, and **`fsync` power-loss durability.**
  Filesystem-product requirements; migr promises process-interruption resume only.
- **Explicit generation numbers.** File order is the implicit generation.
- **A fuzzing harness.** The mandatory negative-test set is the proportionate subset.
- **A separate `SIDECAR_FORMAT.md` governance document.** The grammar lives in this plan.

The throughline holds: adopt what the review *found*, decline the scale it *assumes*.

---

## Documentation synchronization

The plan is the active implementation guide, but accepted choices must be reflected in
the repository's authoritative documents at their gates:

- update D6/D8 when atime, sparse fidelity, container, or format behaviour is settled;
- keep D13's native/portable boundary consistent with the dimension table;
- update `docs/TODO.md` to match this phase plan and remove its old skippable
  `--no-prescan` wording;
- update README's D8/full-fidelity claim only when the accepted native contract is
  actually implemented.

---

## Risk notes

- The project's single largest piece of work — it roughly triples fileops.c, and a single
  bug means silent data corruption. Hence the strict phasing and mandatory roundtrips.
- The probe is the critical path: a wrong native verdict writes no sidecar and loses
  silently. Test it hardest.
- Lossy-fs behaviour cannot be exercised on the dev machine (mount needs root); the
  forced-profile tests cover control flow there, and each phase's driver-level test closes
  on real exFAT/NTFS in the VMs.

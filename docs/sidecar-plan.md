# Sidecar — Implementation Plan

Working design document for the sidecar feature (see DECISIONS.md D6). This is
scaffolding: phases get checked off and details shift as reality pushes back. The
durable rationale lives in DECISIONS.md (D6, D13, D14, and more as they are decided);
this file is the how, not the why.

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

The sidecar is **inherently asymmetric**. Its eventual shape has **three
orchestrations**, sharing low-level helpers (byte copy, metadata apply/capture,
encode/decode) but not one permanently shared loop:

- **backup** — walk the source tree, capture each entry, write payload; in portable
  mode also write the sidecar;
- **native restore** — walk the backup tree, copy to home (today's behaviour, once
  brought up to full fidelity — see "Native mode" below);
- **portable restore** — **sidecar-driven**: iterate the sidecar and replay, because
  the physical names are encoded and the sidecar is authoritative.

Phase A established the boundary without manufacturing divergence early: its
`backup_capture()` and `restore_native()` entries initially delegated to one private
`clone_tree()` core. Phase A2 introduced the first necessary divergence and removed
that shared walker. Production backup now uses `backup_capture_at()` to read a
pathname-based source into an already-open payload directory, while
`restore_native_at()` anchors both payload and destination traversal to directory file
descriptors. Their remaining shared contract is the explicit `CloneContext`; they share
neither an orchestration loop nor walker-specific helpers. `CloneContext` carries the
operation (`CLONE_BACKUP` / `CLONE_RESTORE`) and representation (`CLONE_NATIVE_TREE` /
`CLONE_PORTABLE_SIDECAR`); it should gain sidecar, capability, or hardlink state only
when a later phase gives that state a real consumer. Portable restore remains a future
sidecar-driven orchestration. No "null-ish" context is allowed to imply behaviour by
its absence. A "sink hierarchy" was proposed and declined — explicit entry points that
split as their algorithms actually diverge achieve the needed separation without
class machinery.

---

## Prerequisites — data-plane bugs fixed on `main` before Phase A

These were **not sidecar work.** They were real defects in the copy engine, verified by
testing and fixed before the sidecar branch was built on top. All five landed on `main`
with regression coverage:

1. **Backup mutates the source through a symlink** (critical, security). `preserve_metadata`
   calls plain `chmod(dest, ...)` on a symlink path; `chmod` follows the link. For an
   absolute symlink, `dest` points at the real source file, so its mode is overwritten
   with the symlink's own `0777`. **Verified:** a source `target.txt` went `0600 → 0777`
   through a backup. For `.ssh` this both breaks the key and exposes it, and it violates
   the invariant that backup never modifies the source. Resolved by never calling
   `chmod` on a symlink path (`71ac757`).
2. **Failed copies report success.** A recursive copy failure propagates a `-1` that
   `backup()` ignores; it still prints `Backup complete` and exits `0`. **Verified**
   with a FIFO. Sidecar finalization cannot be trusted until errors reach the CLI and
   prevent a "complete" verdict. Resolved by propagating copy failures through
   `backup()` to the process result (`ac47bfd`).
3. **Explicit-paths basename collision loses data.** Two explicit paths sharing a
   basename both clone to the same name; files overwrite, directories merge. **Verified:**
   `migr backup /dst ~/a/foo.txt ~/b/foo.txt` kept only one `foo.txt`, yet reported
   `2 items copied`. Explicit-paths mode also writes no manifest, so there is no
   disambiguation at all. Initially contained on `main` by detecting and refusing
   basename collisions (`a2aa086`); Phase A2 replaced that temporary refusal with
   stable ordinal payload roots (`ec89e18`, `2e2329a`).
4. **Unchecked `snprintf` path assembly.** `PATH_MAX` buffers are filled without checking
   for truncation, silently producing wrong paths. Low severity then, but filename
   encoding (Phase D) can expand a name past the buffer. Resolved by checking bounded
   path construction and refusing truncation (`0af8aa3`); `openat`/`fstatat` traversal
   remains a possible longer-term improvement where safety requires it.
5. **Special files break the copy.** The old recursive clone handled only
   symlink/regular/directory and returned `-1` for anything else. A FIFO or socket —
   `.gnupg` contains sockets — aborted its subtree. The landed native policy recreates
   FIFOs with `mkfifo`; sockets and device nodes are skipped with a warning because
   neither carries backup payload bytes (`73bd703`). Portable FIFO representation
   remains a later sidecar decision.

---

## What still breaks on a lossy destination (the sidecar's job)

Before Phase A, an exFAT/NTFS backup could lose metadata silently: `chmod`/
`utimensat` failures are still ignored by the native clone core, so permissions and
timestamps could vanish with no error. Phase A now probes the destination first and
refuses a non-native verdict before creating a backup container, closing that silent
loss path while portable mode is absent. The sidecar's job is to turn that safe refusal
into a faithful portable backup — recording metadata in portable mode and making the
corresponding native application paths report failure rather than pretend success.

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
what migr depends on, cleaning up after. Phase A implements six probes: mode round-trip,
symlink, FIFO, a corpus of raw names, case sensitivity, and a `user.*` xattr. Each later
phase extends the profile only when it introduces another native semantic, such as
ownership behaviour, timestamp precision, or hardlinks. Refinements:

- **Classify in the syscall's context.** For Phase A's capability attempts
  (`chmod`, `symlink`, `mkfifo`, `setxattr`) on a fresh directory migr owns,
  `ENOTSUP`/`EOPNOTSUPP` and `EPERM`/`EACCES` mean that semantic is unavailable.
  Supporting-operation failures remain operational errors. A future ownership
  probe must classify `chown` separately: non-root `EPERM` is a privilege result,
  not evidence of a lossy filesystem.
- **Do not silently fall back.** If a destination that should be POSIX fails the probe
  for an unexpected reason, report the failure rather than quietly switching to portable
  mode; a silent switch could hide a broken environment.
- The verdict is not "POSIX filesystem" but "verified every semantic required by the
  current native profile." Only then is native mode selected.

The probe only measures. A separate pure
`select_representation(profile, out)` function applies the policy from D14, so unit
tests exercise the complete native/portable/refuse decision matrix with synthetic
profiles without exposing a production override. Those tests prove the selector, not
the full portable orchestration; real mounted filesystems remain necessary to validate
the probe and its wiring. Once the portable pipeline exists, a test-only seam may be
added if needed to exercise that orchestration on a native development filesystem, but
it must not be reachable through the production CLI, environment, or configuration.

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

Entry records are keyed by `(logical root, relative path)`, never by repeating an
absolute source path in every entry. The manifest's root table owns the mapping from
each logical root to its source and restore policy.

- **XDG roots** reuse the existing manifest keys (`XDG_DOCUMENTS_DIR`, …), which already
  carry canonical cross-locale identity — no `xdg:documents`-style scheme is needed.
- **Explicit-paths roots** get ordinal ids (`EXPLICIT_0`, `EXPLICIT_1`, …), which fixes
  the backup-side basename collision (prerequisite bug #3). The ordinal is identity,
  not by itself a restore address.

### Phase A2 root policy

- Every user-derived filesystem object lives below the container's `data/` namespace.
  Only migr-owned control artifacts live at the container root (D15).
- Explicit roots keep accepting valid paths inside and outside `$HOME`; an external path
  is not a new rejection condition (D16).
- A root proven to be inside the source `$HOME` gets a `HOME_RELATIVE` policy: its
  normalized home-relative address is recreated below the target `$HOME`.
- Every other valid root gets `MANUAL_NATIVE`: it remains directly accessible in its
  `data/EXPLICIT_n` tree and restore reports it, but does not invent a destination.
- Classification is component-based and symlink-aware, not a string-prefix test. A
  selected leaf symlink remains the object being backed up; ancestor traversal must not
  make an external object appear home-relative.
- All explicit roots are validated before container creation. An invalid, duplicate or
  overlapping root rejects the whole invocation rather than silently dropping one of
  the paths the user requested.
- Portable capture refuses a root with `MANUAL_NATIVE` before writing payload. Encoded
  names, symlink placeholders and sidecar metadata are not a usable manual backup
  without a migr restore policy. A future staging, mapped, or guarded original-location
  policy may replace this gate.

The future `conf include` mechanism will feed the same root-addressing model, but it is
not yet decided that every include becomes `HOME_RELATIVE`. A configured child may
overlap an XDG root whose target is locale-dependent. Built-in and configured selections
must eventually be resolved into one normalized, non-overlapping root set before the
manifest is written; include/exclude precedence and XDG-child addressing belong to the
`conf` design, not Phase A2.

---

## Manifest evolution and legacy detection

Legacy manifests have no version and record only XDG basenames. Phase A2 added a v1
manifest carrying:

- a manifest format version;
- native/portable mode and container layout;
- source identity (`machine-id` + numeric uid when available) and the normalized root
  set used to match a partial job for resume;
- logical-root mappings, including D16's `HOME_RELATIVE` / `MANUAL_NATIVE` explicit-root
  policies;
- the sidecar format version when a sidecar is present.

This is required even for native backups, which deliberately have no sidecar and
therefore cannot use the sidecar magic to identify their layout. The versioned reader
and writer now coexist with explicit legacy detection:

- a recognized new version is parsed according to that schema;
- an unknown new version is rejected rather than guessed;
- the existing unversioned XDG-key manifest, and the older manifests-absent layout, use
  an isolated legacy restore path.

The textual grammar remains deliberately small; versioning and an unambiguous legacy
boundary are the requirements.

---

## Backup container

A backup is written to a unique partial directory and **atomically renamed** on success:

```
migr_backup_YYYYMMDD_HHMMSS[-N].partial/   ->   migr_backup_YYYYMMDD_HHMMSS[-N]/
```

The date-only name was insufficient: it could not represent a second backup on the same
day, a rename onto an existing final directory, or a clean resume identity. `HHMMSS[-N]`
is enough — no UUID. Allocation considers both partial and final names, claims the
partial name atomically, and finalization never replaces an existing final container.
Resume matching uses the format/representation, a stable source identity and the
normalized root set — never the timestamp or scope label alone.

**Mandatory invariant — control names never collide with payload:** a payload item must
never be able to overwrite `manifest.txt`, `packages.txt`, or `sidecar.migr`. This is
non-negotiable in backup software; "rare" is not an acceptable defence for silent data
loss. Phase A2 uses a `data/` payload namespace; reserved-name pre-scan rejection was
considered but not chosen.

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

- **Phase A — Structural foundation (complete).** `CloneContext { operation,
  representation }`; the initial distinct backup/restore entries over one private
  native walker; standalone six-capability `fsprobe()` plus pure
  `select_representation()`; and backup preflight wiring. Native destinations retained
  the existing copy behaviour. Its policy still holds: an unavailable native semantic
  selects portable, but backup refuses that verdict before creating any container
  because portable capture is not implemented; an unreliable probe also refuses rather
  than silently falling through. Restore remains native, dry-run does not probe, and
  there is no production capability override. Existing regression tests remained green
  and new probe/preflight tests were added (`e6d367b`, `ac301da`, `ea1a3d9`).
- **Phase A2 — Versioned container (complete).** The first observable format change:
  strict v1 manifest + isolated legacy detection; deterministic root planning;
  directory-fd-anchored backup and restore destinations; `.partial` reservation,
  matching-job adoption and no-replace finalization; and mandatory `data/`
  control/payload separation. D16's explicit-root table restores home-relative roots
  automatically and reports external native roots without inventing a destination.
  Invalid root sets fail before destination mutation, incomplete backups never look
  final, and legacy backups remain restorable. The contract landed in `758ab35`; the
  implementation followed in `2a4bc4b`, `606dae3`, `90d1b41`, `0373bfa`, `ec89e18`,
  and `2e2329a`. The full suite and native roundtrip passed on Fedora, Ubuntu and Arch;
  real vfat loopbacks on both VMs selected portable, refused before container creation,
  and left the mounted destinations empty.
- **Phase B — Format + core metadata.** Finalize the byte grammar; sidecar writer/reader
  with magic+version, committed entry groups, truncated-tail and precedence; finalize the
  deletion representation needed by H; mode/uid/gid/mtime plus the atime decision; file
  size for resume; payload→entry-group commit ordering; source-change and metadata
  failure behaviour; restore ordering.
  **Status: complete (2026-08-04).** Codec, portable capture/resume core, portable
  restore preflight/replay/orchestration, and native core-metadata fidelity are
  implemented and gated (host `make check`; Ubuntu/Arch VM matrix; Fedora parity with
  the known Phase E xattr gap). D17 is marked Implemented with as-built notes. One
  debt is deliberately handed to Phase H: native resume's stale-entry reconciliation
  (sidecar-backed oracle; deleted files/subtrees must not survive a successful resumed
  final backup, and deletion failure blocks finalization) — recorded in D17 and here.
  Production portable dispatch remains disabled through Phase B (D14), including the
  B.5 gate; enabling it is a later, post-safety-phases decision.
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
  replacement, unknown version), versioned/unversioned/unknown manifest handling,
  explicit-root policy roundtrip, and `user.*` xattr roundtrip. Separate test binaries in
  the `tests/test_detect.c` mould.
- **Phase A2 container/root integration (complete):** same-second invocations choose
  distinct names; a failed backup never publishes a final container; an existing final
  is never replaced; a home-contained explicit root restores to the same
  target-home-relative address; an external root remains in `data/EXPLICIT_n` and is
  reported without being restored; missing, duplicate, or overlapping explicit roots
  refuse the whole invocation before container creation; leaf and ancestor symlink
  cases exercise component-aware classification.
- **Portable orchestration integration (once that path exists):** run full
  backup→restore fixtures on real lossy filesystems. If a narrowly scoped test-only seam
  is needed for faster native-filesystem runs, it may supply a synthetic profile to the
  orchestration, but it must not create a production override and cannot replace the
  real-filesystem matrix.
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
- **Regression:** the complete existing regression suite stays green from Phase A on;
  new phase-specific tests are additive.
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
- **Phase A2 — settled and implemented by D15/D16:** payload lives under `data/`; a
  unique `HHMMSS[-N].partial` is atomically finalized without replacing an existing
  container; resume identity includes stable source identity and the normalized root
  set. Explicit paths remain arbitrary: home-contained roots are `HOME_RELATIVE`, other
  native roots are reported as `MANUAL_NATIVE`, and portable capture refuses a
  manual-only root.
- **When `conf` is designed:** define include/exclude precedence and resolve overlaps
  between configured paths and locale-mapped XDG roots before emitting the manifest root
  set.
- **Before Phase B:** the exact record byte grammar and the resume record semantics
  (`DELETE` + last-wins vs atomic rewrite; append-only per D6 favours the former).
- **Before Phase B:** whether atime is part of the fidelity contract; if not, record the
  D6/D8 limitation explicitly.
- **Before Phase B:** source-change behaviour (retry, fail, or explicit warning) and the
  operation result when required metadata cannot be captured or replayed. Phase E extends
  the same result policy to xattrs/ACLs.
  - *Existing precedent:* the required v1 `manifest.txt` is part of container validity,
    so a write failure blocks finalization; package export remains optional and warns
    without invalidating copied payload. A portable sidecar is fidelity-critical, not
    analogous to the package list, so its eventual failure policy must preserve that
    distinction.
- **Before declaring D8 implemented:** reconcile D13 with native sparse files — preserve
  holes in native mode, or document that "full fidelity" has a sparse-file exception.

---

## Declined from the review

Adopted: the verified bugs, the eventual three-orchestration framing, explicit
operation and representation enums,
`EXPLICIT_n` ordinal roots, committed entry groups, truncated-tail,
payload→sidecar commit ordering, versioned manifest + legacy detection, native-mode
fidelity per dimension, `HHMMSS` container + mandatory non-collision invariant,
deletion semantics reserved before format freeze, restore ordering, component-safe
no-follow traversal + mandatory negative tests, real exFAT/NTFS in the final matrix,
contextual probe-error classification + no-silent-fallback.
Declined, with reasons:

- **The `LogicalEntry` / sink hierarchy.** Enterprise abstraction for the current C
  engine; explicit entry points can split into separate loops over shared helpers when
  their algorithms actually diverge.
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

- update D6/D8 when atime, sparse fidelity, or sidecar-format behaviour is settled;
- keep D13's native/portable boundary consistent with the dimension table;
- Phase A2's landed container/root behaviour is synchronized across D15/D16 and README;
- update README's D8/full-fidelity claim only when the accepted native contract is
  actually implemented.

---

## Risk notes

- The project's single largest piece of work — it roughly triples fileops.c, and a single
  bug means silent data corruption. Hence the strict phasing and mandatory roundtrips.
- The probe is the critical path: a wrong native verdict writes no sidecar and loses
  silently. Test it hardest.
- Lossy-filesystem behaviour is outside the unprivileged default suite because mounting
  test filesystems needs root. Synthetic profiles cover the selector's decision matrix;
  loopback filesystems in the VMs cover the real probe and backup wiring. As portable
  orchestration grows, optional test-only seams may shorten iteration but never replace
  real exFAT/NTFS/vfat tests.

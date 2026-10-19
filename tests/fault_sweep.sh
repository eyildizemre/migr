#!/usr/bin/env bash
# Fault-injection sweep: runs each scenario once to list the call sites it
# reaches (tests/fault/fault_inject.c), then once per site with that call
# failing, and once more for a site listed with a second error. The
# scenarios back up, update, restore, and verify, and repair a portable
# backup with one journal record damaged; a backup and its restore
# also run with the scope migr picks from HOME. After every failed run:
#   - migr ended with 0, 1, or 2, not a crash or a hang;
#   - what the run only reads is unchanged (the source of a backup or a
#     verify, the backup a restore or a repair reads);
#   - a run that ended with 0 left a whole result;
#   - the same command run again without a fault finishes, and its result
#     is whole: the backup or the repaired copy verifies and nothing but
#     backups is left beside it, the restored home equals the source; after
#     a second error, which can mislead migr, it may also end with 1 or 2.
# The portable scenarios need root to mount a vfat image and run only then.
#
# Usage: tests/fault_sweep.sh MIGR SHIM [SCENARIO...]

set -u

MIGR=$(realpath "${1:?usage: fault_sweep.sh MIGR SHIM [SCENARIO...]}")
SHIM=$(realpath "${2:?usage: fault_sweep.sh MIGR SHIM [SCENARIO...]}")
shift 2
STUBS=$(cd "$(dirname "${BASH_SOURCE[0]}")/stubs" && pwd)

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

WORK=$(mktemp -d)
VFAT_MOUNT=""
VFAT_LOOP=""
cleanup() {
    if [ -n "$VFAT_MOUNT" ]; then
        umount "$VFAT_MOUNT" 2>/dev/null || umount -l "$VFAT_MOUNT"
    fi
    [ -n "$VFAT_LOOP" ] && losetup -d "$VFAT_LOOP" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# A VS Code installed on the host would write its logs into HOME; this one
# lists one extension and writes nothing.
mkdir "$WORK/bin"
printf '#!/bin/sh\necho ms-python.python@2026.1.0\n' > "$WORK/bin/code"
chmod +x "$WORK/bin/code"

failures=0

# Sets the extended attribute NAME to VALUE on PATH, a symlink itself.
set_xattr() {
    python3 -c 'import os, sys
os.setxattr(sys.argv[1], sys.argv[2], sys.argv[3].encode(),
            follow_symlinks=False)' "$@"
}

# The user.* and trusted.* attributes of the paths read from stdin, split by
# NUL.
list_xattrs() {
    python3 -c 'import os, sys
for path in sys.stdin.buffer.read().split(b"\0"):
    for name in sorted(os.listxattr(path, follow_symlinks=False)) if path else []:
        if name.startswith(("user.", "trusted.")):
            print(path, name, os.getxattr(path, name, follow_symlinks=False))'
}

# A folder with each kind of item a backup keeps, extended attributes (a
# symlink takes only trusted.* ones, which need root), and names that differ
# only in case, which vfat takes for one; a portable backup keeps no FIFO.
make_source() {
    local scenario="$1" notes="$2/notes"
    mkdir -p "$notes/sub/deep" "$notes/Dir" "$notes/dir"
    echo "alpha" > "$notes/a.txt"
    echo "beta" > "$notes/sub/b.txt"
    echo "gamma" > "$notes/sub/deep/c.txt"
    : > "$notes/empty"
    head -c 200000 /dev/urandom > "$notes/large.bin"
    ln -s a.txt "$notes/link"
    ln "$notes/a.txt" "$notes/hard"
    echo "upper" > "$notes/Case.txt"
    echo "lower" > "$notes/case.txt"
    echo "one" > "$notes/Dir/x"
    echo "two" > "$notes/dir/x"
    case "$scenario" in
        native-*) mkfifo "$notes/pipe" ;;
    esac
    chmod 600 "$notes/sub/b.txt"
    set_xattr "$notes/a.txt" user.migr.note "kept"
    set_xattr "$notes/sub" user.migr.note "a folder"
    if [ "$(id -u)" -eq 0 ]; then
        set_xattr "$notes/link" trusted.migr.note "a symlink"
    fi
}

# Path, kind, mode, mtime, and for all but folders size, link count, and
# link target, of everything below a folder but logs/; then its extended
# attributes and its files' content.
snapshot() {
    (cd "$1" &&
     find . -mindepth 1 -path ./logs -prune -o \
         -type d -printf '%p|d|%m|%T@\n' -o \
         -printf '%p|%y|%m|%T@|%s|%n|%l\n' | LC_ALL=C sort &&
     find . -mindepth 1 -path ./logs -prune -o -print0 |
         LC_ALL=C sort -z | list_xattrs &&
     find . -mindepth 1 -path ./logs -prune -o -type f -print0 |
         LC_ALL=C sort -z | xargs -0 -r md5sum)
}

# The finished backups in a folder, one per line.
containers() {
    local found
    for found in "$1"/migr-*; do
        case "$found" in
            *.partial | *.updating) ;;
            *) [ -d "$found" ] && echo "$found" ;;
        esac
    done
}

# Each scenario has its folder D: D/home is HOME, D/answer migr's input.
# A backup, an update, or a verify, which lists the files it finds damaged
# in the backup, writes D/target (or the vfat mount's target), copied from
# its template before each run; a repair writes its copy there, emptied
# before each run. A restore writes D/home, emptied before each run. A
# restore and a repair read the backup in the template.

target_dir() {
    case "$1" in
        portable-*) echo "$VFAT_MOUNT/target" ;;
        *) echo "$2/target" ;;
    esac
}

template_dir() {
    case "$1" in
        portable-*) echo "$VFAT_MOUNT/template" ;;
        *) echo "$2/template" ;;
    esac
}

# PRELOAD names the shim for this run alone, past timeout.
run_migr() {
    local dir="$1"
    shift
    HOME="$dir/home" PATH="$WORK/bin:$STUBS:$PATH" timeout 60 \
        env ${PRELOAD:+LD_PRELOAD="$PRELOAD"} "$MIGR" "$@" \
        < "$dir/answer" > "$dir/output" 2>&1
}

# A scoped backup takes what migr picks from HOME, the others one folder.
backup_into() {
    local scenario="$1" dir="$2" target="$3"
    case "$scenario" in
        *-scoped-*) run_migr "$dir" backup "$target" ;;
        *) run_migr "$dir" backup "$target" "$dir/home/notes" ;;
    esac
}

setup() {
    local scenario="$1" dir="$2" template journal record offset
    template=$(template_dir "$scenario" "$dir")
    rm -rf "$dir" "$template"
    mkdir -p "$dir/home" "$template"
    echo y > "$dir/answer"
    case "$scenario" in
        *-scoped-*)
            make_source "$scenario" "$dir/home/Documents"
            mkdir -m 700 "$dir/home/.ssh"
            echo "Host *" > "$dir/home/.ssh/config"
            echo "alias ll='ls -l'" > "$dir/home/.bashrc"
            ;;
        *) make_source "$scenario" "$dir/home" ;;
    esac
    # A source changed in the second its backup is taken is not compared.
    sleep 1
    case "$scenario" in
        *-backup) ;;
        *) backup_into "$scenario" "$dir" "$template" || return ;;
    esac
    case "$scenario" in
        *-update)
            echo "alpha, changed" > "$dir/home/notes/a.txt"
            rm "$dir/home/notes/sub/b.txt"
            echo "new" > "$dir/home/notes/sub/new.txt"
            echo "upper again" > "$dir/home/notes/CASE.txt"
            sleep 1
            ;;
        *-restore)
            mv "$dir/home" "$dir/expected"
            # Without its lists of packages and Flatpak applications, a
            # restore neither installs software nor waits for a network.
            rm -f "$(containers "$template")"/{packages,flatpak-apps}.txt
            ;;
        *-repair)
            # The kind of one record no longer parses.
            journal="$(containers "$template")/sidecar.migr"
            record='ENTRY\x00[^\x00]*\x00sub/b\.txt\x00b\.txt\x00\x00\K'
            offset=$(grep -obaP "${record}regular" "$journal" | cut -d: -f1)
            [ -n "$offset" ] || return
            printf '#' | dd of="$journal" bs=1 seek="$offset" conv=notrunc \
                status=none
            ;;
    esac
}

fresh() {
    local scenario="$1" dir="$2"
    case "$scenario" in
        *-restore)
            rm -rf "${dir:?}/home"
            mkdir "$dir/home"
            # A new install's home: a folder of its own, and a shell profile
            # the backup has its own of.
            case "$scenario" in
                *-scoped-*)
                    mkdir "$dir/home/Documents"
                    echo "# from the new install" > "$dir/home/.bashrc"
                    ;;
            esac
            ;;
        *-repair)
            rm -rf "$(target_dir "$scenario" "$dir")"
            mkdir "$(target_dir "$scenario" "$dir")"
            ;;
        native-*)
            rm -rf "$dir/target"
            cp -a "$dir/template" "$dir/target"
            ;;
        portable-*)
            rm -rf "$VFAT_MOUNT/target"
            cp -r --preserve=timestamps "$VFAT_MOUNT/template" \
                "$VFAT_MOUNT/target"
            ;;
    esac
}

act() {
    local scenario="$1" dir="$2" backup target
    backup=$(containers "$(template_dir "$scenario" "$dir")")
    target=$(target_dir "$scenario" "$dir")
    case "$scenario" in
        *-restore) run_migr "$dir" restore "$backup" ;;
        *-verify) run_migr "$dir" verify "$(containers "$target")" ;;
        *-repair) run_migr "$dir" repair "$backup" "$target" ;;
        *) backup_into "$scenario" "$dir" "$target" ;;
    esac
}

read_only() {
    local scenario="$1" dir="$2"
    case "$scenario" in
        *-restore | *-repair)
            containers "$(template_dir "$scenario" "$dir")"
            ;;
        *-scoped-*) echo "$dir/home" ;;
        *) echo "$dir/home/notes" ;;
    esac
}

# Whether a run left a whole result; a verify's is the status it ended with.
whole() {
    local scenario="$1" dir="$2" backup target verified=0
    case "$scenario" in
        *-verify) return 0 ;;
        *-restore)
            # A failed restore keeps its log in HOME, in folders the source
            # does not have.
            rm -rf "$dir/home/.local/state/migr"
            rmdir "$dir/home/.local/state" "$dir/home/.local" 2>/dev/null
            [ "$(snapshot "$dir/expected")" = "$(snapshot "$dir/home")" ]
            ;;
        *)
            # Nothing but backups is left in the target.
            target=$(target_dir "$scenario" "$dir")
            [ -z "$(find "$target" -mindepth 1 -maxdepth 1 ! -name 'migr-*' \
                -print -quit)" ] || return
            while IFS= read -r backup; do
                HOME="$dir/home" "$MIGR" verify "$backup" \
                    > "$dir/verify" 2>&1 || return
                verified=1
            done < <(containers "$target")
            [ "$verified" -eq 1 ]
            ;;
    esac
}

fail() {
    echo -e "  ${RED}✗${NC} $1: $2"
    sed 's/^/      /' "$3" | tail -4
    failures=$((failures + 1))
}

sweep() {
    local scenario="$1" dir="$WORK/$1" sites="$WORK/$1.sites"
    if ! setup "$scenario" "$dir"; then
        fail "$scenario" "could not set up" "$dir/output"
        return
    fi
    fresh "$scenario" "$dir"
    PRELOAD="$SHIM" MIGR_FAULT_LIST="$sites" act "$scenario" "$dir"
    local status=$?
    if [ "$status" -ne 0 ] || ! whole "$scenario" "$dir"; then
        fail "$scenario" "a run without a fault ended with $status or not whole" \
            "$dir/output"
        return
    fi

    local count=0 missed=0 site guarded before allowed
    guarded=$(read_only "$scenario" "$dir")
    before=$(snapshot "$guarded")
    while IFS= read -r site; do
        count=$((count + 1))
        fresh "$scenario" "$dir"
        rm -f "$WORK/hit"
        PRELOAD="$SHIM" MIGR_FAULT="$site" MIGR_FAULT_HIT="$WORK/hit" \
            act "$scenario" "$dir"
        status=$?
        if [ ! -e "$WORK/hit" ]; then
            missed=$((missed + 1))
            continue
        fi
        if [ "$status" -gt 2 ]; then
            fail "$scenario" "$site: ended with $status" "$dir/output"
            continue
        fi
        if [ "$(snapshot "$guarded")" != "$before" ]; then
            fail "$scenario" "$site: changed $guarded" "$dir/output"
            continue
        fi
        if [ "$status" -eq 0 ] && ! whole "$scenario" "$dir"; then
            fail "$scenario" "$site: ended with 0 but not whole" "$dir/output"
            continue
        fi
        # A second error tells migr what is not so, such as a name gone that
        # is there; what it did about that can leave a state the next run
        # refuses, so that run may end as the one before could.
        allowed=0
        case "$site" in *' '*) allowed=2 ;; esac
        act "$scenario" "$dir"
        status=$?
        if [ "$status" -gt "$allowed" ] ||
           { [ "$status" -eq 0 ] && ! whole "$scenario" "$dir"; }; then
            fail "$scenario" "$site: the next run ended with $status or not whole" \
                "$dir/output"
        fi
    done < "$sites"
    echo -e "  ${GREEN}✓${NC} $scenario: $count call sites, $missed not reached again"
}

mount_vfat() {
    local image="$WORK/vfat.img"
    truncate -s 64M "$image"
    mkfs.vfat "$image" > /dev/null || return
    VFAT_LOOP=$(losetup --find --show "$image") || return
    VFAT_MOUNT="$WORK/vfat"
    mkdir -p "$VFAT_MOUNT"
    mount "$VFAT_LOOP" "$VFAT_MOUNT"
}

scenarios=("$@")
if [ ${#scenarios[@]} -eq 0 ]; then
    scenarios=(native-backup native-update native-restore native-verify
               native-scoped-backup native-scoped-restore)
    if [ "$(id -u)" -eq 0 ] && command -v mkfs.vfat > /dev/null; then
        scenarios+=(portable-backup portable-update portable-restore
                    portable-verify portable-repair portable-scoped-backup
                    portable-scoped-restore)
    else
        echo "Portable scenarios skipped: they need root and mkfs.vfat."
    fi
fi
for scenario in "${scenarios[@]}"; do
    case "$scenario" in
        portable-*)
            if [ -z "$VFAT_MOUNT" ] && ! mount_vfat; then
                echo -e "${RED}could not mount a vfat image${NC}"
                exit 1
            fi
            ;;
    esac
done

echo -e "${BLUE}::${NC} Fault sweep"
started=$SECONDS
for scenario in "${scenarios[@]}"; do
    sweep "$scenario"
done
echo "Took $((SECONDS - started)) s."
if [ "$failures" -ne 0 ]; then
    echo -e "${RED}$failures fault sweep failure(s)${NC}"
    exit 1
fi
echo -e "${GREEN}fault sweep passed${NC}"

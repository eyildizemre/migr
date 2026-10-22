#!/usr/bin/env bash
# Fault-injection sweep: runs each scenario once to list the call sites it
# reaches (tests/fault/fault_inject.c), then once per site with that call
# failing, and once more for a site listed with a second error. The
# scenarios back up, update, restore, and verify, and repair a portable
# backup with one journal record damaged and a folder it does not record,
# and update one with a record damaged and a copy no record names; a backup
# and its restore also run with the scope migr picks from HOME, and an
# update and a restore as dry runs; a backup keeps a copy of migr, a
# restore reads a backup from before manifests, and an update and a restore
# take the system's network configuration, the restore with /etc behind an
# overlay of its own and SELinux seeming to run. After every failed run:
#   - migr ended with 0, 1, or 2, not a crash or a hang;
#   - what the run only reads is unchanged (the source of a backup or a
#     verify, the backup a restore reads);
#   - a run that ended with 0 left a whole result: a dry run's is HOME
#     and the backup it would update as they were;
#   - the same command run again without a fault finishes, and its result
#     is whole: the backup, repaired or not, verifies and nothing but
#     backups is left beside it, the restored home equals the source; after
#     a second error, which can mislead migr, it may also end with 1 or 2.
# The portable and network scenarios need root and run only then; the copy
# of migr needs a static C library.
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

# What a restore runs to apply network settings does nothing here.
mkdir "$WORK/netbin" "$WORK/overlay"
for command in nmcli systemctl update-crypto-policies; do
    printf '#!/bin/sh\nexit 0\n' > "$WORK/netbin/$command"
    chmod +x "$WORK/netbin/$command"
done

# A backup that keeps a copy of migr takes the static build beside the
# running binary; any static executable stands in for it. Without a static
# C library the scenario is skipped.
SELF_MIGR=""
mkdir "$WORK/self"
if printf 'int main(void) { return 0; }\n' |
       "${CC:-cc}" -static -x c -o "$WORK/self/migr-static" - 2> /dev/null; then
    cp "$MIGR" "$WORK/self/migr"
    SELF_MIGR="$WORK/self/migr"
fi

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
# symlink takes only trusted.* ones, which need root), names that differ
# only in case, which vfat takes for one, and a name with a letter outside
# ASCII, which a portable backup reads back; a portable backup keeps no FIFO.
# A socket, which a backup leaves out with a warning, and a file that an
# update finds turned into one. Beside the folder, another name of one of
# its files and a symlink, each a root of its own.
make_source() {
    local scenario="$1" notes="$2/notes"
    mkdir -p "$notes/sub/deep" "$notes/Dir" "$notes/dir" "$notes/Old" \
        "$notes/old"
    echo "alpha" > "$notes/a.txt"
    echo "beta" > "$notes/sub/b.txt"
    echo "gamma" > "$notes/sub/deep/c.txt"
    : > "$notes/empty"
    head -c 200000 /dev/urandom > "$notes/large.bin"
    ln -s a.txt "$notes/link"
    ln "$notes/a.txt" "$notes/hard"
    echo "upper" > "$notes/Case.txt"
    echo "lower" > "$notes/case.txt"
    echo "delta" > "$notes/café.txt"
    echo "one" > "$notes/Dir/x"
    echo "two" > "$notes/dir/x"
    echo "three" > "$notes/Old/y"
    echo "four" > "$notes/old/y"
    echo "a file for now" > "$notes/later"
    make_socket "$notes/socket"
    ln "$notes/a.txt" "$2/solo.txt"
    ln -s notes/a.txt "$2/solo-link"
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

make_socket() {
    python3 -c 'import socket, sys
socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$1"
}

# Path, kind, mode, mtime, and for all but folders size, link count, and
# link target, of everything below a folder but logs/ and the sockets no
# backup keeps; then its extended attributes and its files' content.
snapshot() {
    (cd "$1" &&
     find . -mindepth 1 \( -path ./logs -o -type s \) -prune -o \
         -type d -printf '%p|d|%m|%T@\n' -o \
         -printf '%p|%y|%m|%T@|%s|%n|%l\n' | LC_ALL=C sort &&
     find . -mindepth 1 \( -path ./logs -o -type s \) -prune -o -print0 |
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

# The backup in the template a restore reads; a legacy one has no
# versioned name.
restore_source() {
    case "$1" in
        *-legacy-*) echo "$2/legacy" ;;
        *) containers "$2" ;;
    esac
}

# Each scenario has its folder D: D/home is HOME, D/answer migr's input.
# A backup, an update, a verify, which lists the files it finds damaged in
# the backup, or a repair, which mends it in place, writes D/target (or the
# vfat mount's target), copied from its template before each run. A restore
# writes D/home, emptied before each run, and reads the backup in the
# template.

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

# PRELOAD names the shim for this run alone, past timeout; MIGR_HOME, when
# set, the home it runs in.
run_migr() {
    local dir="$1"
    shift
    HOME="${MIGR_HOME:-$dir/home}" PATH="$WORK/bin:$STUBS:$PATH" timeout 60 \
        env ${PRELOAD:+LD_PRELOAD="$PRELOAD"} "$MIGR" "$@" \
        < "$dir/answer" > "$dir/output" 2>&1
}

# As run_migr, in a mount namespace of its own where /etc is an overlay on
# a tmpfs: what the run writes to the system's configuration is gone when
# it ends, and the commands that would apply it are stubs. A tmpfs on
# /sys/fs holds selinux/enforce, so the restore relabels what it restored,
# through the stub restorecon.
run_migr_isolated() {
    local dir="$1"
    shift
    HOME="${MIGR_HOME:-$dir/home}" PATH="$WORK/netbin:$WORK/bin:$STUBS:$PATH" \
        timeout 60 \
        unshare --mount --propagation private bash -c '
            mount -t tmpfs tmpfs "$1" &&
            mkdir "$1/upper" "$1/work" &&
            mount -t overlay overlay \
                -o "lowerdir=/etc,upperdir=$1/upper,workdir=$1/work" /etc &&
            mount -t tmpfs tmpfs /sys/fs &&
            mkdir /sys/fs/selinux && : > /sys/fs/selinux/enforce ||
                exit 3
            shift
            exec "$@"' isolate "$WORK/overlay" \
        env ${PRELOAD:+LD_PRELOAD="$PRELOAD"} "$MIGR" "$@" \
        < "$dir/answer" > "$dir/output" 2>&1
}

# A scoped backup takes what migr picks from HOME, the others a folder and
# the two items beside it; the arguments after the target go to migr. A
# network or system scenario also takes the system's own network
# configuration, which only root can read, and a self scenario a copy of
# migr.
backup_into() {
    local scenario="$1" dir="$2" target="$3"
    shift 3
    case "$scenario" in
        *-network-* | *-system-*) set -- --include-network-config "$@" ;;
        *-self-*) set -- --include-self "$@" ;;
    esac
    case "$scenario" in
        *-scoped-*) run_migr "$dir" backup "$target" "$@" ;;
        *-moved-*) run_migr "$dir" backup "$target" "$dir/home/notes" \
               "$dir/home/solo.txt" "$dir/home/solo-link" "$dir/home/.config" \
               "$dir/home/.local" "$@" ;;
        *) run_migr "$dir" backup "$target" "$dir/home/notes" \
               "$dir/home/solo.txt" "$dir/home/solo-link" "$@" ;;
    esac
}

# The home a restore writes: in a moved scenario another one than the
# backup's.
restore_home() {
    case "$1" in
        *-moved-*) echo "$2/moved" ;;
        *) echo "$2/home" ;;
    esac
}

# A backup from before manifests: the home's own folders and dotfiles at
# its top.
make_legacy_backup() {
    mkdir "$2/legacy" &&
        cp -a "$1/home/Documents" "$1/home/.ssh" "$1/home/.bashrc" \
            "$2/legacy/"
}

dry() {
    case "$1" in
        *-dry-*) return 0 ;;
        *) return 1 ;;
    esac
}

# What a dry run leaves as it was: HOME, and the backup it would update.
untouched() {
    local scenario="$1" dir="$2"
    snapshot "$dir/home"
    case "$scenario" in
        *-update) snapshot "$(target_dir "$scenario" "$dir")" ;;
    esac
}

setup() {
    local scenario="$1" dir="$2" template journal record offset unrecorded groups
    local bookmarks storage
    template=$(template_dir "$scenario" "$dir")
    rm -rf "$dir" "$template"
    mkdir -p "$dir/home" "$template"
    echo y > "$dir/answer"
    case "$scenario" in
        *-scoped-* | *-legacy-*)
            make_source "$scenario" "$dir/home/Documents"
            mkdir -m 700 "$dir/home/.ssh"
            echo "Host *" > "$dir/home/.ssh/config"
            echo "alias ll='ls -l'" > "$dir/home/.bashrc"
            ;;
        *) make_source "$scenario" "$dir/home" ;;
    esac
    case "$scenario" in
        *-scoped-*)
            # Where the XDG folders are, which a new install names for
            # itself; a restore keeps its file.
            mkdir "$dir/home/.config"
            printf 'XDG_DOCUMENTS_DIR="$HOME/Documents"\n' \
                > "$dir/home/.config/user-dirs.dirs"
            printf '# from the new install\nXDG_DOCUMENTS_DIR="$HOME/Documents"\n' \
                > "$dir/user-dirs.dirs"
            ;;
        *-moved-*)
            # Bookmarks that name the backup's home, which a restore into
            # another one points at that.
            mkdir -p "$dir/home/.config/gtk-3.0"
            echo "file://$dir/home/notes notes" \
                > "$dir/home/.config/gtk-3.0/bookmarks"
            # Podman's storage, whose container state such a restore leaves
            # out (D94); it holds no container.
            storage="$dir/home/.local/share/containers/storage"
            mkdir -p "$storage/libpod" "$storage/overlay/l" \
                "$storage/overlay-containers" "$storage/overlay-layers"
            echo "[]" > "$storage/overlay-containers/containers.json"
            echo "[]" > "$storage/overlay-layers/layers.json"
            ;;
    esac
    # A source changed in the second its backup is taken is not compared.
    sleep 1
    case "$scenario" in
        *-backup) ;;
        *-legacy-*) make_legacy_backup "$dir" "$template" || return ;;
        *) backup_into "$scenario" "$dir" "$template" || return ;;
    esac
    case "$scenario" in
        *-update)
            # The backup has taken a folder that became a file, one whose
            # name vfat takes for another folder's.
            rm -r "$dir/home/notes/old"
            echo "a file now" > "$dir/home/notes/old"
            sleep 1
            backup_into "$scenario" "$dir" "$template" || return
            echo "alpha, changed" > "$dir/home/notes/a.txt"
            rm "$dir/home/notes/sub/b.txt"
            echo "new" > "$dir/home/notes/sub/new.txt"
            echo "upper again" > "$dir/home/notes/CASE.txt"
            # A folder moved from one nested place to another, a file that
            # became a folder and a folder that became a file, a symlink
            # pointed elsewhere, and a new hard link.
            mv "$dir/home/notes/sub/deep" "$dir/home/notes/Dir/deep"
            rm "$dir/home/notes/empty"
            mkdir "$dir/home/notes/empty"
            rm -r "$dir/home/notes/dir"
            echo "a file now" > "$dir/home/notes/dir"
            ln -sfn sub/new.txt "$dir/home/notes/link"
            ln "$dir/home/notes/large.bin" "$dir/home/notes/large-again"
            rm "$dir/home/notes/later"
            make_socket "$dir/home/notes/later"
            sleep 1
            ;;
        # A dry run installs nothing, so it keeps the lists to preview.
        *-dry-restore) ;;
        *-restore)
            mv "$dir/home" "$dir/expected"
            case "$scenario" in
                *-scoped-*)
                    cp -p "$dir/user-dirs.dirs" \
                        "$dir/expected/.config/user-dirs.dirs"
                    ;;
                *-moved-*)
                    # Rewritten in place, its times kept, as a restore does.
                    bookmarks="$dir/expected/.config/gtk-3.0/bookmarks"
                    touch -r "$bookmarks" "$dir/times"
                    echo "file://$dir/moved/notes notes" > "$bookmarks"
                    touch -r "$dir/times" "$bookmarks"
                    storage="$dir/expected/.local/share/containers/storage"
                    touch -r "$storage" "$dir/times"
                    rm -r "$storage/overlay-containers"
                    touch -r "$dir/times" "$storage"
                    rm "$dir/times"
                    ;;
            esac
            # Without its lists of packages and Flatpak applications, a
            # restore neither installs software nor waits for a network.
            rm -f "$(restore_source "$scenario" "$template")"/{packages,flatpak-apps}.txt
            # A group this system does not have is left for the user, in a
            # list the restore writes next to the backup.
            groups="$(restore_source "$scenario" "$template")/groups.txt"
            if [ -f "$groups" ]; then
                echo "migr-sweep-absent" >> "$groups"
            fi
            ;;
        *-repair)
            # The kind of one record no longer parses.
            journal="$(containers "$template")/sidecar.migr"
            record='ENTRY\x00[^\x00]*\x00sub/b\.txt\x00b\.txt\x00\x00\K'
            offset=$(grep -obaP "${record}regular" "$journal" | cut -d: -f1)
            [ -n "$offset" ] || return
            printf '#' | dd of="$journal" bs=1 seek="$offset" conv=notrunc \
                status=none
            # And payload no record names: a folder with a file in it.
            unrecorded="$(containers "$template")/data/notes/sub/unrecorded"
            mkdir "$unrecorded"
            echo "no record" > "$unrecorded/x"
            ;;
    esac
    case "$scenario" in
        *-damaged-update)
            # The record of a file that left the source no longer parses,
            # and a copy no record names is where a new file goes.
            journal="$(containers "$template")/sidecar.migr"
            record='ENTRY\x00[^\x00]*\x00sub/b\.txt\x00b\.txt\x00\x00\K'
            offset=$(grep -obaP "${record}regular" "$journal" | tail -n 1 |
                cut -d: -f1)
            [ -n "$offset" ] || return
            printf '#' | dd of="$journal" bs=1 seek="$offset" conv=notrunc \
                status=none
            echo "older copy" > \
                "$(containers "$template")/data/notes/sub/new.txt"
            ;;
    esac
}

fresh() {
    local scenario="$1" dir="$2" home
    case "$scenario" in
        *-restore)
            home=$(restore_home "$scenario" "$dir")
            rm -rf "${home:?}"
            mkdir "$home"
            # A new install's home: a folder of its own, and a shell profile
            # and the XDG folders' names the backup has its own of.
            case "$scenario" in
                *-scoped-*)
                    mkdir "$home/Documents" "$home/.config"
                    echo "# from the new install" > "$home/.bashrc"
                    cp -p "$dir/user-dirs.dirs" "$home/.config/user-dirs.dirs"
                    ;;
            esac
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
    if dry "$scenario"; then
        untouched "$scenario" "$dir" > "$dir/untouched"
    fi
}

act() {
    local scenario="$1" dir="$2" backup target options=() MIGR_HOME
    case "$scenario" in
        *-restore) MIGR_HOME=$(restore_home "$scenario" "$dir") ;;
    esac
    backup=$(restore_source "$scenario" "$(template_dir "$scenario" "$dir")")
    target=$(target_dir "$scenario" "$dir")
    if dry "$scenario"; then
        options=(--dry-run)
    fi
    case "$scenario" in
        *-self-*) local MIGR="$SELF_MIGR" ;;
    esac
    case "$scenario" in
        *-system-restore)
            run_migr_isolated "$dir" restore "$backup" "${options[@]}" ;;
        *-restore) run_migr "$dir" restore "$backup" "${options[@]}" ;;
        *-verify) run_migr "$dir" verify "$(containers "$target")" ;;
        *-repair) run_migr "$dir" repair "$(containers "$target")" ;;
        *) backup_into "$scenario" "$dir" "$target" "${options[@]}" ;;
    esac
}

read_only() {
    local scenario="$1" dir="$2"
    case "$scenario" in
        *-restore)
            restore_source "$scenario" "$(template_dir "$scenario" "$dir")"
            ;;
        *-scoped-*) echo "$dir/home" ;;
        *) echo "$dir/home/notes" ;;
    esac
}

# Whether a run left a whole result; a verify's is the status it ended with.
# With "more", a restored home may also hold what a restore leaves out.
whole() {
    local scenario="$1" dir="$2" more="${3:-}" backup target template home
    local stamp verified=0
    case "$scenario" in
        *-verify) return 0 ;;
        *-dry-*)
            [ "$(untouched "$scenario" "$dir")" = "$(cat "$dir/untouched")" ]
            ;;
        *-restore)
            # A failed restore keeps its log in HOME, in folders the source
            # does not have.
            home=$(restore_home "$scenario" "$dir")
            stamp=$(stat -c %y "$home/.local" 2>/dev/null)
            rm -rf "$home/.local/state/migr"
            rmdir "$home/.local/state" "$home/.local" 2>/dev/null
            # Taking them out changes the time of a .local the backup holds.
            if [ -d "$home/.local" ] &&
               [ "$(stat -c %y "$home/.local")" != "$stamp" ]; then
                touch -r "$dir/expected/.local" "$home/.local"
            fi
            if [ -n "$more" ]; then
                [ -z "$(LC_ALL=C comm -23 \
                    <(snapshot "$dir/expected" | LC_ALL=C sort) \
                    <(snapshot "$home" | LC_ALL=C sort))" ]
            else
                [ "$(snapshot "$dir/expected")" = "$(snapshot "$home")" ]
            fi
            ;;
        *)
            # Nothing but backups is left in the target.
            target=$(target_dir "$scenario" "$dir")
            [ -z "$(find "$target" -mindepth 1 -maxdepth 1 ! -name 'migr-*' \
                -print -quit)" ] || return
            template=$(containers "$(template_dir "$scenario" "$dir")")
            while IFS= read -r backup; do
                # A second error that hid the damaged backup an update takes
                # leaves it as it was, beside the new one.
                if [ -n "${misled:-}" ] &&
                   cmp -s "$backup/sidecar.migr" "$template/sidecar.migr"; then
                    continue
                fi
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

    local count=0 missed=0 site guarded before allowed misled told_gone
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
        # A second error tells migr what is not so, such as a name gone that
        # is there; what it did about that can leave a state the next run
        # refuses, so that run may end as the one before could.
        misled=""
        allowed=0
        case "$site" in *' '*) misled=1 allowed=2 ;; esac
        # An item told gone can be one that may well be missing, such as a
        # folder a legacy backup does not hold or a file a restore would
        # point at the new home; a run that goes on without it is whole as
        # far as migr can tell, and the run after it must be, though it may
        # keep what the misled run restored and a restore leaves out (D94):
        # a restore removes nothing it finds.
        case "$site" in
            *' ENOENT') told_gone=more ;;
            *) told_gone="" ;;
        esac
        if [ "$status" -eq 0 ] && [ -z "$told_gone" ] &&
           ! whole "$scenario" "$dir"; then
            fail "$scenario" "$site: ended with 0 but not whole" "$dir/output"
            continue
        fi
        act "$scenario" "$dir"
        status=$?
        if [ "$status" -gt "$allowed" ] ||
           { [ "$status" -eq 0 ] &&
             ! whole "$scenario" "$dir" "$told_gone"; }; then
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
               native-scoped-backup native-scoped-restore native-dry-update
               native-scoped-dry-restore native-legacy-restore
               native-moved-restore)
    if [ -n "$SELF_MIGR" ]; then
        scenarios+=(native-self-backup)
    else
        echo "The self scenario skipped: it needs a static C library."
    fi
    if [ "$(id -u)" -eq 0 ]; then
        scenarios+=(native-network-update native-system-restore)
    fi
    if [ "$(id -u)" -eq 0 ] && command -v mkfs.vfat > /dev/null; then
        scenarios+=(portable-backup portable-update portable-restore
                    portable-verify portable-repair portable-damaged-update
                    portable-scoped-backup portable-scoped-restore
                    portable-dry-update portable-scoped-dry-restore)
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

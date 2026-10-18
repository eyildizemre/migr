#!/usr/bin/env bash
# Fault-injection sweep: runs each scenario once to list the call sites it
# reaches (tests/fault/fault_inject.c), then once per site with that call
# failing. After every failed run:
#   - migr ended with 0, 1, or 2, not a crash or a hang;
#   - what the run only reads is unchanged (the source of a backup, the
#     backup a restore reads);
#   - the same command run again without a fault finishes, and its result
#     is whole: the backup verifies against the source, the restored folder
#     equals the source.
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

failures=0

# A folder with each kind of item a backup keeps; a portable one keeps no
# FIFO.
make_source() {
    local scenario="$1" notes="$2/notes"
    mkdir -p "$notes/sub/deep"
    echo "alpha" > "$notes/a.txt"
    echo "beta" > "$notes/sub/b.txt"
    echo "gamma" > "$notes/sub/deep/c.txt"
    : > "$notes/empty"
    head -c 200000 /dev/urandom > "$notes/large.bin"
    ln -s a.txt "$notes/link"
    ln "$notes/a.txt" "$notes/hard"
    case "$scenario" in
        native-*) mkfifo "$notes/pipe" ;;
    esac
    chmod 600 "$notes/sub/b.txt"
}

# Path, kind, mode, mtime, and for all but folders size, link count, and
# link target, of everything below a folder but logs/; then its files'
# content.
snapshot() {
    (cd "$1" &&
     find . -path ./logs -prune -o -type d -printf '%p|d|%m|%T@\n' -o \
         -printf '%p|%y|%m|%T@|%s|%n|%l\n' | LC_ALL=C sort &&
     find . -path ./logs -prune -o -type f -print0 | LC_ALL=C sort -z |
         xargs -0 -r md5sum)
}

container_of() {
    local found
    for found in "$1"/migr-*; do
        case "$found" in
            *.partial | *.updating) ;;
            *) [ -d "$found" ] && { echo "$found"; return; } ;;
        esac
    done
}

# Each scenario has its folder D: D/home is HOME, D/answer migr's input.
# A backup or update writes D/target (or the vfat mount's target), copied
# from its template before each run; a restore writes D/home, emptied
# before each run, from the backup in the template.

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
    HOME="$dir/home" PATH="$STUBS:$PATH" timeout 60 \
        env ${PRELOAD:+LD_PRELOAD="$PRELOAD"} "$MIGR" "$@" \
        < "$dir/answer" > "$dir/output" 2>&1
}

setup() {
    local scenario="$1" dir="$2" template
    template=$(template_dir "$scenario" "$dir")
    rm -rf "$dir" "$template"
    mkdir -p "$dir/home" "$template"
    echo y > "$dir/answer"
    make_source "$scenario" "$dir/home"
    # A source changed in the second its backup is taken is not compared.
    sleep 1
    case "$scenario" in
        *-update | *-restore)
            run_migr "$dir" backup "$template" "$dir/home/notes" || return
            ;;
    esac
    case "$scenario" in
        *-update)
            echo "alpha, changed" > "$dir/home/notes/a.txt"
            rm "$dir/home/notes/sub/b.txt"
            echo "new" > "$dir/home/notes/sub/new.txt"
            sleep 1
            ;;
        *-restore) mv "$dir/home/notes" "$dir/expected" ;;
    esac
}

fresh() {
    local scenario="$1" dir="$2"
    case "$scenario" in
        *-restore)
            rm -rf "${dir:?}/home"
            mkdir "$dir/home"
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
    local scenario="$1" dir="$2"
    case "$scenario" in
        *-restore)
            run_migr "$dir" restore \
                "$(container_of "$(template_dir "$scenario" "$dir")")"
            ;;
        *)
            run_migr "$dir" backup "$(target_dir "$scenario" "$dir")" \
                "$dir/home/notes"
            ;;
    esac
}

read_only() {
    local scenario="$1" dir="$2"
    case "$scenario" in
        *-restore) container_of "$(template_dir "$scenario" "$dir")" ;;
        *) echo "$dir/home/notes" ;;
    esac
}

whole() {
    local scenario="$1" dir="$2"
    case "$scenario" in
        *-restore)
            [ "$(snapshot "$dir/expected")" = \
              "$(snapshot "$dir/home/notes")" ]
            ;;
        *)
            HOME="$dir/home" "$MIGR" verify \
                "$(container_of "$(target_dir "$scenario" "$dir")")" \
                > "$dir/verify" 2>&1
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

    local count=0 missed=0 site guarded before
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
        act "$scenario" "$dir"
        status=$?
        if [ "$status" -ne 0 ] || ! whole "$scenario" "$dir"; then
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
    scenarios=(native-backup native-update native-restore)
    if [ "$(id -u)" -eq 0 ] && command -v mkfs.vfat > /dev/null; then
        scenarios+=(portable-backup portable-update portable-restore)
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

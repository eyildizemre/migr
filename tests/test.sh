#!/bin/bash

# Halt on any error, fail on undefined variables, and catch pipeline failures
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

PORTABLE_VFAT_MOUNT=""
PORTABLE_VFAT_LOOP=""

# Every backup whose scope exports a package list forks the distribution's real
# listing command, and a single `dnf repoquery` costs more than the entire rest
# of this suite. Only Phase 5 is about that command's own output; every other
# phase just needs *a* package list to exist. So the suite runs with stubs ahead
# of the real tools on PATH, and Phase 5 restores REAL_PATH to exercise the
# genuine one exactly once.
STUB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/stubs" && pwd)"
export REAL_PATH="$PATH"
export PATH="$STUB_DIR:$PATH"

# --- 1. SETUP & TEARDOWN ---
setup() {
    TEST_DIR=$(mktemp -d) # opens a subshell, runs `mktemp -d`, and assigns output to TEST_DIR
    # export makes the variable available to subprocesses
    # since child processes won't have access to parent shell's variables by default
    export TEST_DIR
    export HOME="$TEST_DIR/home"
    export BACKUP_DIR="$TEST_DIR/backup_drive"

    mkdir -p "$HOME/Documents"
    mkdir -p "$HOME/Desktop"
    mkdir -p "$HOME/Downloads"
    mkdir -p "$HOME/Pictures"
    mkdir -p "$HOME/Projects"
    mkdir -p "$HOME/.ssh"
    mkdir -p "$HOME/.gnupg"
    mkdir -p "$HOME/.mozilla/firefox/profile"
    mkdir -p "$HOME/.config/google-chrome/Default"
    mkdir -p "$BACKUP_DIR"

    echo "test doc"  > "$HOME/Documents/note.txt"
    mkfifo "$HOME/Documents/events.fifo"
    echo "secret"    > "$HOME/.ssh/config"
    echo "gituser"   > "$HOME/.gitconfig"
    echo "alias ll='ls -la'" > "$HOME/.bashrc"
    echo "export PATH"       > "$HOME/.profile"
    ln -s "$HOME/Documents/note.txt" "$HOME/Documents/shortcut"
    # 0600 file + an absolute symlink to it: backing up the symlink must not
    # chmod the target. Regression fixture for the symlink source-mutation bug.
    chmod 600 "$HOME/.ssh/config"
    ln -s "$HOME/.ssh/config" "$HOME/Documents/cfg-link"
    echo "places"    > "$HOME/.mozilla/firefox/profile/places.sqlite"
    echo "prefs"     > "$HOME/.config/google-chrome/Default/Preferences"
}

teardown() {
    if [ -n "$PORTABLE_VFAT_MOUNT" ]; then
        umount -l "$PORTABLE_VFAT_MOUNT" 2>/dev/null || true
    fi
    if [ -n "$PORTABLE_VFAT_LOOP" ]; then
        losetup -d "$PORTABLE_VFAT_LOOP" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}

# Execute teardown on exit no matter what
trap teardown EXIT


# --- 2. HELPER FUNCTIONS ---
assert_contains() {
    local output="$1"
    local expected="$2"

    if [[ "$output" == *"$expected"* ]]; then
        echo -e "  ${GREEN}✓${NC} '$expected' found."
    else
        echo -e "  ${RED}✗${NC} Expected '$expected' not found!"
        echo "  Output:"
        echo "$output"
        exit 1
    fi
}

assert_not_contains() {
    local output="$1"
    local unexpected="$2"

    if [[ "$output" == *"$unexpected"* ]]; then
        echo -e "  ${RED}✗${NC} Unexpected '$unexpected' found!"
        echo "  Output:"
        echo "$output"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} '$unexpected' not found."
    fi
}

assert_file_exists() {
    if [ -e "$1" ]; then
        echo -e "  ${GREEN}✓${NC} '$1' exists."
    else
        echo -e "  ${RED}✗${NC} Expected file/dir not found: '$1'"
        exit 1
    fi
}

# `if` suppresses set -e, letting us safely test commands expected to fail
assert_exits_nonzero() {
    if "$@" 2>/dev/null; then # "$@" is used to pass spaces and multiple arguments correctly
        echo -e "  ${RED}✗${NC} Expected non-zero exit from: $*"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Correctly exited non-zero: $*"
    fi
}

# Stronger form: the command must exit non-zero AND print an expected message.
# This distinguishes a clean, intentional refusal from a crash that also happens
# to exit non-zero (e.g. a segfault on a NULL path), which a bare exit-code check
# would wave through.
assert_fails_with() {
    local expected="$1"; shift
    local out rc
    set +e
    out=$("$@" 2>&1)
    rc=$?
    set -e
    if [ "$rc" -ne 0 ] && [[ "$out" == *"$expected"* ]]; then
        # Deliberately omit "$*" here: these commands carry a multi-KB HOME that
        # would flood the log. The expected message identifies the case.
        echo -e "  ${GREEN}✓${NC} Refused with '$expected'"
    else
        echo -e "  ${RED}✗${NC} Expected non-zero exit and '$expected' from: $*"
        echo "  exit=$rc  output: $out"
        exit 1
    fi
}

# The success-path counterpart to assert_fails_with(): the command must exit
# zero AND print the expected text -- used for -h/--help, which must win over
# every other flag/action combination rather than being caught by a
# cross-cutting scope check meant for ordinary arguments.
assert_succeeds_with() {
    local expected="$1"; shift
    local out rc
    set +e
    out=$("$@" 2>&1)
    rc=$?
    set -e
    if [ "$rc" -eq 0 ] && [[ "$out" == *"$expected"* ]]; then
        echo -e "  ${GREEN}✓${NC} Succeeded with '$expected': $*"
    else
        echo -e "  ${RED}✗${NC} Expected zero exit and '$expected' from: $*"
        echo "  exit=$rc  output: $out"
        exit 1
    fi
}

# The finalized and in-progress container grammars (docs/DECISIONS.md D15) are
# matched separately and exactly. A glob that accepts either would let a test
# treat a leftover ".partial" — the one thing a successful backup must never
# leave behind — as its result.
containers_matching() {
    local dir="$1" want="$2" entry leaf
    local stamp='migr_backup_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9]'
    shopt -s nullglob
    for entry in "$dir"/migr_backup_*; do
        [ -d "$entry" ] || continue
        leaf=$(basename "$entry")
        if [ "$want" = partial ]; then
            [[ "$leaf" == *.partial ]] || continue
            leaf="${leaf%.partial}"
        else
            [[ "$leaf" == *.partial ]] && continue
        fi
        # shellcheck disable=SC2254
        case "$leaf" in
            $stamp|$stamp-[1-9]*) printf '%s\n' "$entry" ;;
        esac
    done
    shopt -u nullglob
}

# Returns the single finalized container under $1, failing the suite if there
# is not exactly one — "exactly one" is itself part of what the tests assert.
sole_final_container() {
    local dir="$1" found count
    found=$(containers_matching "$dir" final)
    count=$(printf '%s' "$found" | grep -c . || true)
    if [ "$count" -ne 1 ]; then
        echo -e "  ${RED}✗${NC} Expected exactly one finalized container under '$dir', found $count" >&2
        exit 1
    fi
    printf '%s' "$found"
}

assert_no_partial() {
    local dir="$1" leftover
    leftover=$(containers_matching "$dir" partial)
    if [ -n "$leftover" ]; then
        echo -e "  ${RED}✗${NC} A '.partial' container survived a successful backup: $leftover"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} No '.partial' container left behind."
}


# --- 3. LIFECYCLE ---
test_report() {
    echo -e "${BLUE}::${NC} Phase 1: report"

    local output default_output bare_output critical_output comprehensive_output
    local critical_summary implicit_summary comprehensive_summary without_profile
    local critical_verbose comprehensive_verbose legacy_verbose summary_verbose
    local depth_zero depth_two depth_root summary_depth
    local critical_root_count comprehensive_root_count legacy_root_count
    local raw_status_calls captured_output
    output=$(../migr report)

    raw_status_calls=$(grep -nE 'printf\("Error: |printf\("Warning: ' \
        ../src/*.c || true)
    if [ -n "$raw_status_calls" ]; then
        echo -e "  ${RED}✗${NC} Raw Error/Warning printf call remains in src/"
        echo "$raw_status_calls"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Error/Warning output uses the status helpers."
    fi

    if captured_output=$(HOME="$TEST_DIR/missing-home" \
        ../migr report --critical 2>&1); then
        echo -e "  ${RED}✗${NC} Missing HOME unexpectedly allowed report execution."
        exit 1
    elif [[ "$captured_output" == *$'\033['* ]]; then
        echo -e "  ${RED}✗${NC} Captured status output contains ANSI escape codes."
        echo "$captured_output"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Captured status output stays free of ANSI escape codes."
    fi

    assert_contains "$output" ".bashrc"
    assert_contains "$output" ".ssh"
    assert_contains "$output" "Documents"

    # The no-command and explicit report forms were both the legacy default
    # before scoped reporting existed. Keep their complete output byte-identical.
    default_output="$output"
    bare_output=$(../migr)
    if [ "$default_output" = "$bare_output" ]; then
        echo -e "  ${GREEN}✓${NC} No-flag report output remains byte-for-byte stable."
    else
        echo -e "  ${RED}✗${NC} No-flag report output changed between default entry points."
        exit 1
    fi
    assert_contains "$default_output" \
        "(Documents, Downloads, Pictures, .ssh, .gnupg, .gitconfig, .bashrc)"

    critical_output=$(../migr report --critical)
    assert_contains "$critical_output" "Dotfiles & Config"
    assert_contains "$critical_output" ".profile"
    assert_contains "$critical_output" "Firefox"
    assert_not_contains "$critical_output" ".mozilla"
    assert_not_contains "$critical_output" "google-chrome"
    assert_contains "$critical_output" "Critical estimate"
    if [[ "$critical_output" == *"Dev Tools (re-downloadable)"* ]]; then
        echo -e "  ${RED}✗${NC} Critical scoped report included informational dev tools."
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Critical scoped report follows the real backup plan."
    fi

    depth_root="$HOME/Documents/report-depth"
    mkdir -p "$depth_root/level1/level2/leaf"
    printf 'depth root\n' > "$depth_root/root.txt"
    printf 'depth one\n' > "$depth_root/level1/file.txt"
    printf 'depth two\n' > "$depth_root/level1/level2/file.txt"
    printf 'depth leaf\n' > "$depth_root/level1/level2/leaf/file.txt"

    critical_verbose=$(../migr report --critical -v)
    assert_contains "$critical_verbose" "($HOME/Documents)"
    assert_contains "$critical_verbose" "($depth_root)"
    assert_not_contains "$critical_verbose" "($depth_root/level1)"
    assert_not_contains "$critical_verbose" "($HOME/.ssh/config)"
    assert_not_contains "$critical_verbose" "Measuring:"
    critical_root_count=$(grep -F -c "($HOME/Documents)" <<<"$critical_verbose" || true)
    if [ "$critical_root_count" -eq 1 ]; then
        echo -e "  ${GREEN}✓${NC} Critical verbose keeps one enriched line per root."
    else
        echo -e "  ${RED}✗${NC} Critical verbose printed the Documents root $critical_root_count times."
        exit 1
    fi
    comprehensive_verbose=$(../migr report --comprehensive -v)
    assert_contains "$comprehensive_verbose" "($HOME/Documents)"
    assert_contains "$comprehensive_verbose" "($depth_root)"
    assert_not_contains "$comprehensive_verbose" "Measuring:"
    comprehensive_root_count=$(grep -F -c "($HOME/Documents)" <<<"$comprehensive_verbose" || true)
    if [ "$comprehensive_root_count" -eq 1 ]; then
        echo -e "  ${GREEN}✓${NC} Comprehensive verbose keeps one enriched line per root."
    else
        echo -e "  ${RED}✗${NC} Comprehensive verbose printed the Documents root $comprehensive_root_count times."
        exit 1
    fi
    legacy_verbose=$(../migr report -v)
    assert_contains "$legacy_verbose" "($HOME/Documents)"
    assert_contains "$legacy_verbose" "($depth_root)"
    assert_not_contains "$legacy_verbose" "Measuring:"
    legacy_root_count=$(grep -F -c "($HOME/Documents)" <<<"$legacy_verbose" || true)
    if [ "$legacy_root_count" -eq 1 ]; then
        echo -e "  ${GREEN}✓${NC} Legacy verbose keeps one enriched line per root."
    else
        echo -e "  ${RED}✗${NC} Legacy verbose printed the Documents root $legacy_root_count times."
        exit 1
    fi

    depth_zero=$(../migr report --critical --max-depth=0)
    assert_contains "$depth_zero" "($HOME/Documents)"
    assert_not_contains "$depth_zero" "($depth_root)"
    depth_two=$(../migr report --critical --max-depth=2)
    assert_contains "$depth_two" "($depth_root)"
    assert_contains "$depth_two" "($depth_root/level1)"
    assert_not_contains "$depth_two" "($depth_root/level1/level2)"
    assert_fails_with "Error: --max-depth must be a non-negative integer." \
        ../migr report --critical --max-depth=garbage
    assert_fails_with "Error: --max-depth must be a non-negative integer." \
        ../migr report --critical --max-depth=-1
    assert_fails_with "Error: --max-depth must be a non-negative integer." \
        ../migr report --critical --max-depth=full
    assert_fails_with "Error: --max-depth applies only to 'report'." \
        ../migr backup "$BACKUP_DIR" --max-depth=1
    assert_fails_with "Error: --max-depth applies only to 'report'." \
        ../migr restore "$BACKUP_DIR" --max-depth=1
    rm -rf "$depth_root"

    # Make the profile contribution large enough that the human formatter cannot
    # round it away, then prove the live critical total changes when that root is
    # absent. Restore the small fixture before the remaining phases.
    printf '%4096s\n' '' > "$HOME/.profile"
    critical_summary=$(../migr report --critical -s)
    implicit_summary=$(../migr report --summary)
    if [[ "$critical_summary" =~ ^[0-9]+(\.[0-9]+)?(B|K|M|G)$ ]] && \
       [ "$critical_summary" = "$implicit_summary" ]; then
        echo -e "  ${GREEN}✓${NC} Critical summary is exactly one line and is the default scoped summary."
    else
        echo -e "  ${RED}✗${NC} Critical summary format or implicit-scope default is wrong: '$critical_summary'"
        exit 1
    fi
    summary_verbose=$(../migr report --critical -s -v)
    if [ "$summary_verbose" = "$critical_summary" ]; then
        echo -e "  ${GREEN}✓${NC} Summary suppresses verbose detail."
    else
        echo -e "  ${RED}✗${NC} Summary and summary+verbose outputs differ."
        exit 1
    fi
    summary_depth=$(../migr report --critical -s --max-depth=2)
    if [ "$summary_depth" = "$critical_summary" ]; then
        echo -e "  ${GREEN}✓${NC} Summary suppresses an explicit max-depth breakdown."
    else
        echo -e "  ${RED}✗${NC} Summary and summary+max-depth outputs differ."
        exit 1
    fi
    mv "$HOME/.profile" "$HOME/.profile.report-test"
    without_profile=$(../migr report --critical -s)
    mv "$HOME/.profile.report-test" "$HOME/.profile"
    if [ "$critical_summary" != "$without_profile" ]; then
        echo -e "  ${GREEN}✓${NC} .profile contributes to the critical scoped total."
    else
        echo -e "  ${RED}✗${NC} .profile was not included in the critical scoped total."
        exit 1
    fi

    comprehensive_output=$(../migr report --comprehensive)
    assert_contains "$comprehensive_output" "Comprehensive estimate"
    assert_contains "$comprehensive_output" "Desktop"
    assert_contains "$comprehensive_output" "Projects"
    assert_contains "$comprehensive_output" "Firefox"
    assert_not_contains "$comprehensive_output" ".mozilla"
    assert_not_contains "$comprehensive_output" "google-chrome"
    comprehensive_summary=$(../migr report --comprehensive --summary)
    if [[ "$comprehensive_summary" =~ ^[0-9]+(\.[0-9]+)?(B|K|M|G)$ ]]; then
        echo -e "  ${GREEN}✓${NC} Comprehensive summary is only the formatted total."
    else
        echo -e "  ${RED}✗${NC} Comprehensive summary contains extra output: '$comprehensive_summary'"
        exit 1
    fi
}

test_dry_run() {
    echo -e "${BLUE}::${NC} Phase 2: --dry-run"

    local output plain_output verbose_output
    output=$(../migr backup "$BACKUP_DIR" -n 2>&1)

    assert_contains "$output" "Dry run"

    # The preview must name the payload addresses the live run would use, and
    # must not invent a container name: the "-N" suffix is only settled when a
    # container is actually claimed.
    assert_contains "$output" "data/XDG_DOCUMENTS_DIR"
    assert_contains "$output" "data/BUILTIN_DOT_BASHRC"
    assert_contains "$output" "Would write manifest.txt"
    if [[ "$output" == *".partial"* ]]; then
        echo -e "  ${RED}✗${NC} Dry run named a specific container it cannot know yet"
        echo "$output"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Preview does not claim a specific container name."
    fi

    # override shell behavior of treating an empty query as literal string
    # to prevent false positives when no backup dirs exist yet
    shopt -s nullglob
    backup_dirs=("$BACKUP_DIR"/migr_backup_*)
    shopt -u nullglob # reset to default behavior
    if [ "${#backup_dirs[@]}" -gt 0 ]; then
        echo -e "  ${RED}✗${NC} Dry run wrote files to disk!"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} No files written to disk."
    fi

    plain_output="$output"
    verbose_output=$(../migr backup "$BACKUP_DIR" -n -v 2>&1)
    if [ "$plain_output" = "$verbose_output" ]; then
        echo -e "  ${GREEN}✓${NC} Native dry-run is unchanged by verbose."
    else
        echo -e "  ${RED}✗${NC} Native dry-run changed under verbose."
        exit 1
    fi
}

test_backup() {
    echo -e "${BLUE}::${NC} Phase 3: backup"

    local output
    # -v needed: without it, individual filenames are not printed
    output=$(../migr backup "$BACKUP_DIR" -v 2>&1)

    assert_contains "$output" "Finalizing (syncing to disk)..."
    assert_contains "$output" "Backup complete"
    assert_contains "$output" ".bashrc"
    assert_contains "$output" ".ssh"
    assert_contains "$output" ".gitconfig"

    # Exactly one finalized container, and nothing left in progress.
    local actual_backup
    actual_backup=$(sole_final_container "$BACKUP_DIR")
    assert_no_partial "$BACKUP_DIR"

    # Every captured object is addressed by its manifest root id under data/.
    assert_file_exists "$actual_backup/data/XDG_DOCUMENTS_DIR/note.txt"
    assert_file_exists "$actual_backup/data/BUILTIN_DOT_SSH/config"
    assert_file_exists "$actual_backup/data/BUILTIN_DOT_BASHRC"

    if [ -p "$actual_backup/data/XDG_DOCUMENTS_DIR/events.fifo" ]; then
        echo -e "  ${GREEN}✓${NC} FIFO preserved as a FIFO."
    else
        echo -e "  ${RED}✗${NC} FIFO not copied as a FIFO"
        exit 1
    fi

    # verify symlink was faithfully copied as a symlink, not a regular file
    if [ -L "$actual_backup/data/XDG_DOCUMENTS_DIR/shortcut" ]; then
        echo -e "  ${GREEN}✓${NC} Symlink preserved."
    else
        echo -e "  ${RED}✗${NC} Symlink not copied as symlink"
        exit 1
    fi

    # the absolute symlink must actually have been copied — otherwise the source-mode
    # check below passes vacuously (nothing was there to mutate the target through)
    if [ -L "$actual_backup/data/XDG_DOCUMENTS_DIR/cfg-link" ] && \
       [ "$(readlink "$actual_backup/data/XDG_DOCUMENTS_DIR/cfg-link")" = "$HOME/.ssh/config" ]; then
        echo -e "  ${GREEN}✓${NC} Absolute symlink copied with target intact."
    else
        echo -e "  ${RED}✗${NC} cfg-link not copied as a symlink to $HOME/.ssh/config"
        exit 1
    fi

    # backing up an absolute symlink must not chmod its target: the source .ssh/config
    # must still be 0600, not 0777 (regression for the symlink source-mutation bug)
    local cfg_mode
    cfg_mode=$(stat -c '%a' "$HOME/.ssh/config")
    if [ "$cfg_mode" = "600" ]; then
        echo -e "  ${GREEN}✓${NC} Symlink target permissions unchanged (source not mutated)."
    else
        echo -e "  ${RED}✗${NC} Backup mutated symlink target: .ssh/config is now $cfg_mode, expected 600"
        exit 1
    fi

    # each browser profile is its own root, so its nested source structure is
    # preserved beneath that root rather than rebuilt from the home-relative path
    assert_file_exists "$actual_backup/data/BUILTIN_BROWSER_MOZILLA/firefox/profile/places.sqlite"
    assert_file_exists "$actual_backup/data/BUILTIN_BROWSER_GOOGLE_CHROME/Default/Preferences"

    # Desktop must not appear in a critical backup
    if [ -e "$actual_backup/data/XDG_DESKTOP_DIR" ]; then
        echo -e "  ${RED}✗${NC} Desktop should not be in a critical backup"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Desktop correctly excluded from critical backup."
    fi

    # manifest.txt is the versioned format, and it is a control artifact: it and
    # packages.txt live at the container root, never inside the payload namespace
    assert_file_exists "$actual_backup/manifest.txt"
    assert_file_exists "$actual_backup/packages.txt"
    if head -1 "$actual_backup/manifest.txt" | grep -q '^MIGR_MANIFEST$' && \
       grep -q '^ROOT ID=XDG_DOCUMENTS_DIR POLICY=XDG ' "$actual_backup/manifest.txt"; then
        echo -e "  ${GREEN}✓${NC} manifest.txt is a versioned manifest carrying the root table."
    else
        echo -e "  ${RED}✗${NC} manifest.txt is not a versioned manifest!"
        cat "$actual_backup/manifest.txt"
        exit 1
    fi

    if [ -e "$actual_backup/data/manifest.txt" ] || [ -e "$actual_backup/data/packages.txt" ]; then
        echo -e "  ${RED}✗${NC} A control artifact leaked into the payload namespace"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Controls stay at the container root, out of data/."
    fi
}

test_restore() {
    echo -e "${BLUE}::${NC} Phase 4: restore"

    # wipe home to simulate a fresh system
    rm -rf "$HOME"
    mkdir -p "$HOME"

    # restore() takes the container created by backup, not $BACKUP_DIR itself
    local actual_backup
    actual_backup=$(sole_final_container "$BACKUP_DIR")

    # remove packages.txt so restore skips the sudo package install step
    rm -f "$actual_backup/packages.txt"

    local output
    # restore() calls confirm_action() — pipe "y" to mock user interaction
    output=$(echo "y" | ../migr restore "$actual_backup" 2>&1)

    assert_contains "$output" "Restore complete"
    assert_not_contains "$output" "Restored:"

    assert_file_exists "$HOME/Documents/note.txt"
    assert_file_exists "$HOME/.ssh/config"
    assert_file_exists "$HOME/.bashrc"

    if [ -p "$HOME/Documents/events.fifo" ]; then
        echo -e "  ${GREEN}✓${NC} FIFO restored as a FIFO."
    else
        echo -e "  ${RED}✗${NC} FIFO not restored as a FIFO: '$HOME/Documents/events.fifo'"
        exit 1
    fi

    # nested browser profiles must restore to the correct location, 
    # not $HOME/firefox or $HOME/google-chrome
    assert_file_exists "$HOME/.mozilla/firefox/profile/places.sqlite"
    assert_file_exists "$HOME/.config/google-chrome/Default/Preferences"
}

test_packages() {
    echo -e "${BLUE}::${NC} Phase 5: packages"

    local pkg_backup="$TEST_DIR/package-backup"
    mkdir -p "$pkg_backup"
    # The one phase that runs the distribution's genuine listing command: every
    # assertion below is about what that command actually produces, so a stub
    # here would assert nothing at all.
    PATH="$REAL_PATH" ../migr backup "$pkg_backup"

    local actual_backup
    actual_backup=$(sole_final_container "$pkg_backup")
    local pkg_file="$actual_backup/packages.txt"

    assert_file_exists "$pkg_file"

    # The listing command differs per distribution, but the file it produces must not:
    # one bare package name per line, everywhere. Restore reads the same format no
    # matter which distro wrote the backup, so a per-distro quirk in the query would
    # break restore silently. These checks are the format contract.

    local line_count
    line_count=$(wc -l < "$pkg_file")

    # A query format that emits no line separators still produces a large, non-empty
    # file — so count lines, not bytes. Any real system has more than ten packages.
    if [ "$line_count" -ge 10 ]; then
        echo -e "  ${GREEN}✓${NC} Package list has $line_count lines."
    else
        echo -e "  ${RED}✗${NC} Only $line_count line(s) — export likely collapsed into one record."
        echo "  First 200 bytes:"
        head -c 200 "$pkg_file"
        exit 1
    fi

    # A version column (pacman -Qe) or a status column (dpkg --get-selections) both
    # appear as a second field. Bare names never contain whitespace.
    if grep -qE '[[:space:]]' "$pkg_file"; then
        echo -e "  ${RED}✗${NC} Lines contain whitespace — expected bare names, got:"
        grep -nE '[[:space:]]' "$pkg_file" | head -3
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Every line is a bare package name."
    fi

    # A blank line would become an empty install argument during restore.
    if grep -qE '^$' "$pkg_file"; then
        echo -e "  ${RED}✗${NC} Package list contains blank lines."
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} No blank lines."
    fi

    # Nothing is named this. A line this long means records ran together.
    if awk 'length($0) > 100 { exit 1 }' "$pkg_file"; then
        echo -e "  ${GREEN}✓${NC} No implausibly long entries."
    else
        echo -e "  ${RED}✗${NC} A line exceeds 100 characters — records likely ran together."
        exit 1
    fi

    # An architecture suffix normally means the query printed full NEVRA (rpm -qa)
    # rather than names. Such lines are well-formed, so none of the checks above notice
    # them, yet they are useless on the target system.
    #
    # This cannot be an outright ban: a few packages genuinely carry one in their name.
    # Fedora's akmod-built kernel modules are the known case — kmod-nvidia is literally
    # named kmod-nvidia-<kernel version>.x86_64. So compare proportions instead. A
    # correct export has a handful at most; a NEVRA export has essentially all of them.
    local suffixed
    suffixed=$(grep -cE '\.(x86_64|noarch|i686|aarch64|armv7hl)$' "$pkg_file" || true)

    if [ "$((suffixed * 10))" -gt "$line_count" ]; then
        echo -e "  ${RED}✗${NC} $suffixed of $line_count entries carry architecture suffixes — query is printing NEVRA, not names:"
        grep -nE '\.(x86_64|noarch|i686|aarch64|armv7hl)$' "$pkg_file" | head -3
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Architecture suffixes within normal range ($suffixed of $line_count)."
    fi

    # The checks above cannot know what a valid name looks like on a distribution this
    # suite has never run on. Print a sample so a human can confirm the shape — this is
    # the point of running the suite inside an Ubuntu or Arch VM.
    echo -e "  ${BLUE}i${NC} First 3 entries (confirm these look like package names):"
    head -3 "$pkg_file" | sed 's/^/      /'
}

test_error_propagation() {
    echo -e "${BLUE}::${NC} Phase 6: backup error propagation"

    # A 0000 file is denied even to its owner, so the copy's open() fails — a durable
    # failure that (unlike a FIFO) stays a failure after special-file support lands.
    # Root bypasses permission bits, so the reproduction only holds as a normal user.
    if [ "$(id -u)" -eq 0 ]; then
        echo -e "  ${BLUE}i${NC} Skipped (root bypasses 0000 permissions)."
        return
    fi

    local err_backup="$TEST_DIR/backup_err"
    mkdir -p "$err_backup"
    echo "unreadable" > "$HOME/locked.txt"
    chmod 000 "$HOME/locked.txt"

    local output rc
    # `if` suppresses set -e; output is captured whether the command exits 0 or not
    if output=$(../migr backup "$err_backup" "$HOME/locked.txt" 2>&1); then rc=0; else rc=$?; fi
    chmod 644 "$HOME/locked.txt"  # restore so teardown and later phases are unaffected

    if [ "$rc" -ne 0 ]; then
        echo -e "  ${GREEN}✓${NC} A failed copy exits non-zero ($rc), not 0."
    else
        echo -e "  ${RED}✗${NC} A failed copy still exited 0!"
        echo "$output"
        exit 1
    fi

    # Native metadata preflight may reject the source before reserving a
    # container; either path must be reported as a failed backup, never plain
    # success.
    if [[ "$output" != *"errors"* && "$output" != *"metadata preflight failed"* ]]; then
        echo -e "  ${RED}✗${NC} Failure was not reported as a backup error."
        echo "$output"
        exit 1
    fi
}

test_comprehensive() {
    echo -e "${BLUE}::${NC} Phase 7: backup --comprehensive"

    local comp_backup="$TEST_DIR/backup_comprehensive"
    mkdir -p "$comp_backup"

    # Desktop was not restored by the critical backup in Phase 4, so recreate it
    mkdir -p "$HOME/Desktop"
    echo "icon" > "$HOME/Desktop/browser.desktop"

    local output
    output=$(../migr backup "$comp_backup" --comprehensive 2>&1)

    assert_contains "$output" "Backup complete"

    local actual_backup
    actual_backup=$(sole_final_container "$comp_backup")

    # Desktop is in comprehensive but NOT critical — its presence proves the right mode ran
    assert_file_exists "$actual_backup/data/XDG_DESKTOP_DIR"
    assert_file_exists "$actual_backup/data/XDG_DOCUMENTS_DIR"
}

test_explicit_paths() {
    echo -e "${BLUE}::${NC} Phase 8: backup <PATH...>"

    local paths_backup="$TEST_DIR/backup_paths"
    mkdir -p "$paths_backup"

    local output
    output=$(../migr backup "$paths_backup" "$HOME/Documents" 2>&1)

    assert_contains "$output" "Backup complete"

    local actual_backup
    actual_backup=$(sole_final_container "$paths_backup")

    # the one requested root, under its ordinal identity
    assert_file_exists "$actual_backup/data/EXPLICIT_0/note.txt"

    # dotfiles must be absent — explicit-paths mode makes no assumptions
    if [ -e "$actual_backup/data/BUILTIN_DOT_BASHRC" ]; then
        echo -e "  ${RED}✗${NC} .bashrc should not be in an explicit-paths backup"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Dotfiles correctly excluded from explicit-paths backup."
    fi

    # packages.txt must be absent
    if [ -e "$actual_backup/packages.txt" ]; then
        echo -e "  ${RED}✗${NC} packages.txt should not be in an explicit-paths backup"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} packages.txt correctly excluded from explicit-paths backup."
    fi

    # manifest.txt, by contrast, is mandatory in every mode: it carries the
    # format version, representation and root table, so without it the
    # container is not restorable at all.
    assert_file_exists "$actual_backup/manifest.txt"
    if grep -q '^ROOT ID=EXPLICIT_0 POLICY=HOME_RELATIVE ' "$actual_backup/manifest.txt"; then
        echo -e "  ${GREEN}✓${NC} The explicit root is recorded with its restore policy."
    else
        echo -e "  ${RED}✗${NC} Explicit root missing from the manifest root table"
        cat "$actual_backup/manifest.txt"
        exit 1
    fi

    # Two explicit roots that share a basename are distinct roots, and a
    # trailing slash does not flatten a directory into another root's place.
    local trailing_backup="$TEST_DIR/backup_paths_trailing"
    mkdir -p "$HOME/dir_a" "$HOME/dir_b" "$trailing_backup"
    echo A > "$HOME/dir_a/same.txt"
    echo B > "$HOME/dir_b/same.txt"

    output=$(../migr backup "$trailing_backup" "$HOME/dir_a/same.txt" "$HOME/dir_b/" 2>&1)
    assert_contains "$output" "Backup complete"

    local trailing_actual
    trailing_actual=$(sole_final_container "$trailing_backup")
    # ids follow the sorted normalized paths, so dir_a's file is EXPLICIT_0
    if [ "$(cat "$trailing_actual/data/EXPLICIT_0")" = "A" ] && \
       [ "$(cat "$trailing_actual/data/EXPLICIT_1/same.txt")" = "B" ]; then
        echo -e "  ${GREEN}✓${NC} Trailing slash preserved both explicit items."
    else
        echo -e "  ${RED}✗${NC} Trailing slash caused explicit items to overwrite or merge."
        exit 1
    fi

    # The same basename twice, from different directories: previously refused
    # because a flat layout could not represent it, now two separate roots.
    local samename_backup="$TEST_DIR/backup_paths_samename"
    mkdir -p "$samename_backup"
    output=$(../migr backup "$samename_backup" "$HOME/dir_a/same.txt" "$HOME/dir_b/same.txt" 2>&1)
    assert_contains "$output" "Backup complete"

    local samename_actual
    samename_actual=$(sole_final_container "$samename_backup")
    if [ "$(cat "$samename_actual/data/EXPLICIT_0")" = "A" ] && \
       [ "$(cat "$samename_actual/data/EXPLICIT_1")" = "B" ]; then
        echo -e "  ${GREEN}✓${NC} Same-basename explicit roots are kept apart as EXPLICIT_0/1."
    else
        echo -e "  ${RED}✗${NC} Same-basename explicit roots collided"
        exit 1
    fi
}

test_errors() {
    echo -e "${BLUE}::${NC} Phase 9: error paths"

    # missing required arguments
    assert_exits_nonzero ../migr backup
    assert_exits_nonzero ../migr restore
    assert_exits_nonzero ../migr restore /nonexistent/path

    # unrecognised command word
    assert_exits_nonzero ../migr bogus

    # the two scope flags are mutually exclusive
    assert_exits_nonzero ../migr backup "$BACKUP_DIR" --critical --comprehensive

    # a scope flag cannot be combined with explicit paths
    assert_exits_nonzero ../migr backup "$BACKUP_DIR" --comprehensive "$HOME/Documents"

    # scope flags apply to backup only
    assert_exits_nonzero ../migr restore "$BACKUP_DIR" --comprehensive

    # summary is a report-only presentation mode
    assert_exits_nonzero ../migr backup "$BACKUP_DIR" --summary
    assert_exits_nonzero ../migr restore "$BACKUP_DIR" --summary

    # dry-run is a backup/restore-only presentation mode
    assert_fails_with "Error: --dry-run applies only to 'backup' or 'restore'." \
        ../migr report --dry-run
    assert_fails_with "Error: --dry-run applies only to 'backup' or 'restore'." \
        ../migr --dry-run

    # include-self is meaningful only for backup, and help documents the
    # static-binary prerequisite before a real backup can refuse it.
    assert_fails_with "Error: --include-self applies only to 'backup'." \
        ../migr report --include-self
    assert_fails_with "Error: --include-self applies only to 'backup'." \
        ../migr restore "$BACKUP_DIR" --include-self
    assert_succeeds_with "--include-self" ../migr --help

    # include-network-config is meaningful only for backup.
    assert_fails_with "Error: --include-network-config applies only to 'backup'." \
        ../migr report --include-network-config
    assert_fails_with "Error: --include-network-config applies only to 'backup'." \
        ../migr restore "$BACKUP_DIR" --include-network-config
    assert_succeeds_with "--include-network-config" ../migr --help

    # commands that take exactly one positional reject extras
    assert_exits_nonzero ../migr restore "$BACKUP_DIR" /tmp/extra

    # report takes no arguments at all
    assert_exits_nonzero ../migr report /tmp/somewhere

    # a missing explicit root rejects the whole invocation rather than silently
    # backing up less than was asked for
    assert_fails_with "could not resolve path" \
        ../migr backup "$BACKUP_DIR" "$HOME/no_such_root"

    # overlapping roots are refused as a set, in dry-run exactly as live
    mkdir -p "$HOME/dir_a/nested"
    assert_fails_with "overlap" ../migr backup "$BACKUP_DIR" "$HOME/dir_a" "$HOME/dir_a/nested"
    assert_fails_with "overlap" ../migr backup "$BACKUP_DIR" "$HOME/dir_a" "$HOME/dir_a/nested" --dry-run

    # -h/--help must win over a scope-only flag that would otherwise be
    # rejected as "applies only to backup/report" -- the user asked for help,
    # not a scope validation error.
    assert_succeeds_with "Usage:" ../migr backup --critical --help
    assert_succeeds_with "Usage:" ../migr report --summary --help
    assert_succeeds_with "Usage:" ../migr report --max-depth=2 --help
    assert_succeeds_with "Usage:" ../migr restore --include-self --help
    assert_succeeds_with "Usage:" ../migr restore --include-network-config --help
    assert_succeeds_with "Usage:" ../migr help --critical
    # ...but a genuine conflict detected before --help is even parsed still refuses.
    assert_exits_nonzero ../migr backup --critical --comprehensive --help
}

test_truncation() {
    echo -e "${BLUE}::${NC} Phase 10: path truncation safety"

    # A HOME so long that home/<anything> overflows PATH_MAX. It need not exist:
    # path_join fails on length alone, before any filesystem access.
    local longhome
    longhome="/$(head -c 4100 </dev/zero | tr '\0' h)"

    # Gap 1: xdg_resolve must refuse, not fall back to a relative "Documents" that
    # backup would then create in the current working directory. The message check
    # confirms a clean refusal rather than a crash on a NULL path. `env HOME=...`
    # sets the oversized HOME for this one command only, so it never leaks onward.
    assert_fails_with "HOME path too long" \
        env HOME="$longhome" ../migr backup "$BACKUP_DIR" --critical

    # Same guard on restore. --dry-run skips the interactive confirm yet still
    # reaches xdg_resolve before touching anything.
    mkdir -p "$TEST_DIR/dummy_src"
    assert_fails_with "HOME path too long" \
        env HOME="$longhome" ../migr restore "$TEST_DIR/dummy_src" --dry-run

    # Gap 3: report must not present a silent 0B estimate as success.
    assert_fails_with "report is incomplete" \
        env HOME="$longhome" ../migr report

    # Gap 2: an unusable destination must be refused in dry-run exactly as it is
    # live, so the preview can never promise a backup that would fail. Payload
    # addresses are fd-anchored and short now (data/<root id>), so a deep target
    # no longer overflows per item — what still cannot work is a target path
    # that does not fit in PATH_MAX itself.
    local comp unusable
    comp=$(head -c 200 </dev/zero | tr '\0' c)
    unusable="$TEST_DIR/unusable"
    while [ ${#unusable} -lt 4200 ]; do unusable="$unusable/$comp"; done

    local dry live dry_out live_out
    set +e
    dry_out=$(../migr backup "$unusable" --critical --dry-run 2>&1)
    dry=$?
    live_out=$(../migr backup "$unusable" --critical 2>&1)
    live=$?
    set -e

    if [ "$dry" -eq "$live" ] && [ "$dry" -ne 0 ] && \
       [[ "$live_out" == *"Could not access"* ]] && [[ "$dry_out" == *"Could not access"* ]]; then
        echo -e "  ${GREEN}✓${NC} An unusable destination is refused identically in dry-run and live (exit $dry)."
    else
        echo -e "  ${RED}✗${NC} dry-run/live parity broken: dry=$dry live=$live"
        exit 1
    fi

    # A deep but valid target, by contrast, must now succeed: nothing in the
    # container layout concatenates a per-item destination path any more.
    local deep="$TEST_DIR/deep"
    while [ ${#deep} -lt 3800 ]; do deep="$deep/$comp"; done
    mkdir -p "$deep"
    local leaf src deep_out
    leaf=$(head -c 250 </dev/zero | tr '\0' x)
    src="$TEST_DIR/$leaf"
    echo hi > "$src"

    deep_out=$(../migr backup "$deep" "$src" 2>&1)
    if [[ "$deep_out" == *"Backup complete"* ]] && \
       [ "$(cat "$(sole_final_container "$deep")/data/EXPLICIT_0")" = "hi" ]; then
        echo -e "  ${GREEN}✓${NC} A deep-but-valid destination backs up without a PATH_MAX join."
    else
        echo -e "  ${RED}✗${NC} A deep-but-valid destination failed"
        echo "  output: $deep_out"
        exit 1
    fi

    # The fd-anchored restore core resolves destination_rel component by
    # component and never concatenates the full browser path. A deep but valid
    # HOME must therefore work in both preview and live restore. 4060 is
    # deliberately chosen, not just "big": long enough that HOME + the
    # deepest single destination path here (.config/google-chrome/Default/
    # Preferences, 41 bytes) would overflow PATH_MAX if ever naively
    # concatenated as one string (proving the fd-anchored walk doesn't do
    # that), but short enough that HOME + "/.config/user-dirs.dirs" (23
    # bytes) still fits -- xdg_resolve() now correctly refuses when that
    # join alone would overflow (P0 #24), so this fixture must stay under that
    # boundary (empirically confirmed at exactly 4073) to keep testing what it
    # was written to test, not that separate, already-correct refusal.
    local deep_home="$TEST_DIR/deep_home" room part_len
    mkdir "$deep_home"
    while [ ${#deep_home} -lt 4060 ]; do
        room=$((4060 - ${#deep_home} - 1))
        [ "$room" -le 0 ] && break
        part_len=100
        [ "$room" -lt "$part_len" ] && part_len=$room
        comp=$(head -c "$part_len" </dev/zero | tr '\0' h)
        deep_home="$deep_home/$comp"
        mkdir "$deep_home"
    done

    mkdir -p "$TEST_DIR/dummy_src/.config/google-chrome/Default"
    echo prefs > "$TEST_DIR/dummy_src/.config/google-chrome/Default/Preferences"
    local deep_home_out deep_home_rc deep_home_live_out deep_home_live_rc
    set +e
    deep_home_out=$(env HOME="$deep_home" ../migr restore "$TEST_DIR/dummy_src" --dry-run 2>&1)
    deep_home_rc=$?
    deep_home_live_out=$(printf 'y\n' | env HOME="$deep_home" ../migr restore "$TEST_DIR/dummy_src" 2>&1)
    deep_home_live_rc=$?
    set -e
    if [ "$deep_home_rc" -eq 0 ] &&
       [ "$deep_home_live_rc" -eq 0 ] &&
       [[ "$deep_home_out" == *"Dry run complete"* ]] &&
       [[ "$deep_home_live_out" == *"Restore complete"* ]] &&
       (cd "$deep_home" && grep -q '^prefs$' .config/google-chrome/Default/Preferences); then
        echo -e "  ${GREEN}✓${NC} A deep-but-real HOME previews and restores without a PATH_MAX join."
    else
        echo -e "  ${RED}✗${NC} Expected a deep HOME to preview and restore cleanly"
        echo "  dry exit=$deep_home_rc output: $deep_home_out"
        echo "  live exit=$deep_home_live_rc output: $deep_home_live_out"
        exit 1
    fi

    # If even one XDG fallback cannot be represented, legacy restore must stop
    # before restoring unrelated items. Continuing after a partial XDG
    # resolution would change the established legacy error boundary.
    local too_deep_home="$TEST_DIR/too_deep_home"
    mkdir "$too_deep_home"
    while [ ${#too_deep_home} -lt 4088 ]; do
        room=$((4088 - ${#too_deep_home} - 1))
        [ "$room" -le 0 ] && break
        part_len=100
        [ "$room" -lt "$part_len" ] && part_len=$room
        comp=$(head -c "$part_len" </dev/zero | tr '\0' z)
        too_deep_home="$too_deep_home/$comp"
        mkdir "$too_deep_home"
    done
    echo legacy-dotfile > "$TEST_DIR/dummy_src/.bashrc"

    local too_deep_out too_deep_rc
    set +e
    too_deep_out=$(env HOME="$too_deep_home" ../migr restore "$TEST_DIR/dummy_src" --dry-run 2>&1)
    too_deep_rc=$?
    set -e
    if [ "$too_deep_rc" -ne 0 ] &&
       [[ "$too_deep_out" == *"HOME path too long"* ]] &&
       [[ "$too_deep_out" != *"Would restore: .bashrc"* ]]; then
        echo -e "  ${GREEN}✓${NC} Legacy restore stops when XDG destinations cannot all be resolved."
    else
        echo -e "  ${RED}✗${NC} Legacy XDG failure leaked into a partial restore"
        echo "  exit=$too_deep_rc output: $too_deep_out"
        exit 1
    fi

    # A HOME whose canonical (realpath) form is short and valid, but whose raw
    # lexical form is far past PATH_MAX (many "/a/.." segments that cancel out
    # under resolution), must succeed exactly as the short canonical form
    # would. Regression for backup.c resolving the legacy manifest's XDG
    # basenames against the raw environment value instead of the same
    # canonicalized HOME the planner already validated: that raw value could
    # overflow PATH_MAX on its own even when the canonical form does not,
    # failing only after the dated backup directory (and packages.txt) had
    # already been created.
    local canon_base="$TEST_DIR/canon_home" canon_raw
    local canon_state="$canon_base/.local/state"
    local canon_cache="$canon_base/.cache"
    local canon_config="$canon_base/.config"
    mkdir -p "$canon_base/a" "$canon_state" "$canon_cache" "$canon_config" "$canon_base/Documents"
    echo canon > "$canon_base/Documents/note.txt"
    canon_raw="$canon_base"
    while [ ${#canon_raw} -lt 4200 ]; do
        canon_raw="$canon_raw/a/.."
    done

    local canon_backup="$TEST_DIR/canon_backup"
    mkdir -p "$canon_backup"
    local canon_out
    # Keep the package manager's own state/cache/config paths canonical so this
    # fixture measures migr's HOME normalization rather than an external tool's
    # handling of the deliberately pathological lexical spelling.
    canon_out=$(env HOME="$canon_raw" \
                    XDG_STATE_HOME="$canon_state" \
                    XDG_CACHE_HOME="$canon_cache" \
                    XDG_CONFIG_HOME="$canon_config" \
                    ../migr backup "$canon_backup" --critical 2>&1)
    assert_contains "$canon_out" "Backup complete"

    local canon_actual
    canon_actual=$(sole_final_container "$canon_backup")
    if [ -n "$canon_actual" ] &&
       [ -f "$canon_actual/packages.txt" ] &&
       grep -q "^ROOT ID=XDG_DOCUMENTS_DIR " "$canon_actual/manifest.txt" 2>/dev/null &&
       [[ "$canon_out" != *"Error:"* ]]; then
        echo -e "  ${GREEN}✓${NC} A canonically-short-but-lexically-long HOME backs up cleanly, packages and manifest included."
    else
        echo -e "  ${RED}✗${NC} Expected a full backup+manifest even though raw \$HOME was lexically past PATH_MAX"
        echo "  output: $canon_out"
        exit 1
    fi
}

test_restore_path_safety() {
    echo -e "${BLUE}::${NC} Phase 11: restore path safety"

    # A dangling final symlink is a filesystem object in the payload, not a
    # missing source. Preview must see it and live restore must recreate its
    # stored target string without following it.
    local dangling_src="$TEST_DIR/dangling_src"
    local dangling_home="$TEST_DIR/dangling_home"
    mkdir -p "$dangling_src" "$dangling_home"
    ln -s "missing-target" "$dangling_src/.bashrc"

    local dry_out dry_rc live_out live_rc
    set +e
    dry_out=$(env HOME="$dangling_home" ../migr restore "$dangling_src" --dry-run 2>&1)
    dry_rc=$?
    live_out=$(printf 'y\n' | env HOME="$dangling_home" ../migr restore "$dangling_src" 2>&1)
    live_rc=$?
    set -e
    if [ "$dry_rc" -eq 0 ] &&
       [ "$live_rc" -eq 0 ] &&
       [[ "$dry_out" == *"Would restore: .bashrc"* ]] &&
       [[ "$live_out" == *"Restore complete"* ]] &&
       [ -L "$dangling_home/.bashrc" ] &&
       [ "$(readlink "$dangling_home/.bashrc")" = "missing-target" ]; then
        echo -e "  ${GREEN}✓${NC} Dangling payload symlink is previewed and restored as a symlink."
    else
        echo -e "  ${RED}✗${NC} Dangling payload symlink handling diverged"
        echo "  dry exit=$dry_rc output: $dry_out"
        echo "  live exit=$live_rc output: $live_out"
        exit 1
    fi

    # An intermediate payload symlink must be refused by both modes. The file
    # behind it exists, so a path-following implementation would copy it.
    local unsafe_src="$TEST_DIR/unsafe_src"
    local unsafe_home="$TEST_DIR/unsafe_home"
    local outside_src="$TEST_DIR/outside_src"
    mkdir -p "$unsafe_src" "$unsafe_home" "$outside_src/google-chrome/Default"
    echo "outside-prefs" > "$outside_src/google-chrome/Default/Preferences"
    ln -s "$outside_src" "$unsafe_src/.config"

    set +e
    dry_out=$(env HOME="$unsafe_home" ../migr restore "$unsafe_src" --dry-run 2>&1)
    dry_rc=$?
    live_out=$(printf 'y\n' | env HOME="$unsafe_home" ../migr restore "$unsafe_src" 2>&1)
    live_rc=$?
    set -e
    if [ "$dry_rc" -ne 0 ] &&
       [ "$live_rc" -ne 0 ] &&
       [ ! -e "$unsafe_home/.config/google-chrome/Default/Preferences" ]; then
        echo -e "  ${GREEN}✓${NC} Dry-run and live restore both refuse an intermediate payload symlink."
    else
        echo -e "  ${RED}✗${NC} Intermediate payload symlink refusal diverged"
        echo "  dry exit=$dry_rc output: $dry_out"
        echo "  live exit=$live_rc output: $live_out"
        exit 1
    fi
}


test_v1_restore_dispatch() {
    echo -e "${BLUE}::${NC} Phase 12: versioned (v1) manifest restore dispatch"

    # A hand-crafted v1 manifest exercises CLI restore independently of the
    # backup writer. PAYLOAD/SOURCE/RESTORE need no percent-encoding here since
    # every byte used is in the encoder's safe set (see src/manifest.c's
    # grammar comment).
    local v1_src="$TEST_DIR/v1_src"
    local v1_home="$TEST_DIR/v1_home"
    mkdir -p "$v1_src/data/EXPLICIT_0" "$v1_src/data/EXPLICIT_1" "$v1_home"
    echo "project-note" > "$v1_src/data/EXPLICIT_0/note.txt"
    echo "external-note" > "$v1_src/data/EXPLICIT_1/external.txt"
    cat > "$v1_src/manifest.txt" <<'EOF'
MIGR_MANIFEST
VERSION=1
REPRESENTATION=native
SCOPE=explicit
SIDECAR_VERSION=0
ROOT_COUNT=2
ROOT ID=EXPLICIT_0 POLICY=HOME_RELATIVE PAYLOAD=EXPLICIT_0 SOURCE=Documents/project RESTORE=Documents/project
ROOT ID=EXPLICIT_1 POLICY=MANUAL_NATIVE PAYLOAD=EXPLICIT_1 SOURCE=/mnt/external/project
EOF

    local dry_out
    dry_out=$(env HOME="$v1_home" ../migr restore "$v1_src" --dry-run 2>&1)
    assert_contains "$dry_out" "Roots"
    assert_contains "$dry_out" "Would restore: EXPLICIT_0 -> ~/Documents/project"
    assert_contains "$dry_out" "Manual Roots"
    assert_contains "$dry_out" "/mnt/external/project"

    local live_out
    live_out=$(printf 'y\n' | env HOME="$v1_home" ../migr restore "$v1_src" 2>&1)
    assert_contains "$live_out" "Restore complete"
    assert_file_exists "$v1_home/Documents/project/note.txt"
    if [ "$(cat "$v1_home/Documents/project/note.txt")" = "project-note" ]; then
        echo -e "  ${GREEN}✓${NC} HOME_RELATIVE root content matches the backup payload."
    else
        echo -e "  ${RED}✗${NC} HOME_RELATIVE root content does not match"
        exit 1
    fi
    if [ ! -e "$v1_home/EXPLICIT_1" ] && [ ! -e "$v1_home/external.txt" ] && [ ! -e "$v1_home/external-note" ]; then
        echo -e "  ${GREEN}✓${NC} MANUAL_NATIVE root was not auto-restored into home."
    else
        echo -e "  ${RED}✗${NC} MANUAL_NATIVE root was unexpectedly restored"
        exit 1
    fi
    assert_contains "$live_out" "/mnt/external/project"

    # A .partial-named source is refused before manifest dispatch
    # (docs/DECISIONS.md D15) -- an interrupted backup may be incomplete.
    local partial_src="$TEST_DIR/migr_backup_20260101_000000.partial"
    mkdir -p "$partial_src"
    assert_fails_with "in-progress or abandoned" ../migr restore "$partial_src" --dry-run

    # An unrecognized manifest version refuses the whole restore before ever
    # reaching the confirmation prompt -- no piped "y" is needed here.
    local unknown_src="$TEST_DIR/unknown_version_src"
    mkdir -p "$unknown_src"
    printf 'MIGR_MANIFEST\nVERSION=999\n' > "$unknown_src/manifest.txt"
    assert_fails_with "does not understand" env HOME="$v1_home" ../migr restore "$unknown_src"

    # packages.txt is fd-anchored: a symlinked file must never be followed into
    # an arbitrary location.
    local pkg_src="$TEST_DIR/pkg_symlink_src"
    local pkg_home="$TEST_DIR/pkg_symlink_home"
    local pkg_outside="$TEST_DIR/pkg_outside_secret.txt"
    mkdir -p "$pkg_src" "$pkg_home"
    echo "outside-secret-content" > "$pkg_outside"
    ln -s "$pkg_outside" "$pkg_src/packages.txt"

    local pkg_live_out pkg_live_rc
    set +e
    pkg_live_out=$(printf 'y\n' | env HOME="$pkg_home" ../migr restore "$pkg_src" 2>&1)
    pkg_live_rc=$?
    set -e
    if [ "$pkg_live_rc" -ne 0 ] &&
       [[ "$pkg_live_out" == *"packages.txt"* ]] &&
       [ "$(cat "$pkg_outside")" = "outside-secret-content" ]; then
        echo -e "  ${GREEN}✓${NC} A symlinked packages.txt is refused, its target left untouched."
    else
        echo -e "  ${RED}✗${NC} Symlinked packages.txt handling diverged"
        echo "  exit=$pkg_live_rc output: $pkg_live_out"
        exit 1
    fi

    # A sparse native payload larger than the destination's current free space
    # exercises the restore-side refusal without allocating the payload bytes.
    local space_src="$TEST_DIR/v1_restore_space_src"
    local space_home="$TEST_DIR/v1_restore_space_home"
    mkdir -p "$space_src/data/EXPLICIT_0" "$space_home"
    cat > "$space_src/manifest.txt" <<'EOF'
MIGR_MANIFEST
VERSION=1
REPRESENTATION=native
SCOPE=explicit
SIDECAR_VERSION=0
ROOT_COUNT=1
ROOT ID=EXPLICIT_0 POLICY=HOME_RELATIVE PAYLOAD=EXPLICIT_0 SOURCE=Documents/space RESTORE=Documents/space
EOF

    local space_available
    space_available=$(df -P -B1 "$space_home" | awk 'NR == 2 { print $4 }')
    if ! [[ "$space_available" =~ ^[0-9]+$ ]] ||
       [ "$space_available" -ge 9223372036854775806 ]; then
        echo -e "  ${RED}✗${NC} Could not derive a safe destination free-space test size."
        exit 1
    fi
    truncate -s "$((space_available + 1))" \
        "$space_src/data/EXPLICIT_0/space.bin"

    local space_dry_out space_dry_rc space_live_out space_live_rc
    set +e
    space_dry_out=$(env HOME="$space_home" ../migr restore \
        "$space_src" --dry-run 2>&1)
    space_dry_rc=$?
    space_live_out=$(printf 'y\n' | env HOME="$space_home" ../migr \
        restore "$space_src" 2>&1)
    space_live_rc=$?
    set -e
    if [ "$space_dry_rc" -eq 0 ] || [ "$space_live_rc" -eq 0 ] ||
       [ -e "$space_home/Documents/space" ]; then
        echo -e "  ${RED}✗${NC} Restore free-space refusal did not stop before mutation."
        echo "  dry exit=$space_dry_rc output: $space_dry_out"
        echo "  live exit=$space_live_rc output: $space_live_out"
        exit 1
    fi
    assert_contains "$space_dry_out" "Estimated restore size:"
    assert_contains "$space_dry_out" "Destination free space:"
    assert_contains "$space_dry_out" \
        "Error: not enough free space at $space_home (need "
    assert_not_contains "$space_dry_out" "Continue?"
    assert_contains "$space_live_out" "Estimated restore size:"
    assert_contains "$space_live_out" "Destination free space:"
    assert_contains "$space_live_out" \
        "Error: not enough free space at $space_home (need "
    assert_not_contains "$space_live_out" "Continue?"
    echo -e "  ${GREEN}✓${NC} Native restore refuses a sparse payload that exceeds destination space."
}

test_xdg_nested_destination_recovery() {
    echo -e "${BLUE}::${NC} Phase 12b: legacy XDG destination recovery"

    # user-dirs.dirs can legitimately map an XDG directory to a nested custom
    # path (a real xdg-user-dirs feature). On a fresh restore target, not just
    # the leaf but its parent too may not exist yet -- both a live restore
    # and a dry-run preview of it must recover the same way the native
    # restore engine's own resolve_parent(..., create_intermediates) already
    # does for every other restore root, not refuse.
    local xdg_src="$TEST_DIR/xdg_nested_src"
    local xdg_home="$TEST_DIR/xdg_nested_home"
    mkdir -p "$xdg_src/Documents" "$xdg_home/.config"
    echo nested-doc > "$xdg_src/Documents/note.txt"
    echo 'XDG_DOCUMENTS_DIR="$HOME/data/Documents"' > "$xdg_home/.config/user-dirs.dirs"

    if [ -e "$xdg_home/data" ]; then
        echo -e "  ${RED}✗${NC} fixture setup left \$HOME/data pre-existing"
        exit 1
    fi

    # A dry-run against the same fixture must preview the restore cleanly
    # (open_xdg_destination_anchor() walks up to the nearest existing
    # ancestor and hands the fd-anchored core a multi-component relative
    # path, exactly like every other restore root) -- not report a spurious
    # failure for a destination that a live restore would actually create --
    # while still never creating anything itself.
    local xdg_dry_out
    xdg_dry_out=$(env HOME="$xdg_home" ../migr restore "$xdg_src" --dry-run 2>&1)
    assert_contains "$xdg_dry_out" "Would restore"
    if [ -e "$xdg_home/data" ]; then
        echo -e "  ${RED}✗${NC} Dry-run created \$HOME/data while resolving the XDG destination"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Dry-run previews the recovery without creating the missing XDG destination chain."
    fi

    local xdg_out
    xdg_out=$(printf 'y\n' | env HOME="$xdg_home" ../migr restore "$xdg_src" 2>&1)
    assert_contains "$xdg_out" "Restore complete"
    assert_file_exists "$xdg_home/data/Documents/note.txt"
    if [ "$(cat "$xdg_home/data/Documents/note.txt")" = "nested-doc" ]; then
        echo -e "  ${GREEN}✓${NC} A custom XDG mapping whose parent doesn't exist yet is created and restored into."
    else
        echo -e "  ${RED}✗${NC} Nested XDG destination content does not match"
        exit 1
    fi
}

test_native_restore_progress() {
    echo -e "${BLUE}::${NC} Phase 12a: native restore progress"

    if ! command -v socat >/dev/null 2>&1; then
        echo -e "  ${BLUE}↷${NC} skipped: 'socat' is not available for the TTY check."
        return
    fi

    local progress_src="$TEST_DIR/native_progress_src"
    local progress_home="$TEST_DIR/native_progress_home"
    local redirected_home="$TEST_DIR/native_progress_redirected_home"
    mkdir -p "$progress_src/Documents" "$progress_home" "$redirected_home"
    printf 'native progress\n' > "$progress_src/Documents/progress.txt"

    local pty_output pty_rc redirected_output
    set +e
    pty_output=$(printf 'y\n' | socat - \
        "EXEC:env HOME=$progress_home ../migr restore $progress_src,pty,setsid,ctty,echo=0" \
        2>&1)
    pty_rc=$?
    set -e
    if [ "$pty_rc" -eq 0 ] && [[ "$pty_output" == *"Restored:"* ]] &&
       [[ "$pty_output" == *"current: Documents/progress.txt"* ]] &&
       [[ "$pty_output" == *"elapsed 00:"* ]] &&
       [[ "$pty_output" == *"speed "* ]] &&
       [ -f "$progress_home/Documents/progress.txt" ]; then
        echo -e "  ${GREEN}✓${NC} Native restore shows progress on a real TTY."
    else
        echo -e "  ${RED}✗${NC} Native restore did not produce TTY progress"
        echo "  exit=$pty_rc output: $pty_output"
        exit 1
    fi

    redirected_output=$(printf 'y\n' | env HOME="$redirected_home" \
        ../migr restore "$progress_src" 2>&1)
    if [[ "$redirected_output" != *"Restored:"* ]] &&
       [ -f "$redirected_home/Documents/progress.txt" ]; then
        echo -e "  ${GREEN}✓${NC} Native restore suppresses progress when stdout is redirected."
    else
        echo -e "  ${RED}✗${NC} Redirected native restore unexpectedly emitted progress"
        echo "  output: $redirected_output"
        exit 1
    fi
}


test_probe_refusal() {
    echo -e "${BLUE}::${NC} Phase 13: destination probe (backup preflight)"

    # A regular file is not a valid destination: reject it up front, in both live
    # and dry-run, before writing anything. This needs no special privilege.
    local file_dest="$TEST_DIR/not_a_dir"
    : > "$file_dest"
    assert_fails_with "is not a directory" ../migr backup "$file_dest"
    assert_fails_with "is not a directory" ../migr backup "$file_dest" --dry-run
    rm -f "$file_dest"

    # The remaining cases lean on directory mode bits, which root ignores.
    if [ "$(id -u)" = "0" ]; then
        echo -e "  ${GREEN}✓${NC} (mode-bit cases skipped as root: they do not restrict root)"
        return
    fi

    # A read-only destination that already exists: fsprobe cannot create its temp
    # subdirectory, so a live backup must refuse — and must not delete the dir it
    # did not create.
    local ro_dest="$TEST_DIR/readonly_dest"
    mkdir -p "$ro_dest"
    chmod 555 "$ro_dest"
    assert_fails_with "could not probe" ../migr backup "$ro_dest"
    if [ ! -d "$ro_dest" ]; then
        echo -e "  ${RED}✗${NC} pre-existing read-only dest was removed on refusal"
        exit 1
    fi

    # Same read-only destination under --dry-run: the probe now runs for
    # real (I-6), so it must refuse identically to the live case above.
    assert_fails_with "could not probe" ../migr backup "$ro_dest" --dry-run
    if compgen -G "$ro_dest/migr_backup_*" > /dev/null; then
        echo -e "  ${RED}✗${NC} dry-run wrote a backup dir into a read-only dest"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} dry-run on read-only dest refuses exactly like a live run"
    chmod 755 "$ro_dest" # restore the write bit so teardown can remove it

    # A destination migr creates itself, then hits a probe refusal: the empty root
    # it made this run must be rolled back. umask 0222 makes mkdir() yield a 0555
    # root that fsprobe cannot write into; the umask stays inside the subshell.
    local new_dest="$TEST_DIR/new_probe_failure"
    local nd_out nd_rc
    set +e
    nd_out=$(umask 0222; ../migr backup "$new_dest" 2>&1)
    nd_rc=$?
    set -e
    if [ "$nd_rc" -eq 0 ] || [[ "$nd_out" != *"could not probe"* ]]; then
        echo -e "  ${RED}✗${NC} expected probe refusal on self-created 0555 root; exit=$nd_rc"
        echo "  output: $nd_out"
        exit 1
    fi
    if [ -e "$new_dest" ]; then
        echo -e "  ${RED}✗${NC} migr-created root not rolled back after probe refusal"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} migr-created root rolled back after probe refusal"
}


test_native_stale_reconciliation() {
    # The two roots are deliberately separate. capture_directory_at stops
    # the current root at its first child error, so putting the broken
    # fixture beside the file under test would make the result depend on
    # readdir() order.
    local sr_dest="$TEST_DIR/cp_stale_reconcile"
    local sr_keep="$TEST_DIR/cp_stale_reconcile_a_keep"
    local sr_broken="$TEST_DIR/cp_stale_reconcile_b_broken"
    mkdir -p "$sr_dest" "$sr_keep" "$sr_broken"
    echo will-be-deleted > "$sr_keep/gone.txt"
    echo stays-forever   > "$sr_keep/keeps.txt"
    for i in $(seq -w 0 4999); do
        echo filler > "$sr_keep/filler-$i"
    done
    echo locked > "$sr_broken/locked.txt"

    local sr_race_pid sr_race_status
    (
        for _ in $(seq 1 1000); do
            if compgen -G "$sr_dest/migr_backup_*.partial" > /dev/null; then
                chmod 000 "$sr_broken"
                exit 0
            fi
        sleep 0.001
        done
        exit 1
    ) &
    sr_race_pid=$!
    local sr_first_out sr_first_rc
    set +e
    sr_first_out=$(../migr backup "$sr_dest" "$sr_keep" "$sr_broken" 2>&1)
    sr_first_rc=$?
    set -e
    set +e
    wait "$sr_race_pid"
    sr_race_status=$?
    set -e

    local sr_partial
    sr_partial=$(containers_matching "$sr_dest" partial)
    if [ "$sr_first_rc" -eq 0 ] || [ "$sr_race_status" -ne 0 ] ||
       [ -z "$sr_partial" ] || [ ! -f "$sr_partial/data/EXPLICIT_0/gone.txt" ]; then
        echo -e "  ${RED}✗${NC} Reconciliation fixture did not produce a partial containing the keep root"
        echo "  exit=$sr_first_rc race=$sr_race_status output: $sr_first_out"
        return 1
    fi
    chmod 755 "$sr_broken"
    rm -f "$sr_keep/gone.txt"

    local sr_final sr_second_out
    sr_second_out=$(../migr backup "$sr_dest" "$sr_keep" "$sr_broken" 2>&1)
    sr_final=$(sole_final_container "$sr_dest")
    assert_no_partial "$sr_dest"
    if [ ! -e "$sr_final/data/EXPLICIT_0/gone.txt" ] &&
       [ "$(cat "$sr_final/data/EXPLICIT_0/keeps.txt")" = "stays-forever" ] &&
       [ "$(cat "$sr_final/data/EXPLICIT_1/locked.txt")" = "locked" ]; then
        echo -e "  ${GREEN}✓${NC} A disappeared source file is removed from the resumed final backup."
    else
        echo -e "  ${RED}✗${NC} Stale reconciliation removed the wrong thing, or not the right one"
        echo "  output: $sr_second_out"
        return 1
    fi

    local sg_dest="$TEST_DIR/cp_stale_reconcile_gate"
    local sg_keep="$TEST_DIR/cp_stale_reconcile_gate_a_keep"
    local sg_broken="$TEST_DIR/cp_stale_reconcile_gate_b_broken"
    mkdir -p "$sg_dest" "$sg_keep" "$sg_broken"
    echo will-survive > "$sg_keep/gone.txt"
    echo stays         > "$sg_keep/keeps.txt"
    for i in $(seq -w 0 4999); do
        echo filler > "$sg_keep/filler-$i"
    done
    echo locked > "$sg_broken/locked.txt"

    (
        for _ in $(seq 1 1000); do
            if compgen -G "$sg_dest/migr_backup_*.partial" > /dev/null; then
                chmod 000 "$sg_broken"
                exit 0
            fi
            sleep 0.001
        done
        exit 1
    ) &
    local sg_race_pid=$!
    set +e
    ../migr backup "$sg_dest" "$sg_keep" "$sg_broken" >/dev/null 2>&1
    local sg_first_rc=$?
    wait "$sg_race_pid"
    local sg_first_race=$?
    set -e
    local sg_partial
    sg_partial=$(containers_matching "$sg_dest" partial)
    if [ "$sg_first_rc" -eq 0 ] || [ "$sg_first_race" -ne 0 ] ||
       [ -z "$sg_partial" ] || [ ! -f "$sg_partial/data/EXPLICIT_0/gone.txt" ]; then
        echo -e "  ${RED}✗${NC} Global reconciliation gate fixture did not produce its first partial"
        return 1
    fi

    chmod 755 "$sg_broken"
    rm -f "$sg_keep/gone.txt"
    (
        for _ in $(seq 1 1000); do
            if compgen -G "$sg_dest/migr_backup_*.partial" > /dev/null; then
                chmod 000 "$sg_broken"
                exit 0
            fi
            sleep 0.001
        done
        exit 1
    ) &
    local sg_second_race_pid=$!
    set +e
    ../migr backup "$sg_dest" "$sg_keep" "$sg_broken" >/dev/null 2>&1
    local sg_second_rc=$?
    wait "$sg_second_race_pid"
    local sg_second_race=$?
    set -e
    chmod 755 "$sg_broken"
    sg_partial=$(containers_matching "$sg_dest" partial)
    if [ "$sg_second_rc" -ne 0 ] && [ "$sg_second_race" -eq 0 ] &&
       [ -z "$(containers_matching "$sg_dest" final)" ] &&
       [ -f "$sg_partial/data/EXPLICIT_0/gone.txt" ]; then
        echo -e "  ${GREEN}✓${NC} An incomplete walk leaves stale payload untouched and blocks finalization."
    else
        echo -e "  ${RED}✗${NC} An incomplete walk authorized stale deletion"
        return 1
    fi
}

test_container_production() {
    echo -e "${BLUE}::${NC} Phase 14: versioned container production wiring"

    if [ "$(id -u)" -eq 0 ]; then
        echo -e "  ${BLUE}i${NC} Native stale-reconciliation permission cases skipped (root bypasses 0000 permissions)."
    else
        test_native_stale_reconciliation
    fi

    # --- dry-run creates nothing at all, not even the destination root ---
    # `cp_dry` (the parent) exists; `never_created` (the actual destination)
    # does not -- the common first-time-use case (e.g. a subdirectory not yet
    # made on a fresh mount). The preview must still reflect the real
    # destination filesystem (falling back to the parent), not silently skip
    # size/space/capability checks just because the leaf isn't there yet.
    local dry_dest="$TEST_DIR/cp_dry/never_created"
    mkdir -p "$TEST_DIR/cp_dry"
    local dry_out
    dry_out=$(../migr backup "$dry_dest" --critical --dry-run 2>&1)
    if [ -e "$dry_dest" ]; then
        echo -e "  ${RED}✗${NC} Dry run created the destination root"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Dry run creates no target, container, data/ or control file."
        assert_contains "$dry_out" "Estimated backup size:"
        assert_contains "$dry_out" "Destination free space:"
        assert_contains "$dry_out" \
            "does not exist yet; the preview below reflects its parent directory's filesystem instead."
    fi

    # --- two consecutive backups produce two distinct finalized containers ---
    local twice="$TEST_DIR/cp_twice"
    mkdir -p "$twice"
    ../migr backup "$twice" --critical >/dev/null 2>&1
    # container names carry a whole-second timestamp; the second backup must get
    # its own container either way, via the "-N" suffix if the clock has not moved
    ../migr backup "$twice" --critical >/dev/null 2>&1
    local twice_count
    twice_count=$(containers_matching "$twice" final | grep -c . || true)
    assert_no_partial "$twice"
    if [ "$twice_count" -eq 2 ]; then
        echo -e "  ${GREEN}✓${NC} Two consecutive backups produced two distinct finalized containers."
    else
        echo -e "  ${RED}✗${NC} Expected 2 finalized containers, found $twice_count"
        exit 1
    fi

    # A destination is a write location, so its final symlink must be followed
    # when the link resolves outside the selected source root.
    local link_src="$TEST_DIR/cp_fix_verify_src"
    local link_real="$TEST_DIR/cp_fix_verify_real"
    local link_path="$TEST_DIR/cp_fix_verify_link"
    mkdir -p "$link_src" "$link_real"
    echo symlink-target > "$link_src/file.txt"
    ln -s "$link_real" "$link_path"

    local link_out link_rc link_final_count link_final
    set +e
    link_out=$(../migr backup "$link_path" "$link_src" 2>&1)
    link_rc=$?
    set -e
    link_final=$(containers_matching "$link_real" final)
    link_final_count=$(printf '%s' "$link_final" | grep -c . || true)
    if [ "$link_rc" -eq 0 ] && [ "$link_final_count" -eq 1 ] &&
       [ "$(cat "$link_real"/migr_backup_*/data/EXPLICIT_0/file.txt)" = "symlink-target" ] &&
       [[ "$link_out" == *"Backup complete"* ]]; then
        echo -e "  ${GREEN}✓${NC} A destination final symlink is followed for a valid backup."
    else
        echo -e "  ${RED}✗${NC} A valid destination final symlink was rejected"
        echo "  exit=$link_rc output: $link_out"
        exit 1
    fi

    # --- an unreadable root: fail, keep a valid partial, then resume it ---
    # Root bypasses permission bits, so the unreadable-file reproduction only
    # holds as a normal user.
    if [ "$(id -u)" -eq 0 ]; then
        echo -e "  ${BLUE}i${NC} Resume case skipped (root bypasses 0000 permissions)."
    else
        local resume_dest="$TEST_DIR/cp_resume" resume_src="$HOME/resume_root"
        mkdir -p "$resume_dest" "$resume_src"
        echo readable > "$resume_src/good.txt"
        echo locked   > "$resume_src/locked.txt"
        chmod 000 "$resume_src/locked.txt"

        local first_out first_rc
        set +e
        first_out=$(../migr backup "$resume_dest" "$resume_src" 2>&1)
        first_rc=$?
        set -e

        local partial
        partial=$(containers_matching "$resume_dest" partial)
        if [ "$first_rc" -ne 0 ] &&
           [ -z "$(containers_matching "$resume_dest" final)" ] &&
           [ -n "$partial" ] &&
           [ -f "$partial/manifest.txt" ] &&
           [[ "$first_out" == *"kept for resume"* ]]; then
            echo -e "  ${GREEN}✓${NC} A failed capture publishes nothing and keeps a manifest-carrying partial."
        elif [ "$first_rc" -ne 0 ] &&
             [[ "$first_out" == *"native metadata preflight failed"* ]] &&
             [ -z "$(containers_matching "$resume_dest" partial)" ] &&
             [ -z "$(containers_matching "$resume_dest" final)" ]; then
            echo -e "  ${GREEN}✓${NC} Source metadata preflight rejected the inaccessible root before reserving a container."
            rm -rf "$resume_dest" "$resume_src"
            return 0
        else
            echo -e "  ${RED}✗${NC} Failed backup did not leave a resumable partial"
            echo "  exit=$first_rc output: $first_out"
            exit 1
        fi

        # Two control-slot hazards planted in the partial at once: a symlink
        # (which must not be written through) and, on the next round, a plain
        # file (which must not survive into the published container). Restore
        # acts on whatever packages.txt it finds without re-deriving scope, so
        # an explicit backup that publishes one would drive package installs it
        # never recorded.
        local pkg_sentinel="$TEST_DIR/cp_pkg_sentinel"
        echo untouched > "$pkg_sentinel"
        ln -s "$pkg_sentinel" "$partial/packages.txt"

        chmod 644 "$resume_src/locked.txt"
        local second_out
        second_out=$(../migr backup "$resume_dest" "$resume_src" 2>&1)

        local resumed
        resumed=$(sole_final_container "$resume_dest")
        assert_no_partial "$resume_dest"
        assert_contains "$second_out" "Resuming an interrupted backup"
        if [ "$(cat "$resumed/data/EXPLICIT_0/good.txt")" = "readable" ] &&
           [ "$(cat "$resumed/data/EXPLICIT_0/locked.txt")" = "locked" ]; then
            echo -e "  ${GREEN}✓${NC} The rerun adopted that partial and finalized it with the full payload."
        else
            echo -e "  ${RED}✗${NC} Resumed container is missing payload"
            echo "  output: $second_out"
            exit 1
        fi

        if [ "$(cat "$pkg_sentinel")" = "untouched" ] && [ ! -e "$resumed/packages.txt" ]; then
            echo -e "  ${GREEN}✓${NC} A symlinked packages.txt was neither written through nor published."
        else
            echo -e "  ${RED}✗${NC} A symlinked packages.txt was written through or survived into the final container"
            exit 1
        fi

        # Same shape, but a perfectly ordinary file: an explicit backup exports
        # no package list, so a resumed container must not publish one.
        local stale_dest="$TEST_DIR/cp_stale"
        mkdir -p "$stale_dest"
        chmod 000 "$resume_src/locked.txt"
        ../migr backup "$stale_dest" "$resume_src" >/dev/null 2>&1 || true
        local stale_partial
        stale_partial=$(containers_matching "$stale_dest" partial)
        echo "malicious-package" > "$stale_partial/packages.txt"
        chmod 644 "$resume_src/locked.txt"
        ../migr backup "$stale_dest" "$resume_src" >/dev/null 2>&1

        local stale_final
        stale_final=$(sole_final_container "$stale_dest")
        if [ ! -e "$stale_final/packages.txt" ]; then
            echo -e "  ${GREEN}✓${NC} A stale packages.txt in an adopted partial is cleared, not published."
        else
            echo -e "  ${RED}✗${NC} An explicit backup published a package list it never exported:"
            cat "$stale_final/packages.txt"
            exit 1
        fi

        # A control slot that cannot be cleared at all must block publication
        # rather than be finalized around.
        local stuck_dest="$TEST_DIR/cp_stuck"
        mkdir -p "$stuck_dest"
        chmod 000 "$resume_src/locked.txt"
        ../migr backup "$stuck_dest" "$resume_src" >/dev/null 2>&1 || true
        local stuck_partial
        stuck_partial=$(containers_matching "$stuck_dest" partial)
        mkdir -p "$stuck_partial/packages.txt/stuck"
        chmod 644 "$resume_src/locked.txt"

        local stuck_out stuck_rc
        set +e
        stuck_out=$(../migr backup "$stuck_dest" "$resume_src" 2>&1)
        stuck_rc=$?
        set -e
        if [ "$stuck_rc" -ne 0 ] &&
           [ -z "$(containers_matching "$stuck_dest" final)" ] &&
           [[ "$stuck_out" == *"could not clear packages.txt"* ]]; then
            echo -e "  ${GREEN}✓${NC} An unclearable control slot blocks finalization instead of being published."
        else
            echo -e "  ${RED}✗${NC} An unclearable packages.txt did not block finalization"
            echo "  exit=$stuck_rc output: $stuck_out"
            exit 1
        fi
    fi

    # --- a destination inside a selected root is refused before anything runs ---
    local self_out self_rc
    set +e
    self_out=$(../migr backup "$HOME/Documents/selfbackup" "$HOME/Documents" 2>&1)
    self_rc=$?
    set -e
    if [ "$self_rc" -ne 0 ] && [ ! -e "$HOME/Documents/selfbackup" ] &&
       [[ "$self_out" == *"destination is inside"* ]]; then
        echo -e "  ${GREEN}✓${NC} A destination inside a selected root is refused, creating nothing."
    else
        echo -e "  ${RED}✗${NC} A self-consuming destination was not refused"
        echo "  exit=$self_rc output: $self_out"
        exit 1
    fi

    set +e
    self_out=$(../migr backup "$HOME/Documents/selfbackup" "$HOME/Documents" --dry-run 2>&1)
    self_rc=$?
    set -e
    if [ "$self_rc" -ne 0 ] && [ ! -e "$HOME/Documents/selfbackup" ]; then
        echo -e "  ${GREEN}✓${NC} Dry run refuses it identically, also creating nothing."
    else
        echo -e "  ${RED}✗${NC} Dry run did not refuse a self-consuming destination"
        exit 1
    fi

    # A built-in scope selects HOME's own subtrees, so a destination inside one
    # of them is the same hazard without any explicit path being named.
    assert_fails_with "destination is inside" \
        ../migr backup "$HOME/Documents/inner_backup" --critical

    # A destination is a place to write into, so it must be followed through its
    # final symlink: a link living outside every root but pointing inside one
    # still writes inside one. (A root, by contrast, is copied as the object it
    # is and must not be dereferenced.)
    local alias_src="$HOME/alias_src" alias_link="$TEST_DIR/cp_target_link"
    mkdir -p "$alias_src/destination"
    echo payload > "$alias_src/file.txt"
    ln -s "$alias_src/destination" "$alias_link"

    local alias_out alias_rc
    set +e
    alias_out=$(../migr backup "$alias_link" "$alias_src" 2>&1)
    alias_rc=$?
    set -e
    local alias_entries
    alias_entries=$(find "$alias_src" | wc -l)
    if [ "$alias_rc" -ne 0 ] && [ "$alias_entries" -eq 3 ] &&
       [[ "$alias_out" == *"destination is inside"* ]]; then
        echo -e "  ${GREEN}✓${NC} A destination symlink aliasing into a root is refused, writing nothing."
    else
        echo -e "  ${RED}✗${NC} A destination symlink aliased past the containment check"
        echo "  exit=$alias_rc entries=$alias_entries output: $alias_out"
        exit 1
    fi

    # The same symlink pointing somewhere legitimate must still be usable, or
    # the check above would just be banning symlinked destinations.
    local ok_link="$TEST_DIR/cp_ok_link"
    mkdir -p "$TEST_DIR/cp_ok_dest"
    ln -s "$TEST_DIR/cp_ok_dest" "$ok_link"
    assert_contains "$(../migr backup "$ok_link" "$alias_src" 2>&1)" "Backup complete"

    # --- the packages.txt control slot is never opened in place ---
    # Both hazards below live in an adopted partial. Reusing whatever object is
    # already there would block the backup forever (a FIFO has no reader) or
    # destroy a file outside the container (a hardlink would be truncated and
    # overwritten with the package list).
    if [ "$(id -u)" -eq 0 ]; then
        echo -e "  ${BLUE}i${NC} Control-slot cases skipped (root bypasses 0000 permissions)."
    else
        # The unreadable file has to sit inside a root --critical actually
        # captures, or the first backup would simply succeed and leave no
        # partial to plant anything in.
        mkdir -p "$HOME/Documents"
        local slot_locked="$HOME/Documents/slot_locked.txt"

        # Leaves a partial behind, with its packages.txt removed so the hazard
        # can be planted in an empty slot.
        make_partial_with_empty_slot() {
            local dest="$1" p
            rm -rf "$dest"; mkdir -p "$dest"
            echo locked > "$slot_locked"
            chmod 000 "$slot_locked"
            ../migr backup "$dest" --critical >/dev/null 2>&1 || true
            chmod 644 "$slot_locked"
            p=$(containers_matching "$dest" partial)
            if [ -z "$p" ] || [ ! -d "$p" ]; then
                echo -e "  ${RED}✗${NC} fixture: no partial container to plant a control-slot hazard in" >&2
                exit 1
            fi
            rm -f "$p/packages.txt"
            printf '%s' "$p"
        }

        local fifo_dest="$TEST_DIR/cp_slot_fifo" fifo_partial fifo_rc
        fifo_partial=$(make_partial_with_empty_slot "$fifo_dest")
        mkfifo "$fifo_partial/packages.txt"
        set +e
        timeout 60 ../migr backup "$fifo_dest" --critical >/dev/null 2>&1
        fifo_rc=$?
        set -e
        local fifo_final
        fifo_final=$(sole_final_container "$fifo_dest")
        if [ "$fifo_rc" -ne 124 ] && [ -f "$fifo_final/packages.txt" ] &&
           [ ! -p "$fifo_final/packages.txt" ]; then
            echo -e "  ${GREEN}✓${NC} A FIFO in the packages.txt slot neither blocks the backup nor survives it."
        else
            echo -e "  ${RED}✗${NC} A FIFO packages.txt blocked the backup or was published (exit=$fifo_rc)"
            exit 1
        fi

        local hl_dest="$TEST_DIR/cp_slot_hardlink" hl_partial
        local hl_sentinel="$TEST_DIR/cp_slot_sentinel"
        echo sentinel-original > "$hl_sentinel"
        hl_partial=$(make_partial_with_empty_slot "$hl_dest")
        ln "$hl_sentinel" "$hl_partial/packages.txt"
        ../migr backup "$hl_dest" --critical >/dev/null 2>&1

        local hl_final
        hl_final=$(sole_final_container "$hl_dest")
        if [ "$(cat "$hl_sentinel")" = "sentinel-original" ] &&
           [ "$(stat -c '%h' "$hl_sentinel")" -eq 1 ] &&
           [ -s "$hl_final/packages.txt" ]; then
            echo -e "  ${GREEN}✓${NC} A hardlinked packages.txt is unlinked, not truncated: the outside file survives."
        else
            echo -e "  ${RED}✗${NC} A hardlinked packages.txt was written through to a file outside the container"
            echo "  sentinel: $(head -1 "$hl_sentinel")  links: $(stat -c '%h' "$hl_sentinel")"
            exit 1
        fi
    fi

    # --- an external root stays MANUAL_NATIVE: captured, reported, never restored ---
    local ext_dest="$TEST_DIR/cp_ext" ext_root="$TEST_DIR/outside_home"
    mkdir -p "$ext_dest" "$ext_root"
    echo external > "$ext_root/data.txt"
    ../migr backup "$ext_dest" "$HOME/Documents" "$ext_root" >/dev/null 2>&1

    local ext_actual
    ext_actual=$(sole_final_container "$ext_dest")
    if grep -q "^ROOT ID=EXPLICIT_1 POLICY=MANUAL_NATIVE " "$ext_actual/manifest.txt" &&
       [ "$(cat "$ext_actual/data/EXPLICIT_1/data.txt")" = "external" ]; then
        echo -e "  ${GREEN}✓${NC} An external root is captured under data/ as MANUAL_NATIVE."
    else
        echo -e "  ${RED}✗${NC} External root not captured as MANUAL_NATIVE"
        cat "$ext_actual/manifest.txt"
        exit 1
    fi

    local ext_home="$TEST_DIR/cp_ext_home" ext_restore_out
    mkdir -p "$ext_home"
    ext_restore_out=$(printf 'y\n' | env HOME="$ext_home" ../migr restore "$ext_actual" 2>&1)
    assert_contains "$ext_restore_out" "Manual Roots"
    assert_contains "$ext_restore_out" "$ext_root"
    # the home-relative sibling root proves the restore itself ran
    if [ -f "$ext_home/Documents/note.txt" ] && [ ! -e "$ext_home/data.txt" ]; then
        echo -e "  ${GREEN}✓${NC} Restore recreates the home-relative root and leaves the external one alone."
    else
        echo -e "  ${RED}✗${NC} MANUAL_NATIVE root was auto-restored, or the home-relative root was not"
        echo "  output: $ext_restore_out"
        exit 1
    fi
}

test_portable_vfat_dispatch() {
    echo -e "${BLUE}::${NC} Phase 15: real-vfat portable dispatch smoke"

    if [ "$(id -u)" -ne 0 ]; then
        echo -e "  ${BLUE}↷${NC} skipped: root is required for loop and mount setup."
        return
    fi

    local tool
    for tool in losetup mkfs.vfat mount; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo -e "  ${BLUE}↷${NC} skipped: '$tool' is not available."
            return
        fi
    done

    local image="$TEST_DIR/portable-vfat.img"
    local mount_point="$TEST_DIR/portable-vfat"
    local loop loop_output mkfs_output mount_output
    local output actual_backup

    if ! dd if=/dev/zero of="$image" bs=1M count=64 >/dev/null 2>&1; then
        echo -e "  ${BLUE}↷${NC} skipped: could not create the VFAT image."
        return
    fi

    if ! loop=$(losetup -f 2>&1); then
        echo -e "  ${BLUE}↷${NC} skipped: could not find a free loop device."
        echo "$loop"
        return
    fi
    if ! loop_output=$(losetup "$loop" "$image" 2>&1); then
        echo -e "  ${BLUE}↷${NC} skipped: could not attach the VFAT image."
        echo "$loop_output"
        return
    fi
    PORTABLE_VFAT_LOOP="$loop"

    if ! mkfs_output=$(mkfs.vfat "$loop" 2>&1); then
        echo -e "  ${BLUE}↷${NC} skipped: VFAT formatting is unavailable."
        echo "$mkfs_output"
        return
    fi

    mkdir -p "$mount_point"
    if ! mount_output=$(mount -t vfat "$loop" "$mount_point" 2>&1); then
        echo -e "  ${BLUE}↷${NC} skipped: VFAT mounting is unavailable."
        echo "$mount_output"
        return
    fi
    PORTABLE_VFAT_MOUNT="$mount_point"

    rm -rf "$HOME"
    mkdir -p "$HOME/Documents"
    echo "vfat smoke" > "$HOME/Documents/note.txt"
    echo "second vfat file" > "$HOME/Documents/second.txt"

    local portable_dry portable_dry_verbose
    portable_dry=$(../migr backup "$mount_point/dry-run-dest" --dry-run 2>&1)
    portable_dry_verbose=$(../migr backup "$mount_point/dry-run-dest" --dry-run -v 2>&1)
    if [ "$portable_dry" = "$portable_dry_verbose" ]; then
        echo -e "  ${GREEN}✓${NC} Portable dry-run is unchanged by verbose."
    else
        echo -e "  ${RED}✗${NC} Portable dry-run changed under verbose."
        exit 1
    fi

    output=$(../migr backup "$mount_point/dest" -v 2>&1)
    assert_contains "$output" "Backup complete"

    local capture_verbose_count
    capture_verbose_count=$(grep -F -c "  Capturing: $HOME/Documents -> data/XDG_DOCUMENTS_DIR" <<<"$output" || true)
    if [ "$capture_verbose_count" -eq 1 ]; then
        echo -e "  ${GREEN}✓${NC} Portable capture reports the root once, not once per file."
    else
        echo -e "  ${RED}✗${NC} Portable capture reported the root $capture_verbose_count time(s)."
        echo "$output"
        exit 1
    fi

    actual_backup=$(sole_final_container "$mount_point/dest")
    # A sidecar proves that the production CLI selected the portable path.
    assert_file_exists "$actual_backup/sidecar.migr"

    rm -f "$actual_backup/packages.txt"
    rm -rf "$HOME"
    mkdir -p "$HOME"
    output=$(printf 'y\n' | ../migr restore "$actual_backup" -v 2>&1)
    assert_contains "$output" "Restore complete"
    assert_not_contains "$output" "Restored:"
    local restore_verbose_count
    restore_verbose_count=$(grep -F -c "  Restoring: XDG_DOCUMENTS_DIR" <<<"$output" || true)
    if [ "$restore_verbose_count" -eq 1 ]; then
        echo -e "  ${GREEN}✓${NC} Portable restore reports the root once, not once per file."
    else
        echo -e "  ${RED}✗${NC} Portable restore reported the root $restore_verbose_count time(s)."
        echo "$output"
        exit 1
    fi
    assert_file_exists "$HOME/Documents/note.txt"
    if [ "$(cat "$HOME/Documents/note.txt")" = "vfat smoke" ]; then
        echo -e "  ${GREEN}✓${NC} Restored VFAT fixture content matches byte-for-byte."
    else
        echo -e "  ${RED}✗${NC} Restored VFAT fixture content does not match."
        exit 1
    fi

    if ! command -v socat >/dev/null 2>&1; then
        echo -e "  ${BLUE}↷${NC} skipped: 'socat' is not available for the portable TTY check."
        return
    fi

    local portable_progress_home="$TEST_DIR/portable_progress_home"
    mkdir -p "$portable_progress_home"
    local portable_pty_output portable_pty_rc
    set +e
    portable_pty_output=$(printf 'y\n' | socat - \
        "EXEC:env HOME=$portable_progress_home ../migr restore $actual_backup -v,pty,setsid,ctty,echo=0" \
        2>&1)
    portable_pty_rc=$?
    set -e
    if [ "$portable_pty_rc" -eq 0 ] &&
       [[ "$portable_pty_output" == *"Restored:"* ]] &&
       [[ "$portable_pty_output" == *"note.txt"* ]] &&
       [[ "$portable_pty_output" == *"elapsed 00:"* ]] &&
       [[ "$portable_pty_output" == *"speed "* ]] &&
       [ -f "$portable_progress_home/Documents/note.txt" ]; then
        echo -e "  ${GREEN}✓${NC} Portable restore shows progress on a real TTY."
    else
        echo -e "  ${RED}✗${NC} Portable restore did not produce TTY progress"
        echo "  exit=$portable_pty_rc output: $portable_pty_output"
        exit 1
    fi
}

# --- 4. RUN TESTS ---
echo -e "${BLUE}migr integration tests${NC}"
setup
test_report
test_dry_run
test_backup
test_restore
test_packages
test_error_propagation
test_comprehensive
test_explicit_paths
test_errors
test_truncation
test_restore_path_safety
test_v1_restore_dispatch
test_xdg_nested_destination_recovery
test_native_restore_progress
test_probe_refusal
test_container_production
test_portable_vfat_dispatch
echo -e "${GREEN}all tests passed${NC}"

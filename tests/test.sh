#!/bin/bash

# Halt on any error, fail on undefined variables, and catch pipeline failures
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

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


# --- 3. LIFECYCLE ---
test_report() {
    echo -e "${BLUE}::${NC} Phase 1: report"

    local output
    output=$(../migr report)

    assert_contains "$output" ".bashrc"
    assert_contains "$output" ".ssh"
    assert_contains "$output" "Documents"
}

test_dry_run() {
    echo -e "${BLUE}::${NC} Phase 2: --dry-run"

    local output
    output=$(../migr backup "$BACKUP_DIR" -n)

    assert_contains "$output" "Dry run"

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
}

test_backup() {
    echo -e "${BLUE}::${NC} Phase 3: backup"

    local output
    # -v needed: without it, individual filenames are not printed
    output=$(../migr backup "$BACKUP_DIR" -v)

    assert_contains "$output" "Backup complete"
    assert_contains "$output" ".bashrc"
    assert_contains "$output" ".ssh"
    assert_contains "$output" ".gitconfig"

    # verify backup subdirectory was actually created on disk
    local actual_backup
    actual_backup=$(find "$BACKUP_DIR" -maxdepth 1 -name 'migr_backup_*' -type d | head -1)

    assert_file_exists "$actual_backup/Documents/note.txt"
    assert_file_exists "$actual_backup/.ssh/config"
    assert_file_exists "$actual_backup/.bashrc"

    if [ -p "$actual_backup/Documents/events.fifo" ]; then
        echo -e "  ${GREEN}✓${NC} FIFO preserved as a FIFO."
    else
        echo -e "  ${RED}✗${NC} FIFO not copied as a FIFO: '$actual_backup/Documents/events.fifo'"
        exit 1
    fi

    # verify symlink was faithfully copied as a symlink, not a regular file
    if [ -L "$actual_backup/Documents/shortcut" ]; then
        echo -e "  ${GREEN}✓${NC} Symlink preserved."
    else
        echo -e "  ${RED}✗${NC} Symlink not copied as symlink: '$actual_backup/Documents/shortcut'"
        exit 1
    fi

    # the absolute symlink must actually have been copied — otherwise the source-mode
    # check below passes vacuously (nothing was there to mutate the target through)
    if [ -L "$actual_backup/Documents/cfg-link" ] && \
       [ "$(readlink "$actual_backup/Documents/cfg-link")" = "$HOME/.ssh/config" ]; then
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

    # browser profiles backed up at the correct nested paths
    assert_file_exists "$actual_backup/.mozilla/firefox/profile/places.sqlite"
    assert_file_exists "$actual_backup/.config/google-chrome/Default/Preferences"

    # Desktop must not appear in a critical backup
    if [ -e "$actual_backup/Desktop" ]; then
        echo -e "  ${RED}✗${NC} Desktop should not be in a critical backup"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Desktop correctly excluded from critical backup."
    fi

    # manifest.txt must be present and contain at least one XDG key
    assert_file_exists "$actual_backup/manifest.txt"
    if grep -q "XDG_DOCUMENTS_DIR=" "$actual_backup/manifest.txt"; then
        echo -e "  ${GREEN}✓${NC} manifest.txt contains XDG_DOCUMENTS_DIR entry."
    else
        echo -e "  ${RED}✗${NC} manifest.txt missing XDG_DOCUMENTS_DIR entry!"
        exit 1
    fi
}

test_restore() {
    echo -e "${BLUE}::${NC} Phase 4: restore"

    # wipe home to simulate a fresh system
    rm -rf "$HOME"
    mkdir -p "$HOME"

    # restore() requires the dated subdir created by backup, not $BACKUP_DIR itself
    local actual_backup
    actual_backup=$(find "$BACKUP_DIR" -maxdepth 1 -name 'migr_backup_*' -type d | head -1)

    # remove packages.txt so restore skips the sudo package install step
    rm -f "$actual_backup/packages.txt"

    local output
    # restore() calls confirm_action() — pipe "y" to mock user interaction
    output=$(echo "y" | ../migr restore "$actual_backup")

    assert_contains "$output" "Restore complete"

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

    local pkg_file="$TEST_DIR/pkgs.txt"
    ../migr packages "$pkg_file"

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

    # and the summary must not claim plain success
    assert_contains "$output" "errors"
}

test_comprehensive() {
    echo -e "${BLUE}::${NC} Phase 7: backup --comprehensive"

    local comp_backup="$TEST_DIR/backup_comprehensive"
    mkdir -p "$comp_backup"

    # Desktop was not restored by the critical backup in Phase 4, so recreate it
    mkdir -p "$HOME/Desktop"
    echo "icon" > "$HOME/Desktop/browser.desktop"

    local output
    output=$(../migr backup "$comp_backup" --comprehensive)

    assert_contains "$output" "Backup complete"

    local actual_backup
    actual_backup=$(find "$comp_backup" -maxdepth 1 -name 'migr_backup_*' -type d | head -1)

    # Desktop is in comprehensive but NOT critical — its presence proves the right mode ran
    assert_file_exists "$actual_backup/Desktop"
    assert_file_exists "$actual_backup/Documents"
}

test_explicit_paths() {
    echo -e "${BLUE}::${NC} Phase 8: backup <PATH...>"

    local paths_backup="$TEST_DIR/backup_paths"
    mkdir -p "$paths_backup"

    local output
    output=$(../migr backup "$paths_backup" "$HOME/Documents")

    assert_contains "$output" "Backup complete"

    local actual_backup
    actual_backup=$(find "$paths_backup" -maxdepth 1 -name 'migr_backup_*' -type d | head -1)

    # specified path is present
    assert_file_exists "$actual_backup/Documents"

    # dotfiles must be absent — explicit-paths mode makes no assumptions
    if [ -e "$actual_backup/.bashrc" ]; then
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

    # manifest.txt must also be absent — explicit-paths mode makes no XDG assumptions
    if [ -e "$actual_backup/manifest.txt" ]; then
        echo -e "  ${RED}✗${NC} manifest.txt should not be in an explicit-paths backup"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} manifest.txt correctly excluded from explicit-paths backup."
    fi

    # A trailing slash must not flatten a directory into the backup root and
    # overwrite another explicit item with the same child name.
    local trailing_backup="$TEST_DIR/backup_paths_trailing"
    mkdir -p "$HOME/dir_a" "$HOME/dir_b" "$trailing_backup"
    echo A > "$HOME/dir_a/same.txt"
    echo B > "$HOME/dir_b/same.txt"

    output=$(../migr backup "$trailing_backup" "$HOME/dir_a/same.txt" "$HOME/dir_b/")
    assert_contains "$output" "Backup complete"

    local trailing_actual
    trailing_actual=$(find "$trailing_backup" -maxdepth 1 -name 'migr_backup_*' -type d | head -1)
    assert_file_exists "$trailing_actual/same.txt"
    assert_file_exists "$trailing_actual/dir_b/same.txt"

    if [ "$(cat "$trailing_actual/same.txt")" = "A" ] && \
       [ "$(cat "$trailing_actual/dir_b/same.txt")" = "B" ]; then
        echo -e "  ${GREEN}✓${NC} Trailing slash preserved both explicit items."
    else
        echo -e "  ${RED}✗${NC} Trailing slash caused explicit items to overwrite or merge."
        exit 1
    fi
}

test_errors() {
    echo -e "${BLUE}::${NC} Phase 9: error paths"

    # missing required arguments
    assert_exits_nonzero ../migr backup
    assert_exits_nonzero ../migr restore
    assert_exits_nonzero ../migr packages
    assert_exits_nonzero ../migr restore /nonexistent/path

    # unrecognised command word
    assert_exits_nonzero ../migr bogus

    # the two scope flags are mutually exclusive
    assert_exits_nonzero ../migr backup "$BACKUP_DIR" --critical --comprehensive

    # a scope flag cannot be combined with explicit paths
    assert_exits_nonzero ../migr backup "$BACKUP_DIR" --comprehensive "$HOME/Documents"

    # scope flags apply to backup only
    assert_exits_nonzero ../migr restore "$BACKUP_DIR" --comprehensive

    # commands that take exactly one positional reject extras
    assert_exits_nonzero ../migr restore "$BACKUP_DIR" /tmp/extra
    assert_exits_nonzero ../migr packages /tmp/one /tmp/two

    # report takes no arguments at all
    assert_exits_nonzero ../migr report /tmp/somewhere

    # explicit paths sharing a basename must be refused, not silently merged/overwritten
    mkdir -p "$HOME/dir_a" "$HOME/dir_b"
    echo A > "$HOME/dir_a/same.txt"
    echo B > "$HOME/dir_b/same.txt"
    assert_exits_nonzero ../migr backup "$BACKUP_DIR" "$HOME/dir_a/same.txt" "$HOME/dir_b/same.txt"

    # The filesystem root has no leaf name to place under the backup directory.
    assert_exits_nonzero ../migr backup "$BACKUP_DIR" /
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

    # Gap 2: a per-item destination that overflows PATH_MAX must be refused in
    # dry-run exactly as it is live, so the preview cannot promise a copy that
    # would fail. Build a target long enough that backup_dir/<leaf> overflows while
    # backup_dir itself still fits, so clone_item trips rather than the date check.
    local deep="$TEST_DIR/deep" comp
    comp=$(head -c 100 </dev/zero | tr '\0' c)
    while [ ${#deep} -lt 3850 ]; do deep="$deep/$comp"; done
    mkdir -p "$deep" # must exist: create_dir is non-recursive, so the live run
                     # needs the target already present to reach clone_item
    local leaf src
    leaf=$(head -c 250 </dev/zero | tr '\0' x)
    src="$TEST_DIR/$leaf"
    echo hi > "$src"

    local dry live live_out
    set +e
    ../migr backup "$deep" "$src" --dry-run >/dev/null 2>&1
    dry=$?
    live_out=$(../migr backup "$deep" "$src" 2>&1)
    live=$?
    set -e

    if [ "$dry" -eq "$live" ] && [ "$dry" -ne 0 ] && [[ "$live_out" == *"Destination path too long"* ]]; then
        echo -e "  ${GREEN}✓${NC} Truncating destination refused identically in dry-run and live (exit $dry)."
    else
        echo -e "  ${RED}✗${NC} dry-run/live parity broken: dry=$dry live=$live"
        echo "  live output: $live_out"
        exit 1
    fi

    # The fd-anchored restore core resolves destination_rel component by
    # component and never concatenates the full browser path. A deep but valid
    # HOME must therefore work in both preview and live restore.
    local deep_home="$TEST_DIR/deep_home" room part_len
    mkdir "$deep_home"
    while [ ${#deep_home} -lt 4080 ]; do
        room=$((4080 - ${#deep_home} - 1))
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
    mkdir -p "$canon_base/a" "$canon_state" "$canon_cache" "$canon_config"
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
    canon_actual=$(find "$canon_backup" -maxdepth 1 -name 'migr_backup_*' -type d | head -1)
    if [ -n "$canon_actual" ] &&
       [ -f "$canon_actual/packages.txt" ] &&
       grep -q "XDG_DOCUMENTS_DIR=" "$canon_actual/manifest.txt" 2>/dev/null &&
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
    dry_out=$(env HOME="$v1_home" ../migr restore "$v1_src" --dry-run)
    assert_contains "$dry_out" "[Roots]"
    assert_contains "$dry_out" "Would restore: EXPLICIT_0 -> ~/Documents/project"
    assert_contains "$dry_out" "[Manual Roots]"
    assert_contains "$dry_out" "/mnt/external/project"

    local live_out
    live_out=$(printf 'y\n' | env HOME="$v1_home" ../migr restore "$v1_src")
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

    # Same read-only destination under --dry-run: no probe, no writes, clean exit.
    local dr_out dr_rc
    set +e
    dr_out=$(../migr backup "$ro_dest" --dry-run 2>&1)
    dr_rc=$?
    set -e
    if [ "$dr_rc" -ne 0 ]; then
        echo -e "  ${RED}✗${NC} dry-run on read-only dest should succeed; exit=$dr_rc"
        echo "  output: $dr_out"
        exit 1
    fi
    if compgen -G "$ro_dest/migr_backup_*" > /dev/null; then
        echo -e "  ${RED}✗${NC} dry-run wrote a backup dir into a read-only dest"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} dry-run on read-only dest refused nothing and wrote nothing"
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
test_probe_refusal
echo -e "${GREEN}all tests passed${NC}"

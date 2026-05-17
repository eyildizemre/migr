#!/bin/bash

# Halt on any error, and print commands as they are executed
set -e

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
    echo "secret"    > "$HOME/.ssh/config"
    echo "gituser"   > "$HOME/.gitconfig"
    echo "alias ll='ls -la'" > "$HOME/.bashrc"
    echo "export PATH"       > "$HOME/.profile"
    ln -s "$HOME/Documents/note.txt" "$HOME/Documents/shortcut"
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


# --- 3. LIFECYCLE ---
test_report() {
    echo -e "${BLUE}::${NC} Phase 1: -report"

    local output
    output=$(../migr -report)

    assert_contains "$output" ".bashrc"
    assert_contains "$output" ".ssh"
    assert_contains "$output" "Documents"
}

test_dry_run() {
    echo -e "${BLUE}::${NC} Phase 2: -dry-run"

    local output
    output=$(../migr -backup "$BACKUP_DIR" -n)

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
    echo -e "${BLUE}::${NC} Phase 3: -backup"

    local output
    # -v needed: without it, individual filenames are not printed
    output=$(../migr -backup "$BACKUP_DIR" -v)

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

    # verify symlink was faithfully copied as a symlink, not a regular file
    if [ -L "$actual_backup/Documents/shortcut" ]; then
        echo -e "  ${GREEN}✓${NC} Symlink preserved."
    else
        echo -e "  ${RED}✗${NC} Symlink not copied as symlink: '$actual_backup/Documents/shortcut'"
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
}

test_restore() {
    echo -e "${BLUE}::${NC} Phase 4: -restore"

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
    output=$(echo "y" | ../migr -restore "$actual_backup")

    assert_contains "$output" "Restore complete"

    assert_file_exists "$HOME/Documents/note.txt"
    assert_file_exists "$HOME/.ssh/config"
    assert_file_exists "$HOME/.bashrc"

    # nested browser profiles must restore to the correct location, 
    # not $HOME/firefox or $HOME/google-chrome
    assert_file_exists "$HOME/.mozilla/firefox/profile/places.sqlite"
    assert_file_exists "$HOME/.config/google-chrome/Default/Preferences"
}

test_packages() {
    echo -e "${BLUE}::${NC} Phase 5: -packages"

    local pkg_file="$TEST_DIR/pkgs.txt"
    ../migr -packages "$pkg_file"

    assert_file_exists "$pkg_file"

    if [ -s "$pkg_file" ]; then
        echo -e "  ${GREEN}✓${NC} Package list is non-empty."
    else
        echo -e "  ${RED}✗${NC} Package list is empty: '$pkg_file'"
        exit 1
    fi
}

test_comprehensive() {
    echo -e "${BLUE}::${NC} Phase 7: -backup -comprehensive"

    local comp_backup="$TEST_DIR/backup_comprehensive"
    mkdir -p "$comp_backup"

    # Desktop was not restored by the critical backup in Phase 4, so recreate it
    mkdir -p "$HOME/Desktop"
    echo "icon" > "$HOME/Desktop/browser.desktop"

    local output
    output=$(../migr -backup "$comp_backup" -comprehensive)

    assert_contains "$output" "Backup complete"

    local actual_backup
    actual_backup=$(find "$comp_backup" -maxdepth 1 -name 'migr_backup_*' -type d | head -1)

    # Desktop is in comprehensive but NOT critical — its presence proves the right mode ran
    assert_file_exists "$actual_backup/Desktop"
    assert_file_exists "$actual_backup/Documents"
}

test_paths() {
    echo -e "${BLUE}::${NC} Phase 8: -backup -paths"

    local paths_backup="$TEST_DIR/backup_paths"
    mkdir -p "$paths_backup"

    local output
    output=$(../migr -backup "$paths_backup" -paths "$HOME/Documents")

    assert_contains "$output" "Backup complete"

    local actual_backup
    actual_backup=$(find "$paths_backup" -maxdepth 1 -name 'migr_backup_*' -type d | head -1)

    # specified path is present
    assert_file_exists "$actual_backup/Documents"

    # dotfiles must be absent — paths mode makes no assumptions
    if [ -e "$actual_backup/.bashrc" ]; then
        echo -e "  ${RED}✗${NC} .bashrc should not be in a -paths backup"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} Dotfiles correctly excluded from -paths backup."
    fi

    # packages.txt must be absent
    if [ -e "$actual_backup/packages.txt" ]; then
        echo -e "  ${RED}✗${NC} packages.txt should not be in a -paths backup"
        exit 1
    else
        echo -e "  ${GREEN}✓${NC} packages.txt correctly excluded from -paths backup."
    fi
}

test_errors() {
    echo -e "${BLUE}::${NC} Phase 9: error paths"

    assert_exits_nonzero ../migr -backup
    assert_exits_nonzero ../migr -restore
    assert_exits_nonzero ../migr -restore /nonexistent/path
    assert_exits_nonzero ../migr -backup "$BACKUP_DIR" -paths
}


# --- 4. RUN TESTS ---
echo -e "${BLUE}migr integration tests${NC}"
setup
test_report
test_dry_run
test_backup
test_restore
test_packages
test_comprehensive
test_paths
test_errors
echo -e "${GREEN}all tests passed${NC}"

#!/bin/bash

# Halt on any error, and print commands as they are executed
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 1. SETUP & TEARDOWN ---
setup() {
    TEST_DIR=$(mktemp -d)
    export TEST_DIR
    export HOME="$TEST_DIR/home"
    export BACKUP_DIR="$TEST_DIR/backup_drive"

    mkdir -p "$HOME/Documents"
    mkdir -p "$HOME/Desktop"
    mkdir -p "$HOME/Projects"
    mkdir -p "$HOME/.ssh"
    mkdir -p "$HOME/.gnupg"
    mkdir -p "$BACKUP_DIR"

    echo "test doc" > "$HOME/Documents/note.txt"
    echo "secret" > "$HOME/.ssh/config"
    echo "gituser" > "$HOME/.gitconfig"
    echo "alias ll='ls -la'" > "$HOME/.bashrc"
    echo "export PATH" > "$HOME/.profile"
    ln -s "$HOME/Documents/note.txt" "$HOME/Documents/shortcut"
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
    if "$@" 2>/dev/null; then
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

    # assert no backup directory was actually created on disk
    shopt -s nullglob
    backup_dirs=("$BACKUP_DIR"/migr_backup_*)
    shopt -u nullglob
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
    # restore() calls confirm_action() — pipe "y" to satisfy the prompt
    output=$(echo "y" | ../migr -restore "$actual_backup")

    assert_contains "$output" "Restore complete"

    assert_file_exists "$HOME/Documents/note.txt"
    assert_file_exists "$HOME/.ssh/config"
    assert_file_exists "$HOME/.bashrc"
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

test_errors() {
    echo -e "${BLUE}::${NC} Phase 6: error paths"

    assert_exits_nonzero ../migr -backup
    assert_exits_nonzero ../migr -restore
    assert_exits_nonzero ../migr -restore /nonexistent/path
}


# --- 4. RUN TESTS ---
echo -e "${BLUE}migr integration tests${NC}"
setup
test_report
test_dry_run
test_backup
test_restore
test_packages
test_errors
echo -e "${GREEN}all tests passed${NC}"

CC = gcc
# Packagers pass their own CFLAGS, CPPFLAGS, and LDFLAGS (optimization,
# hardening); the flags migr itself needs are added to whatever they give.
CFLAGS ?= -g
override CFLAGS += -Wall -Wextra -I src -pthread
# Each object records the headers it includes, so a changed header rebuilds it:
# -MMD writes that list beside the object as a make rule (foo.o -> foo.d),
# -MP adds an empty rule per header so a deleted header does not break the
# build. The last line of this file reads the .d files back; git ignores
# them and clean removes them.
DEPFLAGS = -MMD -MP

# Test fixtures set HOME explicitly; a sudo-inherited caller UID must not
# redirect them into the invoking user's real account.
unexport SUDO_UID

CHECK_STRICT_FLAGS = $(CFLAGS) -Wpedantic -Werror
CHECK_SANITIZE_FLAGS = $(CHECK_STRICT_FLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer
ANALYZER_CC = gcc
ANALYZER_FLAGS = $(CFLAGS) -Wpedantic -Werror -fanalyzer

# Valgrind covers the non-scale test suite plus the native visited-set and native
# hardlink inode-map scale tests, whose large allocation volumes are themselves
# memory-safety subjects. Five larger scale binaries remain excluded because of
# their disproportionate runtime.
VALGRIND_TESTS = \
	tests/test_detect \
	tests/test_manifest_selection \
	tests/test_native_selection \
	tests/test_portable_selection \
	tests/test_selection \
	tests/test_config \
	tests/test_report \
	tests/test_pathjoin \
	tests/test_fd_limit \
	tests/test_confirm \
	tests/test_packages \
	tests/test_xdg \
	tests/test_get_dir_size \
	tests/test_run_command \
	tests/test_fsprobe \
	tests/test_manifest \
	tests/test_encoding \
	tests/test_portable_name \
	tests/test_container \
	tests/test_selfcopy \
	tests/test_console \
	tests/test_subid \
	tests/test_podman_state \
	tests/test_sidecar \
	tests/test_sidecar_state \
	tests/test_portable_hashset \
	tests/test_portable_capture \
	tests/test_portable_prepare \
	tests/test_native_reconcile_scale \
	tests/test_native_hardlink_scale \
	tests/test_portable_resume \
	tests/test_portable_reconcile \
	tests/test_portable_restore_preflight \
	tests/test_verify \
	tests/test_repair \
	tests/test_source_snapshot \
	tests/test_portable_restore_replay \
	tests/test_portable_restore_orchestrate \
	tests/test_portable_restore_invariant \
	tests/test_special_files \
	tests/test_restore_native \
	tests/test_restore_sync \
	tests/test_restore_source_read \
	tests/test_backup_source_read \
	tests/test_backup_sync \
	tests/test_restore_dispatch \
	tests/test_restore_atime \
	tests/test_metadata_contract \
	tests/test_metadata_snapshots \
	tests/test_backup_plan \
	$(FUZZ_REPLAY_SIDECAR_PARSE) \
	$(FUZZ_REPLAY_SIDECAR_LOAD) \
	$(FUZZ_REPLAY_SIDECAR_ROUNDTRIP) \
	$(FUZZ_REPLAY_NAMES) \
	$(FUZZ_REPLAY_REPAIR_SALVAGE) \
	$(FUZZ_REPLAY_HOME_REWRITE) \
	$(FUZZ_REPLAY_MANIFEST)

TARGET = migr
STATIC_TARGET = migr-static
VPATH = src
SRCS = selection_match.c selection.c config.c main.c detect.c report.c backup.c backup_plan.c packages.c groups.c flatpak.c restore.c console.c dconf_restore.c live_state.c utils.c selfcopy.c fileops.c fsprobe.c xdg.c manifest.c encoding.c portable_name.c container.c metadata.c metadata_xattr.c portable_hashset.c portable_prescan.c portable_fsops.c portable.c portable_reconcile.c portable_move.c move.c portable_restore_replay.c portable_restore_shared.c portable_restore_orchestrate.c portable_restore_preflight.c sidecar.c sidecar_state.c sidecar_state_map.c hash.c verify.c repair.c source_snapshot.c writer_apps.c home_rewrite.c subid.c podman_state.c
OBJS = $(SRCS:.c=.o)
# Every object but main.o, which tests link against.
LIB_OBJS = $(filter-out main.o,$(OBJS))
# LIB_OBJS with the named test-hook builds (x_test.o) in place of their
# plain ones (x.o).
with_hooks = $(1) $(filter-out $(patsubst %_test.o,%.o,$(1)),$(LIB_OBJS))
STATIC_OBJS = $(SRCS:.c=_static.o)
ANALYZER_SRCS = $(wildcard src/*.c)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS)

$(STATIC_TARGET): $(STATIC_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -static -o $(STATIC_TARGET) $(STATIC_OBJS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

%_static.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

TEST_DETECT = tests/test_detect
TEST_MANIFEST_SELECTION = tests/test_manifest_selection
TEST_NATIVE_SELECTION = tests/test_native_selection
TEST_PORTABLE_SELECTION = tests/test_portable_selection
TEST_SELECTION = tests/test_selection
TEST_CONFIG = tests/test_config
TEST_REPORT = tests/test_report
TEST_PATHJOIN = tests/test_pathjoin
TEST_FD_LIMIT = tests/test_fd_limit
TEST_CONFIRM = tests/test_confirm
TEST_PACKAGES = tests/test_packages
TEST_XDG = tests/test_xdg
TEST_GET_DIR_SIZE = tests/test_get_dir_size
TEST_RUN_COMMAND = tests/test_run_command
TEST_SPECIAL_FILES = tests/test_special_files
TEST_FSPROBE = tests/test_fsprobe
TEST_MANIFEST = tests/test_manifest
TEST_ENCODING = tests/test_encoding
TEST_PORTABLE_NAME = tests/test_portable_name
TEST_CONTAINER = tests/test_container
TEST_SELFCOPY = tests/test_selfcopy
TEST_CONSOLE = tests/test_console
TEST_SUBID = tests/test_subid
TEST_PODMAN_STATE = tests/test_podman_state
TEST_RESTORE_NATIVE = tests/test_restore_native
TEST_RESTORE_SYNC = tests/test_restore_sync
TEST_RESTORE_SOURCE_READ = tests/test_restore_source_read
TEST_BACKUP_SOURCE_READ = tests/test_backup_source_read
TEST_VSCODE_CAPTURE = tests/test_vscode_capture
TEST_DCONF_RESTORE = tests/test_dconf_restore
TEST_LIVE_STATE = tests/test_live_state
TEST_VERIFY = tests/test_verify
TEST_MIGR_UNPRIVILEGED = tests/migr-unprivileged
TEST_REPAIR = tests/test_repair
TEST_SOURCE_SNAPSHOT = tests/test_source_snapshot
TEST_BACKUP_SYNC = tests/test_backup_sync
TEST_RESTORE_DISPATCH = tests/test_restore_dispatch
TEST_RESTORE_ATIME = tests/test_restore_atime
TEST_BACKUP_PLAN = tests/test_backup_plan
TEST_METADATA_CONTRACT = tests/test_metadata_contract
TEST_METADATA_SNAPSHOTS = tests/test_metadata_snapshots
TEST_SIDECAR = tests/test_sidecar
TEST_SIDECAR_STATE = tests/test_sidecar_state
TEST_SIDECAR_SCALE = tests/test_sidecar_scale
TEST_PORTABLE_HASHSET = tests/test_portable_hashset
TEST_PORTABLE_CAPTURE = tests/test_portable_capture
TEST_PORTABLE_CAPTURE_SCALE = tests/test_portable_capture_scale
TEST_PORTABLE_PREPARE = tests/test_portable_prepare
TEST_NATIVE_RECONCILE_SCALE = tests/test_native_reconcile_scale
TEST_NATIVE_HARDLINK_SCALE = tests/test_native_hardlink_scale
TEST_PORTABLE_COLLISION_SCALE = tests/test_portable_collision_scale
TEST_PORTABLE_HARDLINK_SCALE = tests/test_portable_hardlink_scale
TEST_PORTABLE_RESUME = tests/test_portable_resume
TEST_PORTABLE_RECONCILE = tests/test_portable_reconcile
TEST_PORTABLE_RECONCILE_SCALE = tests/test_portable_reconcile_scale
TEST_PORTABLE_RESTORE_PREFLIGHT = tests/test_portable_restore_preflight
TEST_PORTABLE_RESTORE_REPLAY = tests/test_portable_restore_replay
TEST_PORTABLE_RESTORE_ORCHESTRATE = tests/test_portable_restore_orchestrate
TEST_PORTABLE_RESTORE_INVARIANT = tests/test_portable_restore_invariant
# Each fuzz harness linked with tests/fuzz/replay_main.c in place of
# libFuzzer: an ordinary test binary that runs the harness's oracles over the
# generated seeds and the checked-in corpus.
FUZZ_REPLAY_SIDECAR_PARSE = tests/fuzz/replay_sidecar_parse
FUZZ_REPLAY_SIDECAR_LOAD = tests/fuzz/replay_sidecar_load
FUZZ_REPLAY_SIDECAR_ROUNDTRIP = tests/fuzz/replay_sidecar_roundtrip
FUZZ_REPLAY_NAMES = tests/fuzz/replay_names
FUZZ_REPLAY_REPAIR_SALVAGE = tests/fuzz/replay_repair_salvage
FUZZ_REPLAY_HOME_REWRITE = tests/fuzz/replay_home_rewrite
FUZZ_REPLAY_MANIFEST = tests/fuzz/replay_manifest
FUZZ_REPLAY_SOURCES = tests/fuzz/replay_main.c tests/fuzz/fuzz.h
FUZZ_JOURNAL_SEEDS = tests/fuzz/seeds_journal.c

$(TEST_DETECT): tests/test_detect.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

report_test.o: src/report.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c src/report.c -o $@

$(TEST_MANIFEST_SELECTION): tests/test_manifest_selection.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_NATIVE_SELECTION): tests/test_native_selection.c $(call with_hooks,fileops_test.o)
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_PORTABLE_SELECTION): tests/test_portable_selection.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_SELECTION): tests/test_selection.c $(LIB_OBJS) src/selection.h
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_CONFIG): tests/test_config.c $(LIB_OBJS) src/config.h
	$(CC) $(CFLAGS) -Wl,--wrap=read -Wl,--wrap=__read_chk -Wl,--wrap=waitpid -o $@ $(filter %.c %.o,$^)

$(TEST_REPORT): tests/test_report.c $(call with_hooks,report_test.o)
	$(CC) $(CFLAGS) -Wl,--wrap=readdir -o $@ $(filter %.c %.o,$^)

$(TEST_PATHJOIN): tests/test_pathjoin.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_FD_LIMIT): tests/test_fd_limit.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

utils_test.o: src/utils.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DUSER_CONTEXT_TEST_HOOKS -c src/utils.c -o $@

$(TEST_CONFIRM): tests/test_confirm.c $(call with_hooks,utils_test.o)
	$(CC) $(CFLAGS) -DUSER_CONTEXT_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

packages_test.o: src/packages.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DPACKAGES_TEST_HOOKS -c src/packages.c -o $@

groups_test.o: src/groups.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DGROUPS_TEST_HOOKS -c src/groups.c -o $@

$(TEST_PACKAGES): tests/test_packages.c $(call with_hooks,packages_test.o groups_test.o)
	$(CC) $(CFLAGS) -DPACKAGES_TEST_HOOKS -DGROUPS_TEST_HOOKS -Wl,--wrap=malloc -o $@ $(filter %.c %.o,$^)

$(TEST_XDG): tests/test_xdg.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_GET_DIR_SIZE): tests/test_get_dir_size.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_PORTABLE_HASHSET): tests/test_portable_hashset.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_RUN_COMMAND): tests/test_run_command.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -Wl,--wrap=read -o $@ $(filter %.c %.o,$^)

$(TEST_SPECIAL_FILES): tests/test_special_files.c $(call with_hooks,fileops_test.o)
	$(CC) $(CFLAGS) -DFILEOPS_TEST_HOOKS -DBACKUP_TEST_HOOKS -Wl,--wrap=readlink -o $@ $(filter %.c %.o,$^)

$(TEST_FSPROBE): tests/test_fsprobe.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_MANIFEST): tests/test_manifest.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -Wl,--wrap=strdup -o $@ $(filter %.c %.o,$^)

$(TEST_ENCODING): tests/test_encoding.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

portable_name_test.o: src/portable_name.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DPORTABLE_NAME_TEST_HOOKS -c src/portable_name.c -o $@

portable_restore_shared_test.o: src/portable_restore_shared.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DPORTABLE_RESTORE_ADDRESS_TEST_HOOKS -DPORTABLE_NAME_TEST_HOOKS -c src/portable_restore_shared.c -o $@

$(TEST_PORTABLE_NAME): tests/test_portable_name.c $(call with_hooks,portable_name_test.o)
	$(CC) $(CFLAGS) -DPORTABLE_NAME_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

container_test.o: src/container.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DCONTAINER_TEST_HOOKS -c src/container.c -o $@

$(TEST_CONTAINER): tests/test_container.c $(call with_hooks,container_test.o)
	$(CC) $(CFLAGS) -DCONTAINER_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_SELFCOPY): tests/test_selfcopy.c $(LIB_OBJS) $(TARGET)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

console_test.o: src/console.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DCONSOLE_TEST_HOOKS -c src/console.c -o $@

$(TEST_CONSOLE): tests/test_console.c $(call with_hooks,console_test.o)
	$(CC) $(CFLAGS) -DCONSOLE_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_SUBID): tests/test_subid.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_PODMAN_STATE): tests/test_podman_state.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_RESTORE_NATIVE): tests/test_restore_native.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_RESTORE_SYNC): tests/test_restore_sync.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -Wl,--wrap=syncfs -o $@ $(filter %.c %.o,$^)

fileops_test.o: src/fileops.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DFILEOPS_TEST_HOOKS -DBACKUP_TEST_HOOKS -DNATIVE_VISITED_TEST_HOOKS -c src/fileops.c -o $@

$(TEST_RESTORE_SOURCE_READ): tests/test_restore_source_read.c $(call with_hooks,fileops_test.o)
	$(CC) $(CFLAGS) -DFILEOPS_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

backup_test.o: src/backup.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DBACKUP_TEST_HOOKS -c src/backup.c -o $@

restore_test.o: src/restore.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DRESTORE_TEST_HOOKS -c src/restore.c -o $@

writer_apps_test.o: src/writer_apps.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DWRITER_APPS_TEST_HOOKS -c src/writer_apps.c -o $@

backup_plan_test.o: src/backup_plan.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DBACKUP_PLAN_TEST_HOOKS -c src/backup_plan.c -o $@

$(TEST_BACKUP_SOURCE_READ): tests/test_backup_source_read.c $(call with_hooks,backup_test.o fileops_test.o)
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

dconf_restore_test.o: src/dconf_restore.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DDCONF_RESTORE_TEST_HOOKS -c src/dconf_restore.c -o $@

$(TEST_LIVE_STATE): tests/test_live_state.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

# The CLI without the root requirement for backup and restore (D62), so the
# integration suite can drive both commands as an ordinary user.
main_unprivileged.o: main.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DMIGR_ALLOW_UNPRIVILEGED -c src/main.c -o $@

$(TEST_MIGR_UNPRIVILEGED): main_unprivileged.o $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_VERIFY): tests/test_verify.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_REPAIR): tests/test_repair.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_SOURCE_SNAPSHOT): tests/test_source_snapshot.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_DCONF_RESTORE): tests/test_dconf_restore.c $(call with_hooks,dconf_restore_test.o)
	$(CC) $(CFLAGS) -DDCONF_RESTORE_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_VSCODE_CAPTURE): tests/test_vscode_capture.c $(call with_hooks,backup_test.o fileops_test.o)
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -DFILEOPS_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_BACKUP_SYNC): tests/test_backup_sync.c $(call with_hooks,fileops_test.o portable_test.o portable_reconcile_test.o)
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -Wl,--wrap=syncfs -Wl,--wrap=read -o $@ $(filter %.c %.o,$^)

$(TEST_RESTORE_DISPATCH): tests/test_restore_dispatch.c $(call with_hooks,restore_test.o portable_restore_replay_test.o backup_test.o packages_test.o groups_test.o writer_apps_test.o)
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -DRESTORE_TEST_HOOKS -DPACKAGES_TEST_HOOKS -DGROUPS_TEST_HOOKS -DPORTABLE_RESTORE_REPLAY_TEST_HOOKS -DWRITER_APPS_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

# The hook build relabels nothing unless a test sets its relabel hook, so this
# test does not depend on the build host's SELinux or on restorecon.
$(TEST_RESTORE_ATIME): tests/test_restore_atime.c $(call with_hooks,restore_test.o)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_BACKUP_PLAN): tests/test_backup_plan.c $(call with_hooks,backup_test.o backup_plan_test.o fileops_test.o writer_apps_test.o)
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -DBACKUP_PLAN_TEST_HOOKS -DWRITER_APPS_TEST_HOOKS -Wl,--wrap=write -o $@ $(filter %.c %.o,$^)

$(TEST_METADATA_CONTRACT): tests/test_metadata_contract.c $(call with_hooks,metadata_xattr_test.o)
	$(CC) $(CFLAGS) -DMETADATA_XATTR_TEST_HOOKS -Wl,--wrap=flistxattr -o $@ $(filter %.c %.o,$^)

$(TEST_METADATA_SNAPSHOTS): tests/test_metadata_snapshots.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_SIDECAR): tests/test_sidecar.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_SIDECAR_STATE): tests/test_sidecar_state.c $(call with_hooks,sidecar_test.o)
	$(CC) $(CFLAGS) -DSIDECAR_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

sidecar_state_test.o: src/sidecar_state.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DSIDECAR_STATE_TEST_HOOKS -c src/sidecar_state.c -o $@

sidecar_state_map_test.o: src/sidecar_state_map.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DSIDECAR_STATE_TEST_HOOKS -c src/sidecar_state_map.c -o $@

$(TEST_SIDECAR_SCALE): tests/test_sidecar_scale.c $(call with_hooks,sidecar_state_test.o sidecar_state_map_test.o)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_PORTABLE_CAPTURE): tests/test_portable_capture.c $(call with_hooks,portable_prescan_test.o portable_name_test.o)
	$(CC) $(CFLAGS) -DPORTABLE_PRESCAN_TEST_HOOKS -DPORTABLE_NAME_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

portable_test.o: src/portable.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -c src/portable.c -o $@

portable_reconcile_test.o: src/portable_reconcile.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -c src/portable_reconcile.c -o $@

portable_prescan_test.o: src/portable_prescan.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DPORTABLE_PRESCAN_TEST_HOOKS -DPORTABLE_NAME_TEST_HOOKS -c src/portable_prescan.c -o $@

$(TEST_PORTABLE_CAPTURE_SCALE): tests/test_portable_capture_scale.c $(call with_hooks,portable_test.o portable_reconcile_test.o)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(TEST_PORTABLE_PREPARE): tests/test_portable_prepare.c $(call with_hooks,portable_test.o portable_reconcile_test.o sidecar_test.o sidecar_state_test.o sidecar_state_map_test.o)
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -DSIDECAR_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_NATIVE_RECONCILE_SCALE): tests/test_native_reconcile_scale.c $(call with_hooks,fileops_test.o)
	$(CC) $(CFLAGS) -DNATIVE_VISITED_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_NATIVE_HARDLINK_SCALE): tests/test_native_hardlink_scale.c $(call with_hooks,fileops_test.o)
	$(CC) $(CFLAGS) -DNATIVE_VISITED_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_PORTABLE_COLLISION_SCALE): tests/test_portable_collision_scale.c $(call with_hooks,portable_test.o portable_reconcile_test.o)
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_PORTABLE_HARDLINK_SCALE): tests/test_portable_hardlink_scale.c $(call with_hooks,portable_test.o portable_reconcile_test.o sidecar_state_test.o sidecar_state_map_test.o)
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

sidecar_test.o: src/sidecar.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DSIDECAR_TEST_HOOKS -c src/sidecar.c -o $@

$(TEST_PORTABLE_RESUME): tests/test_portable_resume.c $(call with_hooks,portable_test.o portable_reconcile_test.o sidecar_test.o sidecar_state_test.o sidecar_state_map_test.o)
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -DSIDECAR_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_PORTABLE_RECONCILE): tests/test_portable_reconcile.c $(call with_hooks,portable_test.o portable_reconcile_test.o)
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_PORTABLE_RECONCILE_SCALE): tests/test_portable_reconcile_scale.c $(call with_hooks,portable_test.o portable_reconcile_test.o sidecar_state_test.o sidecar_state_map_test.o)
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

portable_restore_replay_test.o: src/portable_restore_replay.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DPORTABLE_RESTORE_REPLAY_TEST_HOOKS -c src/portable_restore_replay.c -o $@

portable_restore_preflight_test.o: src/portable_restore_preflight.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DPORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS -c src/portable_restore_preflight.c -o $@

metadata_test.o: src/metadata.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DMETADATA_TEST_HOOKS -c src/metadata.c -o $@

metadata_xattr_test.o: src/metadata_xattr.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DMETADATA_XATTR_TEST_HOOKS -c src/metadata_xattr.c -o $@

$(TEST_PORTABLE_RESTORE_PREFLIGHT): tests/test_portable_restore_preflight.c $(call with_hooks,portable_restore_replay_test.o portable_restore_preflight_test.o metadata_test.o)
	$(CC) $(CFLAGS) -DMETADATA_TEST_HOOKS -DPORTABLE_RESTORE_PREFLIGHT_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_PORTABLE_RESTORE_REPLAY): tests/test_portable_restore_replay.c $(call with_hooks,portable_restore_replay_test.o)
	$(CC) $(CFLAGS) -DPORTABLE_RESTORE_REPLAY_TEST_HOOKS -Wl,--wrap=syncfs -o $@ $(filter %.c %.o,$^)

$(TEST_PORTABLE_RESTORE_ORCHESTRATE): tests/test_portable_restore_orchestrate.c $(call with_hooks,portable_restore_replay_test.o metadata_test.o backup_test.o)
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -DMETADATA_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(TEST_PORTABLE_RESTORE_INVARIANT): tests/test_portable_restore_invariant.c $(call with_hooks,portable_restore_replay_test.o portable_restore_shared_test.o portable_name_test.o)
	$(CC) $(CFLAGS) -DPORTABLE_RESTORE_ADDRESS_TEST_HOOKS -DPORTABLE_NAME_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(FUZZ_REPLAY_SIDECAR_PARSE): tests/fuzz/fuzz_sidecar_parse.c $(FUZZ_JOURNAL_SEEDS) $(FUZZ_REPLAY_SOURCES) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

# The state layer's hook build counts the claim map's rehash work.
$(FUZZ_REPLAY_SIDECAR_LOAD): tests/fuzz/fuzz_sidecar_load.c $(FUZZ_JOURNAL_SEEDS) $(FUZZ_REPLAY_SOURCES) $(call with_hooks,sidecar_state_test.o sidecar_state_map_test.o)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(FUZZ_REPLAY_SIDECAR_ROUNDTRIP): tests/fuzz/fuzz_sidecar_roundtrip.c tests/fuzz/seeds_roundtrip.c $(FUZZ_REPLAY_SOURCES) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

$(FUZZ_REPLAY_NAMES): tests/fuzz/fuzz_names.c tests/fuzz/seeds_names.c $(FUZZ_REPLAY_SOURCES) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

repair_test.o: src/repair.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DREPAIR_TEST_HOOKS -c src/repair.c -o $@

$(FUZZ_REPLAY_REPAIR_SALVAGE): tests/fuzz/fuzz_repair_salvage.c $(FUZZ_JOURNAL_SEEDS) $(FUZZ_REPLAY_SOURCES) $(call with_hooks,repair_test.o)
	$(CC) $(CFLAGS) -DREPAIR_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

home_rewrite_test.o: src/home_rewrite.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DHOME_REWRITE_TEST_HOOKS -c src/home_rewrite.c -o $@

# The hook build counts the positions the prefix search examines.
$(FUZZ_REPLAY_HOME_REWRITE): tests/fuzz/fuzz_home_rewrite.c tests/fuzz/seeds_home_rewrite.c $(FUZZ_REPLAY_SOURCES) $(call with_hooks,home_rewrite_test.o)
	$(CC) $(CFLAGS) -DHOME_REWRITE_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(FUZZ_REPLAY_MANIFEST): tests/fuzz/fuzz_manifest.c tests/fuzz/seeds_manifest.c $(FUZZ_REPLAY_SOURCES) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.c %.o,$^)

test: $(TEST_NATIVE_SELECTION) $(TEST_MANIFEST_SELECTION) $(TEST_PORTABLE_SELECTION) $(TEST_SELECTION) $(TEST_CONFIG) $(TARGET) $(TEST_DETECT) $(TEST_REPORT) $(TEST_PATHJOIN) $(TEST_FD_LIMIT) $(TEST_CONFIRM) $(TEST_PACKAGES) $(TEST_XDG) $(TEST_GET_DIR_SIZE) $(TEST_RUN_COMMAND) $(TEST_SPECIAL_FILES) $(TEST_FSPROBE) $(TEST_MANIFEST) $(TEST_ENCODING) $(TEST_PORTABLE_NAME) $(TEST_CONTAINER) $(TEST_SELFCOPY) $(TEST_CONSOLE) $(TEST_SUBID) $(TEST_PODMAN_STATE) $(TEST_RESTORE_NATIVE) $(TEST_RESTORE_SYNC) $(TEST_RESTORE_SOURCE_READ) $(TEST_BACKUP_SOURCE_READ) $(TEST_VSCODE_CAPTURE) $(TEST_DCONF_RESTORE) $(TEST_LIVE_STATE) $(TEST_VERIFY) $(TEST_REPAIR) $(TEST_SOURCE_SNAPSHOT) $(TEST_MIGR_UNPRIVILEGED) $(TEST_BACKUP_SYNC) $(TEST_RESTORE_DISPATCH) $(TEST_RESTORE_ATIME) $(TEST_BACKUP_PLAN) $(TEST_METADATA_CONTRACT) $(TEST_METADATA_SNAPSHOTS) $(TEST_SIDECAR) $(TEST_SIDECAR_STATE) $(TEST_SIDECAR_SCALE) $(TEST_PORTABLE_HASHSET) $(TEST_PORTABLE_CAPTURE) $(TEST_PORTABLE_CAPTURE_SCALE) $(TEST_PORTABLE_PREPARE) $(TEST_NATIVE_RECONCILE_SCALE) $(TEST_NATIVE_HARDLINK_SCALE) $(TEST_PORTABLE_COLLISION_SCALE) $(TEST_PORTABLE_HARDLINK_SCALE) $(TEST_PORTABLE_RESUME) $(TEST_PORTABLE_RECONCILE) $(TEST_PORTABLE_RECONCILE_SCALE) $(TEST_PORTABLE_RESTORE_PREFLIGHT) $(TEST_PORTABLE_RESTORE_REPLAY) $(TEST_PORTABLE_RESTORE_ORCHESTRATE) $(TEST_PORTABLE_RESTORE_INVARIANT) $(FUZZ_REPLAY_SIDECAR_PARSE) $(FUZZ_REPLAY_SIDECAR_LOAD) $(FUZZ_REPLAY_SIDECAR_ROUNDTRIP) $(FUZZ_REPLAY_NAMES) $(FUZZ_REPLAY_REPAIR_SALVAGE) $(FUZZ_REPLAY_HOME_REWRITE) $(FUZZ_REPLAY_MANIFEST)
	./$(TEST_DETECT)
	./$(TEST_MANIFEST_SELECTION)
	./$(TEST_NATIVE_SELECTION)
	./$(TEST_PORTABLE_SELECTION)
	./$(TEST_SELECTION)
	./$(TEST_CONFIG)
	./$(TEST_REPORT)
	./$(TEST_PATHJOIN)
	./$(TEST_FD_LIMIT)
	./$(TEST_CONFIRM)
	./$(TEST_PACKAGES)
	./$(TEST_XDG)
	./$(TEST_GET_DIR_SIZE)
	./$(TEST_RUN_COMMAND)
	./$(TEST_SPECIAL_FILES)
	./$(TEST_FSPROBE)
	./$(TEST_MANIFEST)
	./$(TEST_ENCODING)
	./$(TEST_PORTABLE_NAME)
	./$(TEST_CONTAINER)
	./$(TEST_SELFCOPY)
	./$(TEST_CONSOLE)
	./$(TEST_SUBID)
	./$(TEST_PODMAN_STATE)
	./$(TEST_RESTORE_NATIVE)
	./$(TEST_RESTORE_SYNC)
	./$(TEST_RESTORE_SOURCE_READ)
	./$(TEST_BACKUP_SOURCE_READ)
	./$(TEST_VSCODE_CAPTURE)
	./$(TEST_DCONF_RESTORE)
	./$(TEST_LIVE_STATE)
	./$(TEST_VERIFY)
	./$(TEST_REPAIR)
	./$(TEST_SOURCE_SNAPSHOT)
	./$(TEST_BACKUP_SYNC)
	./$(TEST_RESTORE_DISPATCH)
	./$(TEST_RESTORE_ATIME)
	./$(TEST_METADATA_CONTRACT)
	./$(TEST_METADATA_SNAPSHOTS)
	./$(TEST_SIDECAR)
	./$(TEST_SIDECAR_STATE)
	./$(TEST_SIDECAR_SCALE)
	./$(TEST_PORTABLE_HASHSET)
	./$(TEST_PORTABLE_CAPTURE)
	./$(TEST_PORTABLE_CAPTURE_SCALE)
	./$(TEST_PORTABLE_PREPARE)
	./$(TEST_NATIVE_RECONCILE_SCALE)
	./$(TEST_NATIVE_HARDLINK_SCALE)
	./$(TEST_PORTABLE_COLLISION_SCALE)
	./$(TEST_PORTABLE_HARDLINK_SCALE)
	./$(TEST_PORTABLE_RESUME)
	./$(TEST_PORTABLE_RECONCILE)
	./$(TEST_PORTABLE_RECONCILE_SCALE)
	./$(TEST_PORTABLE_RESTORE_PREFLIGHT)
	./$(TEST_PORTABLE_RESTORE_REPLAY)
	./$(TEST_PORTABLE_RESTORE_ORCHESTRATE)
	./$(TEST_PORTABLE_RESTORE_INVARIANT)
	./$(FUZZ_REPLAY_SIDECAR_PARSE)
	./$(FUZZ_REPLAY_SIDECAR_LOAD)
	./$(FUZZ_REPLAY_SIDECAR_ROUNDTRIP)
	./$(FUZZ_REPLAY_NAMES)
	./$(FUZZ_REPLAY_REPAIR_SALVAGE)
	./$(FUZZ_REPLAY_HOME_REWRITE)
	./$(FUZZ_REPLAY_MANIFEST)
# This one drives backup() end to end, so a successful --critical run forks the
# distribution's real package listing command. Give it the same stubs test.sh
# uses; only test.sh's own Phase 5 is about that command's real output. Each
# recipe line runs in its own shell, so this never reaches the line below.
	PATH="$(CURDIR)/tests/stubs:$$PATH" ./$(TEST_BACKUP_PLAN)
	cd tests && bash test.sh

# The host Phase B gate: rebuild and run the complete functional suite with
# warnings treated as errors under GCC and, when installed, Clang. The default
# CFLAGS remain unchanged; this target cleans its temporary flag-specific build.
check-strict:
	@set -e; \
	trap '$(MAKE) clean >/dev/null' EXIT; \
	$(MAKE) clean; \
	$(MAKE) CC=gcc CFLAGS="$(CHECK_STRICT_FLAGS)" test; \
	if command -v clang >/dev/null 2>&1; then \
		$(MAKE) clean; \
		$(MAKE) CC=clang CFLAGS="$(CHECK_STRICT_FLAGS)" test; \
	else \
		echo "check-strict: clang not found; GCC-only strict check."; \
	fi

# The host Phase B sanitizer gate: rebuild every object, including test-hook
# variants, and run the full suite with AddressSanitizer and UBSan. Leak
# detection and halt-on-error are inherited by the integration test as well.
check-sanitize:
	@set -e; \
	trap '$(MAKE) clean >/dev/null' EXIT; \
	$(MAKE) clean; \
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1 \
	$(MAKE) CFLAGS="$(CHECK_SANITIZE_FLAGS)" test

# The host Phase B Valgrind gate runs VALGRIND_TESTS with strict compilation.
# Its deliberate exclusions are documented with the list above. Valgrind
# reports go to one file per process, shown when a binary fails: written to
# stderr, they would mix into the output that tests capture from children.
# Children installed on the system (sh, dnf, flatpak) are not traced, and the
# package tools are the stubs `make test` gives test_backup_plan.
check-valgrind:
	@set -e; \
	logs=$$(mktemp -d); \
	trap 'rm -rf "$$logs"; $(MAKE) clean >/dev/null' EXIT; \
	$(MAKE) clean; \
	$(MAKE) CFLAGS="$(CHECK_STRICT_FLAGS)" $(VALGRIND_TESTS); \
	failed=; \
	for binary in $(VALGRIND_TESTS); do \
		echo "==> valgrind ./$$binary"; \
		rm -f "$$logs"/*; \
		PATH="$(CURDIR)/tests/stubs:$$PATH" valgrind --error-exitcode=1 --trace-children=yes --trace-children-skip='/usr/*,/bin/*,/sbin/*' --leak-check=full --track-origins=yes --log-file="$$logs/%p.log" ./$$binary || { cat "$$logs"/*; failed="$$failed $$binary"; }; \
	done; \
	if [ -n "$$failed" ]; then echo "check-valgrind failed:$$failed"; exit 1; fi

# The host Phase B static-analysis gate: GCC analyzes every source file,
# discarding the object. -fsyntax-only would stop before the analyzer runs.
# Tests are intentionally outside this target's scope.
check-analyze:
	@set -e; \
	for source in $(ANALYZER_SRCS); do \
		echo "==> gcc -fanalyzer $$source"; \
		$(ANALYZER_CC) $(ANALYZER_FLAGS) -c -o /dev/null "$$source"; \
	done

# Run the complete host gate in the roadmap order. Each prerequisite target
# fails immediately, so a green result means every individual gate was run.
check:
	$(MAKE) test
	$(MAKE) check-strict
	$(MAKE) check-sanitize
	$(MAKE) check-valgrind
	$(MAKE) check-analyze

# Discovery: libFuzzer runs one harness open-ended and nondeterministically,
# so it is run by hand, never by make check, and needs clang and compiler-rt:
#   make fuzz [FUZZ_TARGET=sidecar_parse|sidecar_load|sidecar_roundtrip|names|repair_salvage|home_rewrite|manifest] [FUZZ_TIME=seconds]
# Its objects are built with the sanitizers into FUZZ_OBJ_DIR, apart from the
# GCC objects here. A run starts from the generated seeds and the checked-in
# corpus, and keeps the corpus it grows and any crash, leak, or timeout input
# in FUZZ_OUT_DIR/<target>; FUZZ_ARGS passes more libFuzzer options. The RSS
# limit sits above the journal layer's 1 GiB allocation budget plus the
# sanitizers' overhead. make fuzz-repro ART=<file> runs one input through the
# fuzzer build; the replay binary, tests/fuzz/replay_<target> <file>, runs it
# through the GCC build. A finding is minimized (libFuzzer's -minimize_crash=1)
# and checked in under tests/fuzz/corpus/<target>/, named for the outcome it
# must have once fixed; real backups' journals never become inputs. A target
# reads the dictionary named FUZZ_DICT_<target>, else the journal's.
FUZZ_CC = clang
FUZZ_TARGET = sidecar_parse
FUZZ_TIME = 300
FUZZ_ARGS =
FUZZ_OBJ_DIR = fuzz-obj
FUZZ_OUT_DIR = fuzz-out
FUZZ_FLAGS = -g -O1 -Wall -Wextra -I src -pthread -fsanitize=address,undefined -fno-omit-frame-pointer
FUZZ_BINARY = $(FUZZ_OBJ_DIR)/fuzz_$(FUZZ_TARGET)
FUZZ_DICT_names = tests/fuzz/names.dict
FUZZ_DICT_home_rewrite = tests/fuzz/home_rewrite.dict
FUZZ_DICT_manifest = tests/fuzz/manifest.dict
FUZZ_DICT = $(or $(FUZZ_DICT_$(FUZZ_TARGET)),tests/fuzz/sidecar.dict)

$(FUZZ_OBJ_DIR)/%.o: %.c
	@mkdir -p $(FUZZ_OBJ_DIR)
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer-no-link -c $< -o $@

$(FUZZ_OBJ_DIR)/sidecar_state_test.o: src/sidecar_state.c
	@mkdir -p $(FUZZ_OBJ_DIR)
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer-no-link -DSIDECAR_STATE_TEST_HOOKS -c $< -o $@

$(FUZZ_OBJ_DIR)/sidecar_state_map_test.o: src/sidecar_state_map.c
	@mkdir -p $(FUZZ_OBJ_DIR)
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer-no-link -DSIDECAR_STATE_TEST_HOOKS -c $< -o $@

$(FUZZ_OBJ_DIR)/repair_test.o: src/repair.c
	@mkdir -p $(FUZZ_OBJ_DIR)
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer-no-link -DREPAIR_TEST_HOOKS -c $< -o $@

$(FUZZ_OBJ_DIR)/home_rewrite_test.o: src/home_rewrite.c
	@mkdir -p $(FUZZ_OBJ_DIR)
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer-no-link -DHOME_REWRITE_TEST_HOOKS -c $< -o $@

$(FUZZ_OBJ_DIR)/fuzz_sidecar_parse: tests/fuzz/fuzz_sidecar_parse.c tests/fuzz/fuzz.h $(addprefix $(FUZZ_OBJ_DIR)/,$(LIB_OBJS))
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^)

$(FUZZ_OBJ_DIR)/fuzz_sidecar_load: tests/fuzz/fuzz_sidecar_load.c tests/fuzz/fuzz.h $(addprefix $(FUZZ_OBJ_DIR)/,$(call with_hooks,sidecar_state_test.o sidecar_state_map_test.o))
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^)

$(FUZZ_OBJ_DIR)/fuzz_sidecar_roundtrip: tests/fuzz/fuzz_sidecar_roundtrip.c tests/fuzz/fuzz.h $(addprefix $(FUZZ_OBJ_DIR)/,$(LIB_OBJS))
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^)

$(FUZZ_OBJ_DIR)/fuzz_names: tests/fuzz/fuzz_names.c tests/fuzz/fuzz.h $(addprefix $(FUZZ_OBJ_DIR)/,$(LIB_OBJS))
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^)

$(FUZZ_OBJ_DIR)/fuzz_repair_salvage: tests/fuzz/fuzz_repair_salvage.c tests/fuzz/fuzz.h $(addprefix $(FUZZ_OBJ_DIR)/,$(call with_hooks,repair_test.o))
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer -DREPAIR_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(FUZZ_OBJ_DIR)/fuzz_home_rewrite: tests/fuzz/fuzz_home_rewrite.c tests/fuzz/fuzz.h $(addprefix $(FUZZ_OBJ_DIR)/,$(call with_hooks,home_rewrite_test.o))
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer -DHOME_REWRITE_TEST_HOOKS -o $@ $(filter %.c %.o,$^)

$(FUZZ_OBJ_DIR)/fuzz_manifest: tests/fuzz/fuzz_manifest.c tests/fuzz/fuzz.h $(addprefix $(FUZZ_OBJ_DIR)/,$(LIB_OBJS))
	$(FUZZ_CC) $(FUZZ_FLAGS) -fsanitize=fuzzer -o $@ $(filter %.c %.o,$^)

fuzz-toolchain:
	@printf 'int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { (void)d; (void)n; return 0; }\n' | \
		$(FUZZ_CC) -fsanitize=fuzzer,address,undefined -x c - -o /dev/null 2>/dev/null || \
		{ echo "fuzz: $(FUZZ_CC) cannot build a libFuzzer binary; discovery needs clang and compiler-rt."; exit 1; }

fuzz: fuzz-toolchain
	$(MAKE) $(FUZZ_BINARY) tests/fuzz/replay_$(FUZZ_TARGET)
	mkdir -p $(FUZZ_OUT_DIR)/$(FUZZ_TARGET)/corpus
	./tests/fuzz/replay_$(FUZZ_TARGET) --write-seeds $(FUZZ_OUT_DIR)/$(FUZZ_TARGET)/corpus
	./$(FUZZ_BINARY) -dict=$(FUZZ_DICT) -max_total_time=$(FUZZ_TIME) -timeout=10 -rss_limit_mb=2560 \
		-artifact_prefix=$(FUZZ_OUT_DIR)/$(FUZZ_TARGET)/ $(FUZZ_ARGS) \
		$(FUZZ_OUT_DIR)/$(FUZZ_TARGET)/corpus $(wildcard tests/fuzz/corpus/$(FUZZ_TARGET))

fuzz-repro: fuzz-toolchain
	@test -n "$(ART)" || { echo "fuzz-repro: name the input with ART=<file>."; exit 1; }
	$(MAKE) $(FUZZ_BINARY)
	./$(FUZZ_BINARY) $(ART)

# Fails each system call migr makes in a backup, an update, a restore, a
# verify, and a repair, one call site per run, and checks what each failure
# leaves behind (see tests/fault_sweep.sh). As root, with mkfs.vfat, it
# covers portable backups too. The preloaded shim is built apart from
# CFLAGS, which may carry coverage or sanitizer flags meant for migr.
FAULT_SHIM = tests/fault/fault_inject.so

$(FAULT_SHIM): tests/fault/fault_inject.c
	$(CC) -O2 -Wall -Wextra -fPIC -shared -o $@ $< -ldl

fault-sweep: $(TEST_MIGR_UNPRIVILEGED) $(FAULT_SHIM)
	./tests/fault_sweep.sh $(TEST_MIGR_UNPRIVILEGED) $(FAULT_SHIM)

# Packages install into a staging root: make install DESTDIR=... PREFIX=/usr.
# The static binary sits beside migr, where --include-self looks for it; it
# has its own target because building it needs a static C library.
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

install: $(TARGET)
	install -Dm755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

install-static: $(STATIC_TARGET)
	install -Dm755 $(STATIC_TARGET) $(DESTDIR)$(BINDIR)/$(STATIC_TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET) $(DESTDIR)$(BINDIR)/$(STATIC_TARGET)

clean:
	rm -rf $(FUZZ_OBJ_DIR)
	rm -f ./*.o ./*.d $(TARGET) $(STATIC_TARGET) $(FAULT_SHIM) $(TEST_NATIVE_SELECTION) $(TEST_MANIFEST_SELECTION) $(TEST_PORTABLE_SELECTION) $(TEST_SELECTION) $(TEST_CONFIG) $(TEST_DETECT) $(TEST_REPORT) $(TEST_PATHJOIN) $(TEST_FD_LIMIT) $(TEST_CONFIRM) $(TEST_PACKAGES) $(TEST_XDG) $(TEST_GET_DIR_SIZE) $(TEST_RUN_COMMAND) $(TEST_SPECIAL_FILES) $(TEST_FSPROBE) $(TEST_MANIFEST) $(TEST_ENCODING) $(TEST_PORTABLE_NAME) $(TEST_CONTAINER) $(TEST_SELFCOPY) $(TEST_CONSOLE) $(TEST_SUBID) $(TEST_PODMAN_STATE) $(TEST_RESTORE_NATIVE) $(TEST_RESTORE_SYNC) $(TEST_RESTORE_SOURCE_READ) $(TEST_BACKUP_SOURCE_READ) $(TEST_VSCODE_CAPTURE) $(TEST_DCONF_RESTORE) $(TEST_LIVE_STATE) $(TEST_VERIFY) $(TEST_REPAIR) $(TEST_SOURCE_SNAPSHOT) $(TEST_MIGR_UNPRIVILEGED) $(TEST_BACKUP_SYNC) $(TEST_RESTORE_DISPATCH) $(TEST_RESTORE_ATIME) $(TEST_BACKUP_PLAN) $(TEST_METADATA_CONTRACT) $(TEST_METADATA_SNAPSHOTS) $(TEST_SIDECAR) $(TEST_SIDECAR_STATE) $(TEST_SIDECAR_SCALE) $(TEST_PORTABLE_HASHSET) $(TEST_PORTABLE_CAPTURE) $(TEST_PORTABLE_CAPTURE_SCALE) $(TEST_PORTABLE_PREPARE) $(TEST_NATIVE_RECONCILE_SCALE) $(TEST_NATIVE_HARDLINK_SCALE) $(TEST_PORTABLE_COLLISION_SCALE) $(TEST_PORTABLE_HARDLINK_SCALE) $(TEST_PORTABLE_RESUME) $(TEST_PORTABLE_RECONCILE) $(TEST_PORTABLE_RECONCILE_SCALE) $(TEST_PORTABLE_RESTORE_PREFLIGHT) $(TEST_PORTABLE_RESTORE_REPLAY) $(TEST_PORTABLE_RESTORE_ORCHESTRATE) $(TEST_PORTABLE_RESTORE_INVARIANT) $(FUZZ_REPLAY_SIDECAR_PARSE) $(FUZZ_REPLAY_SIDECAR_LOAD) $(FUZZ_REPLAY_SIDECAR_ROUNDTRIP) $(FUZZ_REPLAY_NAMES) $(FUZZ_REPLAY_REPAIR_SALVAGE) $(FUZZ_REPLAY_HOME_REWRITE) $(FUZZ_REPLAY_MANIFEST)

.PHONY: clean test check-strict check-sanitize check-valgrind check-analyze check install install-static uninstall fuzz fuzz-repro fuzz-toolchain fault-sweep

-include $(wildcard *.d)

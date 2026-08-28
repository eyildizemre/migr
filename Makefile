CC = gcc
CFLAGS = -Wall -Wextra -g -I src

CHECK_STRICT_FLAGS = $(CFLAGS) -Wpedantic -Werror
CHECK_SANITIZE_FLAGS = $(CHECK_STRICT_FLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer
ANALYZER_CC = gcc
ANALYZER_FLAGS = $(CFLAGS) -Wpedantic -Werror -fanalyzer

# Valgrind covers the stateful sidecar/portable/restore paths and file-operation
# walkers. Most scale tests, simple parsers, and the package-manager integration
# are excluded because they add little memory coverage at disproportionate cost;
# the native visited-set and native hardlink inode-map scale tests are included
# because their large allocation volumes are memory-safety subjects in their
# respective decisions.
VALGRIND_TESTS = \
	tests/test_report \
	tests/test_sidecar \
	tests/test_sidecar_state \
	tests/test_portable_capture \
	tests/test_portable_prepare \
	tests/test_native_reconcile_scale \
	tests/test_native_hardlink_scale \
	tests/test_portable_resume \
	tests/test_portable_reconcile \
	tests/test_portable_restore_preflight \
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
	tests/test_metadata_contract

TARGET = migr
VPATH = src
SRCS = main.c detect.c report.c backup.c backup_plan.c packages.c restore.c utils.c fileops.c fsprobe.c xdg.c manifest.c encoding.c container.c metadata.c metadata_xattr.c portable_hashset.c portable_prescan.c portable_fsops.c portable.c portable_restore.c sidecar.c sidecar_state.c sidecar_state_map.c hash.c
OBJS = $(SRCS:.c=.o)
ANALYZER_SRCS = $(wildcard src/*.c)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

TEST_DETECT = tests/test_detect
TEST_REPORT = tests/test_report
TEST_PATHJOIN = tests/test_pathjoin
TEST_FD_LIMIT = tests/test_fd_limit
TEST_SPECIAL_FILES = tests/test_special_files
TEST_FSPROBE = tests/test_fsprobe
TEST_MANIFEST = tests/test_manifest
TEST_ENCODING = tests/test_encoding
TEST_CONTAINER = tests/test_container
TEST_RESTORE_NATIVE = tests/test_restore_native
TEST_RESTORE_SYNC = tests/test_restore_sync
TEST_RESTORE_SOURCE_READ = tests/test_restore_source_read
TEST_BACKUP_SOURCE_READ = tests/test_backup_source_read
TEST_BACKUP_SYNC = tests/test_backup_sync
TEST_RESTORE_DISPATCH = tests/test_restore_dispatch
TEST_RESTORE_ATIME = tests/test_restore_atime
TEST_BACKUP_PLAN = tests/test_backup_plan
TEST_METADATA_CONTRACT = tests/test_metadata_contract
TEST_SIDECAR = tests/test_sidecar
TEST_SIDECAR_STATE = tests/test_sidecar_state
TEST_SIDECAR_SCALE = tests/test_sidecar_scale
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

$(TEST_DETECT): tests/test_detect.c detect.o
	$(CC) $(CFLAGS) -o $@ tests/test_detect.c detect.o

report_test.o: src/report.c src/report.h src/backup_plan.h src/detect.h src/fileops.h src/utils.h
	$(CC) $(CFLAGS) -c src/report.c -o $@

$(TEST_REPORT): tests/test_report.c report_test.o $(filter-out main.o report.o,$(OBJS))
	$(CC) $(CFLAGS) -Wl,--wrap=readdir -o $@ tests/test_report.c report_test.o $(filter-out main.o report.o,$(OBJS))

$(TEST_PATHJOIN): tests/test_pathjoin.c utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_pathjoin.c utils.o

$(TEST_FD_LIMIT): tests/test_fd_limit.c utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_fd_limit.c utils.o

$(TEST_SPECIAL_FILES): tests/test_special_files.c fileops_test.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o
	$(CC) $(CFLAGS) -DFILEOPS_TEST_HOOKS -DBACKUP_TEST_HOOKS -o $@ tests/test_special_files.c fileops_test.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o

$(TEST_FSPROBE): tests/test_fsprobe.c fsprobe.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_fsprobe.c fsprobe.o utils.o

$(TEST_MANIFEST): tests/test_manifest.c manifest.o encoding.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_manifest.c manifest.o encoding.o utils.o

$(TEST_ENCODING): tests/test_encoding.c encoding.o
	$(CC) $(CFLAGS) -o $@ tests/test_encoding.c encoding.o

$(TEST_CONTAINER): tests/test_container.c container.o manifest.o encoding.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_container.c container.o manifest.o encoding.o utils.o

$(TEST_RESTORE_NATIVE): tests/test_restore_native.c fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_restore_native.c fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o

$(TEST_RESTORE_SYNC): tests/test_restore_sync.c fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o
	$(CC) $(CFLAGS) -Wl,--wrap=syncfs -o $@ tests/test_restore_sync.c fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o

fileops_test.o: src/fileops.c src/fileops.h src/metadata.h src/portable.h
	$(CC) $(CFLAGS) -DFILEOPS_TEST_HOOKS -DBACKUP_TEST_HOOKS -DNATIVE_VISITED_TEST_HOOKS -c src/fileops.c -o $@

$(TEST_RESTORE_SOURCE_READ): tests/test_restore_source_read.c fileops_test.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o
	$(CC) $(CFLAGS) -DFILEOPS_TEST_HOOKS -o $@ tests/test_restore_source_read.c fileops_test.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o

backup_test.o: src/backup.c src/backup.h src/backup_plan.h src/fileops.h src/metadata.h
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -c src/backup.c -o $@

$(TEST_BACKUP_SOURCE_READ): tests/test_backup_source_read.c backup_test.o backup_plan.o container.o fileops_test.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o fsprobe.o manifest.o encoding.o packages.o utils.o xdg.o detect.o
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -o $@ tests/test_backup_source_read.c backup_test.o backup_plan.o container.o fileops_test.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o fsprobe.o manifest.o encoding.o packages.o utils.o xdg.o detect.o

$(TEST_BACKUP_SYNC): tests/test_backup_sync.c fileops_test.o portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o metadata.o metadata_xattr.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -Wl,--wrap=syncfs -Wl,--wrap=read -o $@ tests/test_backup_sync.c fileops_test.o portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o metadata.o metadata_xattr.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o

$(TEST_RESTORE_DISPATCH): tests/test_restore_dispatch.c restore.o portable_restore.o fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o fsprobe.o manifest.o encoding.o container.o utils.o xdg.o detect.o backup_test.o backup_plan.o packages.o
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -o $@ tests/test_restore_dispatch.c restore.o portable_restore.o fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o fsprobe.o manifest.o encoding.o container.o utils.o xdg.o detect.o backup_test.o backup_plan.o packages.o

$(TEST_RESTORE_ATIME): tests/test_restore_atime.c restore.o portable_restore.o fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o fsprobe.o manifest.o encoding.o container.o utils.o xdg.o detect.o backup.o backup_plan.o packages.o
	$(CC) $(CFLAGS) -o $@ tests/test_restore_atime.c restore.o portable_restore.o fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o fsprobe.o manifest.o encoding.o container.o utils.o xdg.o detect.o backup.o backup_plan.o packages.o

$(TEST_BACKUP_PLAN): tests/test_backup_plan.c backup_test.o backup_plan.o container.o fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o fsprobe.o manifest.o encoding.o packages.o utils.o xdg.o detect.o
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -o $@ tests/test_backup_plan.c backup_test.o backup_plan.o container.o fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o fsprobe.o manifest.o encoding.o packages.o utils.o xdg.o detect.o

$(TEST_METADATA_CONTRACT): tests/test_metadata_contract.c fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_metadata_contract.c fileops.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o

$(TEST_SIDECAR): tests/test_sidecar.c sidecar.o
	$(CC) $(CFLAGS) -o $@ tests/test_sidecar.c sidecar.o

$(TEST_SIDECAR_STATE): tests/test_sidecar_state.c sidecar.o sidecar_state.o sidecar_state_map.o hash.o
	$(CC) $(CFLAGS) -o $@ tests/test_sidecar_state.c sidecar.o sidecar_state.o sidecar_state_map.o hash.o

sidecar_state_test.o: src/sidecar_state.c src/sidecar.h src/sidecar_state_internal.h
	$(CC) $(CFLAGS) -DSIDECAR_STATE_TEST_HOOKS -c src/sidecar_state.c -o $@

sidecar_state_map_test.o: src/sidecar_state_map.c src/sidecar_state_internal.h src/sidecar.h
	$(CC) $(CFLAGS) -DSIDECAR_STATE_TEST_HOOKS -c src/sidecar_state_map.c -o $@

$(TEST_SIDECAR_SCALE): tests/test_sidecar_scale.c sidecar.o sidecar_state_test.o sidecar_state_map_test.o hash.o
	$(CC) $(CFLAGS) -o $@ tests/test_sidecar_scale.c sidecar.o sidecar_state_test.o sidecar_state_map_test.o hash.o

$(TEST_PORTABLE_CAPTURE): tests/test_portable_capture.c portable.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_portable_capture.c portable.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o

portable_test.o: src/portable.c src/portable.h src/sidecar.h src/portable_hashset_internal.h src/portable_prescan_internal.h src/portable_fsops_internal.h
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -c src/portable.c -o $@

$(TEST_PORTABLE_CAPTURE_SCALE): tests/test_portable_capture_scale.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_portable_capture_scale.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o

$(TEST_PORTABLE_PREPARE): tests/test_portable_prepare.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar_test.o sidecar_state_test.o sidecar_state_map_test.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -DSIDECAR_TEST_HOOKS -o $@ tests/test_portable_prepare.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar_test.o sidecar_state_test.o sidecar_state_map_test.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o

$(TEST_NATIVE_RECONCILE_SCALE): tests/test_native_reconcile_scale.c fileops_test.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o
	$(CC) $(CFLAGS) -DNATIVE_VISITED_TEST_HOOKS -o $@ tests/test_native_reconcile_scale.c fileops_test.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o

$(TEST_NATIVE_HARDLINK_SCALE): tests/test_native_hardlink_scale.c fileops_test.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o
	$(CC) $(CFLAGS) -DNATIVE_VISITED_TEST_HOOKS -o $@ tests/test_native_hardlink_scale.c fileops_test.o metadata.o metadata_xattr.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o utils.o

$(TEST_PORTABLE_COLLISION_SCALE): tests/test_portable_collision_scale.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -o $@ tests/test_portable_collision_scale.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o

$(TEST_PORTABLE_HARDLINK_SCALE): tests/test_portable_hardlink_scale.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state_test.o sidecar_state_map_test.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -o $@ tests/test_portable_hardlink_scale.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state_test.o sidecar_state_map_test.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o

sidecar_test.o: src/sidecar.c src/sidecar.h
	$(CC) $(CFLAGS) -DSIDECAR_TEST_HOOKS -c src/sidecar.c -o $@

$(TEST_PORTABLE_RESUME): tests/test_portable_resume.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar_test.o sidecar_state_test.o sidecar_state_map_test.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -DSIDECAR_TEST_HOOKS -o $@ tests/test_portable_resume.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar_test.o sidecar_state_test.o sidecar_state_map_test.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o

$(TEST_PORTABLE_RECONCILE): tests/test_portable_reconcile.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -o $@ tests/test_portable_reconcile.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o

$(TEST_PORTABLE_RECONCILE_SCALE): tests/test_portable_reconcile_scale.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state_test.o sidecar_state_map_test.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -o $@ tests/test_portable_reconcile_scale.c portable_test.o portable_fsops.o portable_prescan.o portable_hashset.o fileops.o sidecar.o sidecar_state_test.o sidecar_state_map_test.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o

portable_restore_test.o: src/portable_restore.c src/portable_restore.h src/backup.h src/fsprobe.h src/sidecar.h src/manifest.h src/metadata.h src/encoding.h src/xdg.h
	$(CC) $(CFLAGS) -c src/portable_restore.c -o $@

metadata_test.o: src/metadata.c src/metadata.h src/fileops.h
	$(CC) $(CFLAGS) -DMETADATA_TEST_HOOKS -c src/metadata.c -o $@

$(TEST_PORTABLE_RESTORE_PREFLIGHT): tests/test_portable_restore_preflight.c portable_restore_test.o fsprobe.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata_test.o metadata_xattr.o utils.o xdg.o backup.o backup_plan.o container.o fileops.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o packages.o detect.o
	$(CC) $(CFLAGS) -DMETADATA_TEST_HOOKS -o $@ tests/test_portable_restore_preflight.c portable_restore_test.o fsprobe.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata_test.o metadata_xattr.o utils.o xdg.o backup.o backup_plan.o container.o fileops.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o packages.o detect.o

$(TEST_PORTABLE_RESTORE_REPLAY): tests/test_portable_restore_replay.c portable_restore_test.o fsprobe.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o xdg.o backup.o backup_plan.o container.o fileops.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o packages.o detect.o
	$(CC) $(CFLAGS) -Wl,--wrap=syncfs -o $@ tests/test_portable_restore_replay.c portable_restore_test.o fsprobe.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o xdg.o backup.o backup_plan.o container.o fileops.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o packages.o detect.o

$(TEST_PORTABLE_RESTORE_ORCHESTRATE): tests/test_portable_restore_orchestrate.c portable_restore_test.o fsprobe.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata_test.o metadata_xattr.o utils.o xdg.o backup_test.o backup_plan.o container.o fileops.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o packages.o detect.o
	$(CC) $(CFLAGS) -DBACKUP_TEST_HOOKS -DMETADATA_TEST_HOOKS -o $@ tests/test_portable_restore_orchestrate.c portable_restore_test.o fsprobe.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata_test.o metadata_xattr.o utils.o xdg.o backup_test.o backup_plan.o container.o fileops.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o packages.o detect.o

$(TEST_PORTABLE_RESTORE_INVARIANT): tests/test_portable_restore_invariant.c portable_restore_test.o fsprobe.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o xdg.o backup.o backup_plan.o container.o fileops.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o packages.o detect.o
	$(CC) $(CFLAGS) -o $@ tests/test_portable_restore_invariant.c portable_restore_test.o fsprobe.o sidecar.o sidecar_state.o sidecar_state_map.o hash.o manifest.o encoding.o metadata.o metadata_xattr.o utils.o xdg.o backup.o backup_plan.o container.o fileops.o portable.o portable_fsops.o portable_prescan.o portable_hashset.o packages.o detect.o

test: $(TARGET) $(TEST_DETECT) $(TEST_REPORT) $(TEST_PATHJOIN) $(TEST_FD_LIMIT) $(TEST_SPECIAL_FILES) $(TEST_FSPROBE) $(TEST_MANIFEST) $(TEST_ENCODING) $(TEST_CONTAINER) $(TEST_RESTORE_NATIVE) $(TEST_RESTORE_SYNC) $(TEST_RESTORE_SOURCE_READ) $(TEST_BACKUP_SOURCE_READ) $(TEST_BACKUP_SYNC) $(TEST_RESTORE_DISPATCH) $(TEST_RESTORE_ATIME) $(TEST_BACKUP_PLAN) $(TEST_METADATA_CONTRACT) $(TEST_SIDECAR) $(TEST_SIDECAR_STATE) $(TEST_SIDECAR_SCALE) $(TEST_PORTABLE_CAPTURE) $(TEST_PORTABLE_CAPTURE_SCALE) $(TEST_PORTABLE_PREPARE) $(TEST_NATIVE_RECONCILE_SCALE) $(TEST_NATIVE_HARDLINK_SCALE) $(TEST_PORTABLE_COLLISION_SCALE) $(TEST_PORTABLE_HARDLINK_SCALE) $(TEST_PORTABLE_RESUME) $(TEST_PORTABLE_RECONCILE) $(TEST_PORTABLE_RECONCILE_SCALE) $(TEST_PORTABLE_RESTORE_PREFLIGHT) $(TEST_PORTABLE_RESTORE_REPLAY) $(TEST_PORTABLE_RESTORE_ORCHESTRATE) $(TEST_PORTABLE_RESTORE_INVARIANT)
	./$(TEST_DETECT)
	./$(TEST_REPORT)
	./$(TEST_PATHJOIN)
	./$(TEST_FD_LIMIT)
	./$(TEST_SPECIAL_FILES)
	./$(TEST_FSPROBE)
	./$(TEST_MANIFEST)
	./$(TEST_ENCODING)
	./$(TEST_CONTAINER)
	./$(TEST_RESTORE_NATIVE)
	./$(TEST_RESTORE_SYNC)
	./$(TEST_RESTORE_SOURCE_READ)
	./$(TEST_BACKUP_SOURCE_READ)
	./$(TEST_BACKUP_SYNC)
	./$(TEST_RESTORE_DISPATCH)
	./$(TEST_RESTORE_ATIME)
	./$(TEST_METADATA_CONTRACT)
	./$(TEST_SIDECAR)
	./$(TEST_SIDECAR_STATE)
	./$(TEST_SIDECAR_SCALE)
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

# The host Phase B Valgrind gate runs the memory-sensitive core only. The scale
# binaries, simple parsers, and package-manager integration are excluded: they
# are covered by make test and make the leak gate disproportionately slow.
check-valgrind:
	@set -e; \
	trap '$(MAKE) clean >/dev/null' EXIT; \
	$(MAKE) clean; \
	$(MAKE) CFLAGS="$(CHECK_STRICT_FLAGS)" $(VALGRIND_TESTS); \
	for binary in $(VALGRIND_TESTS); do \
		echo "==> valgrind ./$$binary"; \
		valgrind --error-exitcode=1 --trace-children=yes --leak-check=full --track-origins=yes ./$$binary; \
	done

# The host Phase B static-analysis gate: GCC analyzes every source file
# compile-only. Tests are intentionally outside this target's scope.
check-analyze:
	@set -e; \
	for source in $(ANALYZER_SRCS); do \
		echo "==> gcc -fanalyzer $$source"; \
		$(ANALYZER_CC) $(ANALYZER_FLAGS) -fsyntax-only "$$source"; \
	done

# Run the complete host gate in the roadmap order. Each prerequisite target
# fails immediately, so a green result means every individual gate was run.
check:
	$(MAKE) test
	$(MAKE) check-strict
	$(MAKE) check-sanitize
	$(MAKE) check-valgrind
	$(MAKE) check-analyze

clean:
	rm -f $(OBJS) report_test.o backup_test.o fileops_test.o sidecar.o sidecar_test.o sidecar_state.o sidecar_state_map.o sidecar_state_test.o sidecar_state_map_test.o portable.o portable_fsops.o portable_test.o portable_hashset.o portable_prescan.o portable_restore_test.o metadata_test.o metadata_xattr.o $(TARGET) $(TEST_DETECT) $(TEST_REPORT) $(TEST_PATHJOIN) $(TEST_FD_LIMIT) $(TEST_SPECIAL_FILES) $(TEST_FSPROBE) $(TEST_MANIFEST) $(TEST_ENCODING) $(TEST_CONTAINER) $(TEST_RESTORE_NATIVE) $(TEST_RESTORE_SYNC) $(TEST_RESTORE_SOURCE_READ) $(TEST_BACKUP_SOURCE_READ) $(TEST_BACKUP_SYNC) $(TEST_RESTORE_DISPATCH) $(TEST_RESTORE_ATIME) $(TEST_BACKUP_PLAN) $(TEST_METADATA_CONTRACT) $(TEST_SIDECAR) $(TEST_SIDECAR_STATE) $(TEST_SIDECAR_SCALE) $(TEST_PORTABLE_CAPTURE) $(TEST_PORTABLE_CAPTURE_SCALE) $(TEST_PORTABLE_PREPARE) $(TEST_NATIVE_RECONCILE_SCALE) $(TEST_NATIVE_HARDLINK_SCALE) $(TEST_PORTABLE_COLLISION_SCALE) $(TEST_PORTABLE_HARDLINK_SCALE) $(TEST_PORTABLE_RESUME) $(TEST_PORTABLE_RECONCILE) $(TEST_PORTABLE_RECONCILE_SCALE) $(TEST_PORTABLE_RESTORE_PREFLIGHT) $(TEST_PORTABLE_RESTORE_REPLAY) $(TEST_PORTABLE_RESTORE_ORCHESTRATE) $(TEST_PORTABLE_RESTORE_INVARIANT)

.PHONY: clean test check-strict check-sanitize check-valgrind check-analyze check

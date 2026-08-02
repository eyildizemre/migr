CC = gcc
CFLAGS = -Wall -Wextra -g -I src

TARGET = migr
VPATH = src
SRCS = main.c detect.c report.c backup.c backup_plan.c packages.c restore.c utils.c fileops.c fsprobe.c xdg.c manifest.c container.c metadata.c
OBJS = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

TEST_DETECT = tests/test_detect
TEST_PATHJOIN = tests/test_pathjoin
TEST_SPECIAL_FILES = tests/test_special_files
TEST_FSPROBE = tests/test_fsprobe
TEST_MANIFEST = tests/test_manifest
TEST_CONTAINER = tests/test_container
TEST_RESTORE_NATIVE = tests/test_restore_native
TEST_RESTORE_DISPATCH = tests/test_restore_dispatch
TEST_BACKUP_PLAN = tests/test_backup_plan
TEST_METADATA_CONTRACT = tests/test_metadata_contract
TEST_SIDECAR = tests/test_sidecar
TEST_SIDECAR_STATE = tests/test_sidecar_state
TEST_SIDECAR_SCALE = tests/test_sidecar_scale
TEST_PORTABLE_CAPTURE = tests/test_portable_capture
TEST_PORTABLE_CAPTURE_SCALE = tests/test_portable_capture_scale
TEST_PORTABLE_RESUME = tests/test_portable_resume
TEST_PORTABLE_RECONCILE = tests/test_portable_reconcile
TEST_PORTABLE_RECONCILE_SCALE = tests/test_portable_reconcile_scale
TEST_PORTABLE_RESTORE_PREFLIGHT = tests/test_portable_restore_preflight
TEST_PORTABLE_RESTORE_REPLAY = tests/test_portable_restore_replay

$(TEST_DETECT): tests/test_detect.c detect.o
	$(CC) $(CFLAGS) -o $@ tests/test_detect.c detect.o

$(TEST_PATHJOIN): tests/test_pathjoin.c utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_pathjoin.c utils.o

$(TEST_SPECIAL_FILES): tests/test_special_files.c fileops.o metadata.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_special_files.c fileops.o metadata.o utils.o

$(TEST_FSPROBE): tests/test_fsprobe.c fsprobe.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_fsprobe.c fsprobe.o utils.o

$(TEST_MANIFEST): tests/test_manifest.c manifest.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_manifest.c manifest.o utils.o

$(TEST_CONTAINER): tests/test_container.c container.o manifest.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_container.c container.o manifest.o utils.o

$(TEST_RESTORE_NATIVE): tests/test_restore_native.c fileops.o metadata.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_restore_native.c fileops.o metadata.o utils.o

$(TEST_RESTORE_DISPATCH): tests/test_restore_dispatch.c restore.o fileops.o metadata.o fsprobe.o manifest.o container.o utils.o xdg.o detect.o
	$(CC) $(CFLAGS) -o $@ tests/test_restore_dispatch.c restore.o fileops.o metadata.o fsprobe.o manifest.o container.o utils.o xdg.o detect.o

$(TEST_BACKUP_PLAN): tests/test_backup_plan.c backup.o backup_plan.o container.o fileops.o metadata.o fsprobe.o manifest.o packages.o utils.o xdg.o detect.o
	$(CC) $(CFLAGS) -o $@ tests/test_backup_plan.c backup.o backup_plan.o container.o fileops.o metadata.o fsprobe.o manifest.o packages.o utils.o xdg.o detect.o

$(TEST_METADATA_CONTRACT): tests/test_metadata_contract.c fileops.o metadata.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_metadata_contract.c fileops.o metadata.o utils.o

$(TEST_SIDECAR): tests/test_sidecar.c sidecar.o
	$(CC) $(CFLAGS) -o $@ tests/test_sidecar.c sidecar.o

$(TEST_SIDECAR_STATE): tests/test_sidecar_state.c sidecar.o sidecar_state.o
	$(CC) $(CFLAGS) -o $@ tests/test_sidecar_state.c sidecar.o sidecar_state.o

sidecar_state_test.o: src/sidecar_state.c src/sidecar.h
	$(CC) $(CFLAGS) -DSIDECAR_STATE_TEST_HOOKS -c src/sidecar_state.c -o $@

$(TEST_SIDECAR_SCALE): tests/test_sidecar_scale.c sidecar.o sidecar_state_test.o
	$(CC) $(CFLAGS) -o $@ tests/test_sidecar_scale.c sidecar.o sidecar_state_test.o

$(TEST_PORTABLE_CAPTURE): tests/test_portable_capture.c portable.o sidecar.o sidecar_state.o manifest.o metadata.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_portable_capture.c portable.o sidecar.o sidecar_state.o manifest.o metadata.o utils.o

portable_test.o: src/portable.c src/portable.h src/sidecar.h
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -c src/portable.c -o $@

$(TEST_PORTABLE_CAPTURE_SCALE): tests/test_portable_capture_scale.c portable_test.o sidecar.o sidecar_state.o manifest.o metadata.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_portable_capture_scale.c portable_test.o sidecar.o sidecar_state.o manifest.o metadata.o utils.o

sidecar_test.o: src/sidecar.c src/sidecar.h
	$(CC) $(CFLAGS) -DSIDECAR_TEST_HOOKS -c src/sidecar.c -o $@

$(TEST_PORTABLE_RESUME): tests/test_portable_resume.c portable_test.o sidecar_test.o sidecar_state_test.o manifest.o metadata.o utils.o
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -DSIDECAR_TEST_HOOKS -o $@ tests/test_portable_resume.c portable_test.o sidecar_test.o sidecar_state_test.o manifest.o metadata.o utils.o

$(TEST_PORTABLE_RECONCILE): tests/test_portable_reconcile.c portable_test.o sidecar.o sidecar_state.o manifest.o metadata.o utils.o
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -o $@ tests/test_portable_reconcile.c portable_test.o sidecar.o sidecar_state.o manifest.o metadata.o utils.o

$(TEST_PORTABLE_RECONCILE_SCALE): tests/test_portable_reconcile_scale.c portable_test.o sidecar.o sidecar_state_test.o manifest.o metadata.o utils.o
	$(CC) $(CFLAGS) -DPORTABLE_CAPTURE_TEST_HOOKS -o $@ tests/test_portable_reconcile_scale.c portable_test.o sidecar.o sidecar_state_test.o manifest.o metadata.o utils.o

portable_restore_test.o: src/portable_restore.c src/portable_restore.h src/sidecar.h src/manifest.h src/metadata.h
	$(CC) $(CFLAGS) -c src/portable_restore.c -o $@

metadata_test.o: src/metadata.c src/metadata.h src/fileops.h
	$(CC) $(CFLAGS) -DMETADATA_TEST_HOOKS -c src/metadata.c -o $@

$(TEST_PORTABLE_RESTORE_PREFLIGHT): tests/test_portable_restore_preflight.c portable_restore_test.o sidecar.o sidecar_state.o manifest.o metadata_test.o utils.o
	$(CC) $(CFLAGS) -DMETADATA_TEST_HOOKS -o $@ tests/test_portable_restore_preflight.c portable_restore_test.o sidecar.o sidecar_state.o manifest.o metadata_test.o utils.o

$(TEST_PORTABLE_RESTORE_REPLAY): tests/test_portable_restore_replay.c portable_restore_test.o sidecar.o sidecar_state.o manifest.o metadata.o utils.o
	$(CC) $(CFLAGS) -o $@ tests/test_portable_restore_replay.c portable_restore_test.o sidecar.o sidecar_state.o manifest.o metadata.o utils.o

test: $(TARGET) $(TEST_DETECT) $(TEST_PATHJOIN) $(TEST_SPECIAL_FILES) $(TEST_FSPROBE) $(TEST_MANIFEST) $(TEST_CONTAINER) $(TEST_RESTORE_NATIVE) $(TEST_RESTORE_DISPATCH) $(TEST_BACKUP_PLAN) $(TEST_METADATA_CONTRACT) $(TEST_SIDECAR) $(TEST_SIDECAR_STATE) $(TEST_SIDECAR_SCALE) $(TEST_PORTABLE_CAPTURE) $(TEST_PORTABLE_CAPTURE_SCALE) $(TEST_PORTABLE_RESUME) $(TEST_PORTABLE_RECONCILE) $(TEST_PORTABLE_RECONCILE_SCALE) $(TEST_PORTABLE_RESTORE_PREFLIGHT) $(TEST_PORTABLE_RESTORE_REPLAY)
	./$(TEST_DETECT)
	./$(TEST_PATHJOIN)
	./$(TEST_SPECIAL_FILES)
	./$(TEST_FSPROBE)
	./$(TEST_MANIFEST)
	./$(TEST_CONTAINER)
	./$(TEST_RESTORE_NATIVE)
	./$(TEST_RESTORE_DISPATCH)
	./$(TEST_METADATA_CONTRACT)
	./$(TEST_SIDECAR)
	./$(TEST_SIDECAR_STATE)
	./$(TEST_SIDECAR_SCALE)
	./$(TEST_PORTABLE_CAPTURE)
	./$(TEST_PORTABLE_CAPTURE_SCALE)
	./$(TEST_PORTABLE_RESUME)
	./$(TEST_PORTABLE_RECONCILE)
	./$(TEST_PORTABLE_RECONCILE_SCALE)
	./$(TEST_PORTABLE_RESTORE_PREFLIGHT)
	./$(TEST_PORTABLE_RESTORE_REPLAY)
# This one drives backup() end to end, so a successful --critical run forks the
# distribution's real package listing command. Give it the same stubs test.sh
# uses; only test.sh's own Phase 5 is about that command's real output. Each
# recipe line runs in its own shell, so this never reaches the line below.
	PATH="$(CURDIR)/tests/stubs:$$PATH" ./$(TEST_BACKUP_PLAN)
	cd tests && bash test.sh

clean:
	rm -f $(OBJS) sidecar.o sidecar_test.o sidecar_state.o sidecar_state_test.o portable.o portable_test.o portable_restore_test.o metadata_test.o $(TARGET) $(TEST_DETECT) $(TEST_PATHJOIN) $(TEST_SPECIAL_FILES) $(TEST_FSPROBE) $(TEST_MANIFEST) $(TEST_CONTAINER) $(TEST_RESTORE_NATIVE) $(TEST_RESTORE_DISPATCH) $(TEST_BACKUP_PLAN) $(TEST_METADATA_CONTRACT) $(TEST_SIDECAR) $(TEST_SIDECAR_STATE) $(TEST_SIDECAR_SCALE) $(TEST_PORTABLE_CAPTURE) $(TEST_PORTABLE_CAPTURE_SCALE) $(TEST_PORTABLE_RESUME) $(TEST_PORTABLE_RECONCILE) $(TEST_PORTABLE_RECONCILE_SCALE) $(TEST_PORTABLE_RESTORE_PREFLIGHT) $(TEST_PORTABLE_RESTORE_REPLAY)

.PHONY: clean test

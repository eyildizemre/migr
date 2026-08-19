// Unit tests for fsprobe() and select_representation().
//
// select_representation is pure, so synthetic profiles drive the whole
// native/portable/refuse decision without touching a filesystem. fsprobe reads a real
// filesystem, so it cannot be pinned to a verdict here — the suite may run on ext4,
// btrfs, tmpfs, overlayfs, ... — the check is only that it returns a defined status,
// fills a well-formed profile, and leaves no residue. The "capable filesystem ->
// native, lossy -> portable" verdict is a known-filesystem integration test (btrfs/ext4
// vs real exFAT/NTFS in the VMs), where the filesystem is controlled — not in this
// portable unit binary.

#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fsprobe.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures = 0;

static void check(int cond, const char *label)
{
    if (cond)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

// A profile with every capability supported; individual tests then poke holes in it.
static FsCapabilityProfile all_supported(void)
{
    FsCapabilityProfile p;
    for (int i = 0; i < FS_CAP_COUNT; i++)
    {
        p.capabilities[i].status = FS_CAP_SUPPORTED;
        p.capabilities[i].errnum = 0;
    }
    return p;
}

static int directory_is_empty(const char *path)
{
    DIR *dir = opendir(path);
    if (dir == NULL)
        return 0;

    int empty = 1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
        {
            empty = 0;
            break;
        }
    }
    closedir(dir);
    return empty;
}

static void test_fsprobe_fd_is_anchored(char *root)
{
    printf(BLUE "::" NC " fsprobe: fd primitive stays on the opened directory after a path swap\n");

    FsCapabilityProfile profile;
    check(fsprobe_fd(-1, &profile) == -1,
          "fd-anchored probe rejects an invalid root fd");

    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(root_fd >= 0, "fixture: open the probe root before swapping its path");
    if (root_fd < 0)
        return;

    char saved[sizeof "/tmp/fsprobe_root_XXXXXX.saved"];
    if (snprintf(saved, sizeof(saved), "%s.saved", root) < 0 ||
        rename(root, saved) != 0)
    {
        check(0, "fixture: move the originally opened directory aside");
        close(root_fd);
        return;
    }

    int swapped_fd = open(root, O_CREAT | O_WRONLY | O_EXCL | O_CLOEXEC, 0600);
    check(swapped_fd >= 0, "fixture: replace the original path with a different object");

    int rc = fsprobe_fd(root_fd, &profile);
    check(rc == 0,
          "fd-anchored probe succeeds on the originally opened directory");
    check(fcntl(root_fd, F_GETFD) >= 0,
          "fd-anchored probe leaves the borrowed root fd open");
    check(directory_is_empty(saved),
          "all probe artifacts were created and removed under the opened directory");

    struct stat swapped_st;
    check(lstat(root, &swapped_st) == 0 && S_ISREG(swapped_st.st_mode),
          "the swapped-in path was not used as the probe anchor");

    if (swapped_fd >= 0)
        close(swapped_fd);
    check(unlink(root) == 0, "fixture: remove the swapped-in object");
    check(rmdir(saved) == 0, "fixture: remove the original probe root");
    close(root_fd);
    check(mkdir(root, 0700) == 0, "fixture: recreate the probe root for later checks");
}

int main(void)
{
    printf(BLUE "::" NC " fsprobe (unit)\n");

    CloneRepresentation repr;
    FsCapabilityProfile p;

    // --- select_representation: the full decision matrix (pure, no filesystem) ---
    p = all_supported();
    check(select_representation(&p, &repr) == 0 && repr == CLONE_NATIVE_TREE,
          "all supported -> native");

    p = all_supported();
    p.capabilities[FS_CAP_XATTR].status = FS_CAP_UNAVAILABLE;
    check(select_representation(&p, &repr) == 0 && repr == CLONE_PORTABLE_SIDECAR,
          "a missing capability -> portable");

    p = all_supported();
    p.capabilities[FS_CAP_CASE_SENSITIVE].status = FS_CAP_UNAVAILABLE;
    check(select_representation(&p, &repr) == 0 && repr == CLONE_PORTABLE_SIDECAR,
          "case-insensitive target -> portable, not native");

    p = all_supported();
    p.capabilities[FS_CAP_HARDLINK].status = FS_CAP_UNAVAILABLE;
    check(select_representation(&p, &repr) == 0 && repr == CLONE_PORTABLE_SIDECAR,
          "a destination that can't hardlink -> portable, not native");

    p = all_supported();
    p.capabilities[FS_CAP_MODE].status = FS_CAP_ERROR;
    check(select_representation(&p, &repr) == -1,
          "an operational error -> refusal");

    p = all_supported();
    p.capabilities[FS_CAP_FIFO].status = FS_CAP_UNAVAILABLE;
    p.capabilities[FS_CAP_MODE].status = FS_CAP_ERROR;
    check(select_representation(&p, &repr) == -1,
          "error outranks unavailable -> refusal");

    // A corrupt/unknown status must fail closed, never fall through to native.
    p = all_supported();
    p.capabilities[FS_CAP_MODE].status = (FsCapabilityStatus)999;
    check(select_representation(&p, &repr) == -1,
          "an unknown status -> refusal (fail closed, not native)");

    p = all_supported();
    p.capabilities[FS_CAP_HARDLINK].status = FS_CAP_UNSET;
    check(select_representation(&p, &repr) == -1,
          "an unset (never-probed) capability -> refusal, not native");

    // NULL arguments are refused, not dereferenced.
    p = all_supported();
    check(select_representation(NULL, &repr) == -1, "NULL profile -> refusal");
    check(select_representation(&p, NULL) == -1, "NULL out -> refusal");

    // A refused profile must leave *out untouched.
    p = all_supported();
    p.capabilities[FS_CAP_XATTR].status = FS_CAP_ERROR;
    repr = CLONE_PORTABLE_SIDECAR; // sentinel distinct from native
    check(select_representation(&p, &repr) == -1 && repr == CLONE_PORTABLE_SIDECAR,
          "a refused profile leaves *out unchanged");

    // --- fsprobe: runs coherently on the real filesystem and cleans up after itself ---
    char root[] = "/tmp/fsprobe_root_XXXXXX";
    if (mkdtemp(root) == NULL)
    {
        printf(RED "could not create a probe root" NC "\n");
        return 1;
    }

    FsCapabilityProfile real;
    int rc = fsprobe(root, &real);
    // The root exists and is writable, so the probe must run to completion — a -1 here
    // means the probe itself is broken, not that the destination is unusable.
    check(rc == 0, "fsprobe runs successfully on a usable root");

    if (rc == 0)
    {
        int well_formed = 1;
        for (int i = 0; i < FS_CAP_COUNT; i++)
        {
            FsCapabilityStatus s = real.capabilities[i].status;
            if (s != FS_CAP_SUPPORTED && s != FS_CAP_UNAVAILABLE && s != FS_CAP_ERROR)
                well_formed = 0;
        }
        check(well_formed, "every capability has a valid status");

        // Report the observed verdict — informational, since it depends on whatever
        // filesystem the suite happens to run on.
        if (select_representation(&real, &repr) == 0)
            printf("    (observed verdict: %s)\n",
                   repr == CLONE_NATIVE_TREE ? "native" : "portable");
        else
            printf("    (observed verdict: refuse)\n");
    }

    test_fsprobe_fd_is_anchored(root);

    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(root_fd >= 0, "timestamp probe root opens by fd");
    if (root_fd >= 0)
    {
        struct timespec original[2] = {
            { .tv_sec = 1700010101, .tv_nsec = 111111111 },
            { .tv_sec = 1700010202, .tv_nsec = 222222222 }
        };
        check(futimens(root_fd, original) == 0,
              "timestamp probe fixture times are set");
        struct stat before;
        check(fstat(root_fd, &before) == 0,
              "timestamp probe fixture times are readable");

        int nsec_exact = -1;
        int timestamp_rc = fsprobe_timestamps_fd(root_fd, &nsec_exact);
        check(timestamp_rc == 0 && (nsec_exact == 0 || nsec_exact == 1),
              "fd-anchored timestamp probe runs and reports nsec policy");

        struct stat after;
        int times_preserved = fstat(root_fd, &after) == 0 &&
                              after.st_atim.tv_sec == before.st_atim.tv_sec &&
                              after.st_mtim.tv_sec == before.st_mtim.tv_sec;
        if (timestamp_rc == 0 && nsec_exact)
            times_preserved = times_preserved &&
                              after.st_atim.tv_nsec == before.st_atim.tv_nsec &&
                              after.st_mtim.tv_nsec == before.st_mtim.tv_nsec;
        check(times_preserved,
              "fd-anchored timestamp probe restores anchor core times");
        check(fsprobe_timestamps_fd(-1, &nsec_exact) == -1,
              "timestamp probe rejects an invalid root fd");
        close(root_fd);
    }

    // No residue: the root must be readable and empty again (fsprobe removed its subdir),
    // and it must remove cleanly. A failed opendir is a test failure, not "empty".
    DIR *d = opendir(root);
    check(d != NULL, "probe root is readable after fsprobe");
    int empty = 1;
    if (d != NULL)
    {
        struct dirent *e;
        while ((e = readdir(d)) != NULL)
        {
            if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
                empty = 0;
        }
        closedir(d);
    }
    check(empty, "fsprobe leaves no residue in the destination");
    check(rmdir(root) == 0, "probe root removed cleanly");

    if (failures > 0)
    {
        printf(RED "%d fsprobe test(s) failed" NC "\n", failures);
        return 1;
    }
    return 0;
}

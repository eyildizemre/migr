#define _GNU_SOURCE
#include "dconf_restore.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fileops.h"
#include "home_rewrite.h"
#include "utils.h"

#define DCONF_DUMP_LIMIT_DEFAULT (8U * 1024U * 1024U)

static const char *dconf_runtime_root = "/run/user";
static size_t dconf_dump_limit = DCONF_DUMP_LIMIT_DEFAULT;

#ifdef DCONF_RESTORE_TEST_HOOKS
void dconf_restore_test_set_runtime_root(const char *path)
{
    dconf_runtime_root = path != NULL ? path : "/run/user";
}

void dconf_restore_test_set_dump_limit(size_t bytes)
{
    dconf_dump_limit = bytes != 0 ? bytes : DCONF_DUMP_LIMIT_DEFAULT;
}
#endif

typedef struct {
    int drop_identity;
    uid_t uid;
    gid_t gid;
    char home[PATH_MAX];
} DconfTarget;

// Under sudo the settings belong to the invoking user (D38); otherwise to the
// process's own user, whose environment already describes it.
static int dconf_target_resolve(DconfTarget *target)
{
    memset(target, 0, sizeof(*target));
    int sudo = sudo_invoker(&target->uid, &target->gid, target->home);
    if (sudo < 0)
        return -1;
    if (sudo)
    {
        target->drop_identity = target->uid != 0;
        return 0;
    }
    target->uid = geteuid();
    target->gid = getegid();
    return 0;
}

static int dconf_command_available(void)
{
    const char *path = getenv("PATH");
    if (path == NULL || path[0] == '\0')
        return 0;
    const char *cursor = path;
    while (*cursor != '\0')
    {
        const char *end = strchr(cursor, ':');
        size_t length = end != NULL ? (size_t)(end - cursor) : strlen(cursor);
        char candidate[PATH_MAX];
        int written = snprintf(candidate, sizeof(candidate), "%.*s/dconf",
                               (int)length, cursor);
        if (length != 0 && written > 0 && (size_t)written < sizeof(candidate) &&
            access(candidate, X_OK) == 0)
            return 1;
        if (end == NULL)
            break;
        cursor = end + 1;
    }
    return 0;
}

static int write_file_at(int dir_fd, const char *name, const void *data,
                         size_t length)
{
    int fd = openat(dir_fd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    if (fd < 0)
        return -1;
    if (write_all(fd, data, length) != 0)
    {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return close(fd);
}

static int copy_database_at(int database_fd, int dir_fd, const char *name)
{
    int fd = openat(dir_fd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    if (fd < 0)
        return -1;
    unsigned char buffer[65536];
    off_t offset = 0;
    int result = 0;
    for (;;)
    {
        ssize_t got = pread(database_fd, buffer, sizeof(buffer), offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
        {
            result = -1;
            break;
        }
        if (got == 0)
            break;
        if (write_all(fd, buffer, (size_t)got) != 0)
        {
            result = -1;
            break;
        }
        offset += got;
    }
    int saved = errno;
    if (close(fd) != 0 && result == 0)
        return -1;
    errno = saved;
    return result;
}

typedef struct {
    char path[PATH_MAX];
    int fd;
} DconfWorkDir;

static const char *const dconf_work_files[] = {
    "dconf/user", "profile", "keyfiles/user", "compiled"
};

static void dconf_work_dir_remove(DconfWorkDir *work)
{
    if (work->fd < 0)
        return;
    for (size_t index = 0;
         index < sizeof(dconf_work_files) / sizeof(dconf_work_files[0]);
         index++)
        (void)unlinkat(work->fd, dconf_work_files[index], 0);
    (void)unlinkat(work->fd, "dconf", AT_REMOVEDIR);
    (void)unlinkat(work->fd, "keyfiles", AT_REMOVEDIR);
    close(work->fd);
    work->fd = -1;
    (void)rmdir(work->path);
}

// A private directory holding a copy of the database as <dir>/dconf/user and
// a profile naming it, so `dconf dump` reads the backup rather than the
// user's live database. Owned by the target user when migr drops to it.
static int dconf_work_dir_create(DconfWorkDir *work, int database_fd,
                                 const DconfTarget *target)
{
    work->fd = -1;
    snprintf(work->path, sizeof(work->path), "/tmp/migr-dconf-XXXXXX");
    if (mkdtemp(work->path) == NULL)
        return -1;
    work->fd = open(work->path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                    O_CLOEXEC);
    if (work->fd < 0)
    {
        int saved = errno;
        (void)rmdir(work->path);
        errno = saved;
        return -1;
    }
    static const char profile[] = "user-db:user\n";
    if (mkdirat(work->fd, "dconf", 0700) != 0 ||
        copy_database_at(database_fd, work->fd, "dconf/user") != 0 ||
        write_file_at(work->fd, "profile", profile, sizeof(profile) - 1U) != 0)
        goto fail;
    if (target->drop_identity)
    {
        static const char *const owned[] = { "dconf/user", "dconf", "profile" };
        for (size_t index = 0; index < sizeof(owned) / sizeof(owned[0]);
             index++)
            if (fchownat(work->fd, owned[index], target->uid, target->gid,
                         AT_SYMLINK_NOFOLLOW) != 0)
                goto fail;
        if (fchown(work->fd, target->uid, target->gid) != 0)
            goto fail;
    }
    return 0;

fail:
    {
        int saved = errno;
        dconf_work_dir_remove(work);
        errno = saved;
    }
    return -1;
}

// Compiles settings, a dump, into a database in the work directory and puts
// it in place of the restored ~/.config/dconf/user (dconf compile reads the
// same key file format that dconf dump writes).
static int dconf_replace_database(const DconfWorkDir *work,
                                  const DconfTarget *target,
                                  const char *settings, int home_fd)
{
    char keyfiles[PATH_MAX], compiled[PATH_MAX];
    if (path_join(keyfiles, sizeof(keyfiles), work->path, "keyfiles") != 0 ||
        path_join(compiled, sizeof(compiled), work->path, "compiled") != 0 ||
        mkdirat(work->fd, "keyfiles", 0700) != 0 ||
        write_file_at(work->fd, "keyfiles/user", settings,
                      strlen(settings)) != 0)
        return -1;
    if (target->drop_identity &&
        (fchownat(work->fd, "keyfiles/user", target->uid, target->gid,
                  AT_SYMLINK_NOFOLLOW) != 0 ||
         fchownat(work->fd, "keyfiles", target->uid, target->gid,
                  AT_SYMLINK_NOFOLLOW) != 0))
        return -1;

    RunCommandOptions options = {
        .drop_identity = target->drop_identity,
        .uid = target->uid,
        .gid = target->gid,
        .home = target->drop_identity ? target->home : NULL
    };
    char output[256];
    char *const compile_argv[] = { "dconf", "compile", compiled, keyfiles,
                                   NULL };
    if (run_command_capture_with(compile_argv, output, sizeof(output),
                                 &options) != 0)
        return -1;
    int fd = openat(work->fd, "compiled", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int result = home_rewrite_replace_at(home_fd, ".config/dconf/user", fd);
    int saved = errno;
    close(fd);
    errno = saved;
    return result;
}

static size_t dconf_dump_key_count(const char *dump)
{
    size_t count = 0;
    for (const char *line = dump; line != NULL && *line != '\0';)
    {
        const char *end = strchr(line, '\n');
        size_t length = end != NULL ? (size_t)(end - line) : strlen(line);
        if (length != 0 && line[0] != '[' && memchr(line, '=', length) != NULL)
            count++;
        line = end != NULL ? end + 1 : NULL;
    }
    return count;
}

// Whether the target user has a session bus a dconf service could run on,
// and dconf to load into it; fills the runtime directory and bus paths.
static DconfRestoreStatus dconf_session_check(const DconfTarget *target,
                                              char runtime_dir[PATH_MAX],
                                              char bus_path[PATH_MAX])
{
    int runtime_length = snprintf(runtime_dir, PATH_MAX, "%s/%ju",
                                  dconf_runtime_root, (uintmax_t)target->uid);
    if (runtime_length < 0 || runtime_length >= PATH_MAX ||
        path_join(bus_path, PATH_MAX, runtime_dir, "bus") != 0)
        return DCONF_RESTORE_FAILED;
    struct stat bus_st;
    if (lstat(bus_path, &bus_st) != 0 || !S_ISSOCK(bus_st.st_mode))
        return DCONF_RESTORE_NO_SESSION;
    if (!dconf_command_available())
        return DCONF_RESTORE_UNAVAILABLE;
    return DCONF_RESTORE_APPLIED;
}

int dconf_restore_session_loads(void)
{
    DconfTarget target;
    char runtime_dir[PATH_MAX], bus_path[PATH_MAX];
    return dconf_target_resolve(&target) == 0 &&
           dconf_session_check(&target, runtime_dir, bus_path) ==
               DCONF_RESTORE_APPLIED;
}

int dconf_restore_session_running(void)
{
    DconfTarget target;
    char runtime_dir[PATH_MAX], bus_path[PATH_MAX];
    if (dconf_target_resolve(&target) != 0)
        return 0;
    DconfRestoreStatus status = dconf_session_check(&target, runtime_dir,
                                                    bus_path);
    return status == DCONF_RESTORE_APPLIED ||
           status == DCONF_RESTORE_UNAVAILABLE;
}

DconfRestoreStatus dconf_restore_apply(int database_fd, int home_fd,
                                       const HomeRewritePair *pairs,
                                       size_t pair_count,
                                       size_t *applied_keys)
{
    if (applied_keys != NULL)
        *applied_keys = 0;
    if (database_fd < 0)
        return DCONF_RESTORE_FAILED;

    DconfTarget target;
    if (dconf_target_resolve(&target) != 0)
        return DCONF_RESTORE_FAILED;

    char runtime_dir[PATH_MAX], bus_path[PATH_MAX];
    DconfRestoreStatus session = dconf_session_check(&target, runtime_dir,
                                                     bus_path);
    // Without a session the restored file is the result; only paths that
    // name the backup's home folder may need changing in it.
    if (session == DCONF_RESTORE_NO_SESSION &&
        (pair_count == 0 || !dconf_command_available()))
        return session;
    if (session == DCONF_RESTORE_UNAVAILABLE ||
        session == DCONF_RESTORE_FAILED)
        return session;
    int loads = session == DCONF_RESTORE_APPLIED;

    DconfRestoreStatus status = loads ? DCONF_RESTORE_FAILED
                                      : DCONF_RESTORE_HOME_NOT_REWRITTEN;
    DconfWorkDir work;
    if (dconf_work_dir_create(&work, database_fd, &target) != 0)
        return status;

    char *dump = malloc(dconf_dump_limit);
    char *rewritten = NULL;
    char profile_env[PATH_MAX + 32], config_env[PATH_MAX + 32];
    char bus_env[PATH_MAX + 64], runtime_env[PATH_MAX + 32];
    if (dump == NULL ||
        snprintf(profile_env, sizeof(profile_env), "DCONF_PROFILE=%s/profile",
                 work.path) >= (int)sizeof(profile_env) ||
        snprintf(config_env, sizeof(config_env), "XDG_CONFIG_HOME=%s",
                 work.path) >= (int)sizeof(config_env) ||
        snprintf(bus_env, sizeof(bus_env),
                 "DBUS_SESSION_BUS_ADDRESS=unix:path=%s", bus_path) >=
            (int)sizeof(bus_env) ||
        snprintf(runtime_env, sizeof(runtime_env), "XDG_RUNTIME_DIR=%s",
                 runtime_dir) >= (int)sizeof(runtime_env))
        goto done;

    // dconf keeps state in the runtime directory even to read; the invoker's
    // environment may name root's, which the user cannot write.
    const char *const dump_env[] = { profile_env, config_env, runtime_env,
                                     NULL };
    RunCommandOptions dump_options = {
        .drop_identity = target.drop_identity,
        .uid = target.uid,
        .gid = target.gid,
        .home = target.drop_identity ? target.home : NULL,
        .env = dump_env
    };
    char *const dump_argv[] = { "dconf", "dump", "/", NULL };
    if (run_command_capture_with(dump_argv, dump, dconf_dump_limit,
                                 &dump_options) != 0)
        goto done;
    size_t dump_length = strlen(dump);
    // A full buffer means the dump was cut short; loading a truncated dump
    // would apply an arbitrary subset.
    if (dump_length >= dconf_dump_limit - 1U)
        goto done;

    // Paths under the backup's home folder (a wallpaper, a last-used folder)
    // name this system's (D101).
    const char *settings = dump;
    if (pair_count != 0)
    {
        rewritten = home_rewrite_text(dump, pairs, pair_count);
        if (rewritten == NULL)
            goto done;
        settings = rewritten;
    }
    if (!loads)
    {
        if (strcmp(settings, dump) == 0 ||
            dconf_replace_database(&work, &target, settings, home_fd) == 0)
            status = DCONF_RESTORE_NO_SESSION;
        goto done;
    }

    size_t keys = dconf_dump_key_count(settings);
    if (keys == 0)
    {
        status = DCONF_RESTORE_APPLIED;
        goto done;
    }

    const char *const load_env[] = { bus_env, runtime_env, NULL };
    RunCommandOptions load_options = {
        .drop_identity = target.drop_identity,
        .uid = target.uid,
        .gid = target.gid,
        .home = target.drop_identity ? target.home : NULL,
        .env = load_env,
        .stdin_data = settings,
        .stdin_length = strlen(settings)
    };
    char load_output[256];
    char *const load_argv[] = { "dconf", "load", "/", NULL };
    if (run_command_capture_with(load_argv, load_output, sizeof(load_output),
                                 &load_options) != 0)
        goto done;
    if (applied_keys != NULL)
        *applied_keys = keys;
    status = DCONF_RESTORE_APPLIED;

done:
    free(rewritten);
    free(dump);
    dconf_work_dir_remove(&work);
    return status;
}

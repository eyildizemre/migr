// Fault injection for tests/fault_sweep.sh, loaded into migr with
// LD_PRELOAD. A call site is the call's name and the innermost frames of
// migr's own code that lead to it, so every caller of a shared helper is a
// site of its own.
//
//   MIGR_FAULT_LIST=FILE  appends each site to FILE the first time it runs
//   MIGR_FAULT=SITE       fails the first call at SITE, and appends SITE to
//                         MIGR_FAULT_HIT when that file is named
//
// Calls that write or create fail with ENOSPC, allocations with ENOMEM,
// the calls that start and wait for programs with an error of their own,
// the others with EIO. A call that can also fail for a reason migr tells
// apart is listed a second time as "SITE ERROR": a lookup of a path that
// is gone (ENOENT), a create where a name appeared (EEXIST), a read or
// write cut short by a signal (EINTR), an attribute removed after it was
// listed (ENODATA).

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <link.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define SITE_FRAMES 4
#define SEEN_SLOTS 65536U

static uintptr_t exe_start;
static uintptr_t exe_end;
static int list_fd = -1;
static char fault_line[256];
static const char *fault_site;
static int fault_error;
static const char *hit_path;
static int fault_fired;
static int exiting;
static int stop_at_exit_set;
static uint64_t seen[SEEN_SLOTS];
static __thread int inside;

static const struct
{
    int error;
    const char *name;
} other_errors[] = {
    {ENOENT, "ENOENT"},
    {EEXIST, "EEXIST"},
    {EINTR, "EINTR"},
    {ENODATA, "ENODATA"},
};

static const char *other_error_name(int error)
{
    for (size_t i = 0; i < sizeof(other_errors) / sizeof(other_errors[0]); i++)
        if (other_errors[i].error == error)
            return other_errors[i].name;
    return NULL;
}

static int find_exe(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    (void)data;
    // The executable is the first object listed.
    for (int i = 0; i < info->dlpi_phnum; i++)
    {
        const ElfW(Phdr) *header = &info->dlpi_phdr[i];
        if (header->p_type != PT_LOAD)
            continue;
        uintptr_t start = info->dlpi_addr + header->p_vaddr;
        if (exe_start == 0 || start < exe_start)
            exe_start = start;
        if (start + header->p_memsz > exe_end)
            exe_end = start + header->p_memsz;
    }
    return 1;
}

static void append_line(const char *path, int fd, const char *line)
{
    int own = fd < 0;
    if (own)
        fd = (int)syscall(SYS_openat, AT_FDCWD, path,
                          O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    size_t length = strlen(line);
    if (syscall(SYS_write, fd, line, length) != (long)length)
        abort();
    if (own)
        syscall(SYS_close, fd);
}

__attribute__((constructor)) static void fault_init(void)
{
    // Programs migr runs get none of this.
    unsetenv("LD_PRELOAD");
    dl_iterate_phdr(find_exe, NULL);
    // The first backtrace() loads the unwinder; never inside a call.
    void *frames[1];
    backtrace(frames, 1);
    const char *list = getenv("MIGR_FAULT_LIST");
    if (list != NULL)
        list_fd = (int)syscall(SYS_openat, AT_FDCWD, list,
                               O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                               0600);
    const char *fault = getenv("MIGR_FAULT");
    if (fault != NULL)
    {
        snprintf(fault_line, sizeof(fault_line), "%s", fault);
        char *error = strchr(fault_line, ' ');
        if (error != NULL)
        {
            *error++ = '\0';
            for (size_t i = 0;
                 i < sizeof(other_errors) / sizeof(other_errors[0]); i++)
                if (strcmp(error, other_errors[i].name) == 0)
                    fault_error = other_errors[i].error;
        }
        fault_site = fault_line;
    }
    hit_path = getenv("MIGR_FAULT_HIT");
}

// Writes the site of the running call to out.
static void site_of(const char *name, char *out, size_t size)
{
    void *frames[32];
    int count = backtrace(frames, 32);
    int used = snprintf(out, size, "%s", name);
    int kept = 0;
    // The shim's own frames lie outside the executable, however many the
    // compiler kept.
    for (int i = 0; i < count && kept < SITE_FRAMES; i++)
    {
        uintptr_t address = (uintptr_t)frames[i];
        if (address < exe_start || address >= exe_end)
            continue;
        used += snprintf(out + used, size - (size_t)used, "+%lx",
                         (unsigned long)(address - exe_start));
        kept++;
    }
}

static uint64_t hash_text(const char *text)
{
    uint64_t hash = 1469598103934665603ULL;
    for (; *text != '\0'; text++)
        hash = (hash ^ (unsigned char)*text) * 1099511628211ULL;
    return hash | 1U;
}

// Whether the site to fail is a call of this name.
static int names_fault_call(const char *name)
{
    size_t length = strlen(name);
    return strncmp(fault_site, name, length) == 0 &&
           (fault_site[length] == '+' || fault_site[length] == '\0');
}

// The error the running call fails with, or 0 when it runs: error is its
// own, other the second one it is listed with, or 0.
static void stop_at_exit(void)
{
    exiting = 1;
}

static int should_fail(const char *name, int error, int other)
{
    if (inside || exiting ||
        (list_fd < 0 && (fault_site == NULL || fault_fired ||
                         !names_fault_call(name))))
        return 0;
    inside = 1;
    char site[256];
    site_of(name, site, sizeof(site));
    // A coverage build writes its counters at exit, and some libgcov
    // versions crash when an allocation there fails; those calls are not
    // migr's. Exit handlers run last registered first, so one registered
    // once migr's own code runs comes before the one that writes them.
    if (!stop_at_exit_set && strchr(site, '+') != NULL)
    {
        stop_at_exit_set = 1;
        atexit(stop_at_exit);
    }
    int fail = 0;
    if (list_fd >= 0)
    {
        uint64_t hash = hash_text(site);
        for (uint32_t slot = (uint32_t)hash % SEEN_SLOTS;;
             slot = (slot + 1U) % SEEN_SLOTS)
        {
            if (seen[slot] == hash)
                break;
            if (seen[slot] == 0)
            {
                seen[slot] = hash;
                char line[sizeof(site) + 16];
                snprintf(line, sizeof(line), "%s\n", site);
                append_line(NULL, list_fd, line);
                const char *other_name = other_error_name(other);
                if (other_name != NULL)
                {
                    snprintf(line, sizeof(line), "%s %s\n", site, other_name);
                    append_line(NULL, list_fd, line);
                }
                break;
            }
        }
    }
    else if (strcmp(site, fault_site) == 0)
    {
        fault_fired = 1;
        fail = fault_error != 0 ? fault_error : error;
        if (hit_path != NULL)
            append_line(hit_path, -1, "hit\n");
    }
    inside = 0;
    return fail;
}

#define REAL(name) \
    static __typeof__(name) *real; \
    if (real == NULL) \
        real = (__typeof__(name) *)dlsym(RTLD_NEXT, #name)

// other, the second error, may read the call's parameters.
#define WRAP_FAILING(type, name, error, other, failed, params, args) \
    type name params \
    { \
        REAL(name); \
        int fault = should_fail(#name, error, other); \
        if (fault != 0) \
        { \
            errno = fault; \
            return failed; \
        } \
        return real args; \
    }

#define WRAP(type, name, error, other, params, args) \
    WRAP_FAILING(type, name, error, other, -1, params, args)

// A coverage build writes its counters through open() at exit; they are
// not migr's files.
static int coverage_file(const char *path)
{
    size_t length = path != NULL ? strlen(path) : 0;
    return length > 5 && strcmp(path + length - 5, ".gcda") == 0;
}

// An open that creates can find the name taken only with O_EXCL.
static int open_other(int flags)
{
    if (!(flags & O_CREAT))
        return ENOENT;
    return (flags & O_EXCL) ? EEXIST : 0;
}

int open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE))
    {
        va_list arguments;
        va_start(arguments, flags);
        mode = va_arg(arguments, mode_t);
        va_end(arguments);
    }
    REAL(open);
    int fault = coverage_file(path)
                    ? 0
                    : should_fail("open", (flags & O_CREAT) ? ENOSPC : EIO,
                                  open_other(flags));
    if (fault != 0)
    {
        errno = fault;
        return -1;
    }
    return real(path, flags, mode);
}

int openat(int dir_fd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE))
    {
        va_list arguments;
        va_start(arguments, flags);
        mode = va_arg(arguments, mode_t);
        va_end(arguments);
    }
    REAL(openat);
    int fault = coverage_file(path)
                    ? 0
                    : should_fail("openat", (flags & O_CREAT) ? ENOSPC : EIO,
                                  open_other(flags));
    if (fault != 0)
    {
        errno = fault;
        return -1;
    }
    return real(dir_fd, path, flags, mode);
}

// A coverage build locks its counter files with F_SETLKW, which migr never
// uses.
int fcntl(int fd, int command, ...)
{
    va_list arguments;
    va_start(arguments, command);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    REAL(fcntl);
    if (command != F_SETLKW && should_fail("fcntl", EIO, 0))
    {
        errno = EIO;
        return -1;
    }
    return real(fd, command, argument);
}

int ioctl(int fd, unsigned long request, ...)
{
    va_list arguments;
    va_start(arguments, request);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    REAL(ioctl);
    if (should_fail("ioctl", EIO, 0))
    {
        errno = EIO;
        return -1;
    }
    return real(fd, request, argument);
}

// Linux releases the descriptor even when close() fails.
int close(int fd)
{
    REAL(close);
    int fail = should_fail("close", EIO, 0);
    int result = real(fd);
    if (fail)
    {
        errno = EIO;
        return -1;
    }
    return result;
}

WRAP(ssize_t, read, EIO, EINTR, (int fd, void *buffer, size_t count),
     (fd, buffer, count))
WRAP(ssize_t, pread, EIO, EINTR,
     (int fd, void *buffer, size_t count, off_t offset),
     (fd, buffer, count, offset))
WRAP(ssize_t, write, ENOSPC, EINTR, (int fd, const void *buffer, size_t count),
     (fd, buffer, count))
WRAP(ssize_t, copy_file_range, ENOSPC, 0,
     (int in_fd, off_t *in_offset, int out_fd, off_t *out_offset,
      size_t length, unsigned int flags),
     (in_fd, in_offset, out_fd, out_offset, length, flags))
WRAP(int, fsync, EIO, 0, (int fd), (fd))
WRAP(int, syncfs, EIO, 0, (int fd), (fd))
WRAP(int, ftruncate, ENOSPC, 0, (int fd, off_t length), (fd, length))
WRAP(int, mkdir, ENOSPC, EEXIST, (const char *path, mode_t mode), (path, mode))
WRAP(int, mkdirat, ENOSPC, EEXIST, (int dir_fd, const char *path, mode_t mode),
     (dir_fd, path, mode))
WRAP(int, mkfifoat, ENOSPC, EEXIST, (int dir_fd, const char *path, mode_t mode),
     (dir_fd, path, mode))
WRAP(int, symlinkat, ENOSPC, EEXIST,
     (const char *target, int dir_fd, const char *path),
     (target, dir_fd, path))
WRAP(int, link, ENOSPC, EEXIST, (const char *from, const char *to), (from, to))
WRAP(int, linkat, ENOSPC, EEXIST,
     (int from_dir, const char *from, int to_dir, const char *to, int flags),
     (from_dir, from, to_dir, to, flags))
WRAP(int, rename, EIO, ENOENT, (const char *from, const char *to), (from, to))
WRAP(int, renameat, EIO, ENOENT,
     (int from_dir, const char *from, int to_dir, const char *to),
     (from_dir, from, to_dir, to))
WRAP(int, renameat2, EIO, (flags & RENAME_NOREPLACE) ? EEXIST : ENOENT,
     (int from_dir, const char *from, int to_dir, const char *to,
      unsigned int flags),
     (from_dir, from, to_dir, to, flags))
WRAP(int, unlink, EIO, ENOENT, (const char *path), (path))
WRAP(int, unlinkat, EIO, ENOENT, (int dir_fd, const char *path, int flags),
     (dir_fd, path, flags))
WRAP(int, fchmod, EIO, 0, (int fd, mode_t mode), (fd, mode))
WRAP(int, fchmodat, EIO, ENOENT,
     (int dir_fd, const char *path, mode_t mode, int flags),
     (dir_fd, path, mode, flags))
WRAP(int, fchown, EIO, 0,
     (int fd, uid_t owner, gid_t group), (fd, owner, group))
WRAP(int, fchownat, EIO, ENOENT,
     (int dir_fd, const char *path, uid_t owner, gid_t group, int flags),
     (dir_fd, path, owner, group, flags))
WRAP(int, futimens, EIO, 0,
     (int fd, const struct timespec times[2]), (fd, times))
WRAP(int, utimensat, EIO, path != NULL ? ENOENT : 0,
     (int dir_fd, const char *path, const struct timespec times[2], int flags),
     (dir_fd, path, times, flags))
WRAP(int, fsetxattr, ENOSPC, 0,
     (int fd, const char *name, const void *value, size_t size, int flags),
     (fd, name, value, size, flags))
WRAP(int, lsetxattr, ENOSPC, ENOENT,
     (const char *path, const char *name, const void *value, size_t size,
      int flags),
     (path, name, value, size, flags))
WRAP(int, fremovexattr, EIO, 0, (int fd, const char *name), (fd, name))
WRAP(int, stat, EIO, ENOENT,
     (const char *path, struct stat *buffer), (path, buffer))
WRAP(int, lstat, EIO, ENOENT,
     (const char *path, struct stat *buffer), (path, buffer))
WRAP(int, fstat, EIO, 0, (int fd, struct stat *buffer), (fd, buffer))
WRAP(int, fstatat, EIO, ENOENT,
     (int dir_fd, const char *path, struct stat *buffer, int flags),
     (dir_fd, path, buffer, flags))
WRAP(int, statx, EIO, ENOENT,
     (int dir_fd, const char *path, int flags, unsigned int mask,
      struct statx *buffer),
     (dir_fd, path, flags, mask, buffer))
WRAP(off_t, lseek, EIO, 0, (int fd, off_t offset, int whence),
     (fd, offset, whence))
WRAP(int, dup, EIO, 0, (int fd), (fd))
WRAP(int, dup2, EIO, 0, (int fd, int to), (fd, to))
WRAP_FAILING(DIR *, opendir, EIO, ENOENT, NULL, (const char *path), (path))
WRAP_FAILING(DIR *, fdopendir, EIO, 0, NULL, (int fd), (fd))
WRAP_FAILING(struct dirent *, readdir, EIO, 0, NULL, (DIR *dir), (dir))

// closedir() releases the stream even when it fails.
int closedir(DIR *dir)
{
    REAL(closedir);
    int fail = should_fail("closedir", EIO, 0);
    int result = real(dir);
    if (fail)
    {
        errno = EIO;
        return -1;
    }
    return result;
}
WRAP(ssize_t, readlink, EIO, ENOENT,
     (const char *path, char *buffer, size_t size),
     (path, buffer, size))
WRAP(ssize_t, readlinkat, EIO, ENOENT,
     (int dir_fd, const char *path, char *buffer, size_t size),
     (dir_fd, path, buffer, size))
WRAP(ssize_t, getxattr, EIO, ENODATA,
     (const char *path, const char *name, void *value, size_t size),
     (path, name, value, size))
WRAP(ssize_t, lgetxattr, EIO, ENODATA,
     (const char *path, const char *name, void *value, size_t size),
     (path, name, value, size))
WRAP(ssize_t, fgetxattr, EIO, ENODATA,
     (int fd, const char *name, void *value, size_t size),
     (fd, name, value, size))
WRAP(ssize_t, llistxattr, EIO, ENOENT,
     (const char *path, char *list, size_t size),
     (path, list, size))
WRAP(ssize_t, flistxattr, EIO, 0, (int fd, char *list, size_t size),
     (fd, list, size))

// glibc's own allocations, those of strdup() or fopen() too, go through
// these; the __libc_ entry points reach its allocator without dlsym(),
// which allocates.
extern void *__libc_malloc(size_t size);
extern void *__libc_calloc(size_t count, size_t size);
extern void *__libc_realloc(void *pointer, size_t size);

void *malloc(size_t size)
{
    if (should_fail("malloc", ENOMEM, 0))
    {
        errno = ENOMEM;
        return NULL;
    }
    return __libc_malloc(size);
}

void *calloc(size_t count, size_t size)
{
    if (should_fail("calloc", ENOMEM, 0))
    {
        errno = ENOMEM;
        return NULL;
    }
    return __libc_calloc(count, size);
}

void *realloc(void *pointer, size_t size)
{
    if (should_fail("realloc", ENOMEM, 0))
    {
        errno = ENOMEM;
        return NULL;
    }
    return __libc_realloc(pointer, size);
}
WRAP(int, statfs, EIO, ENOENT, (const char *path, struct statfs *buffer),
     (path, buffer))
WRAP(int, fstatfs, EIO, 0, (int fd, struct statfs *buffer), (fd, buffer))
WRAP(int, fstatvfs, EIO, 0, (int fd, struct statvfs *buffer), (fd, buffer))
WRAP_FAILING(FILE *, fopen, mode[0] == 'r' ? EIO : ENOSPC,
             mode[0] == 'r' ? ENOENT : 0, NULL,
             (const char *path, const char *mode), (path, mode))
WRAP_FAILING(pid_t, fork, EAGAIN, 0, -1, (void), ())
WRAP(int, pipe, EMFILE, 0, (int fds[2]), (fds))
WRAP(int, pipe2, EMFILE, 0, (int fds[2], int flags), (fds, flags))
WRAP_FAILING(pid_t, waitpid, ECHILD, EINTR, -1,
             (pid_t pid, int *status, int options), (pid, status, options))
WRAP(int, poll, ENOMEM, EINTR, (struct pollfd *fds, nfds_t count, int timeout),
     (fds, count, timeout))
WRAP(int, execvp, EACCES, ENOENT, (const char *file, char *const argv[]),
     (file, argv))

// The standard streams are not files migr opens.
static int own_stream(FILE *stream)
{
    return stream != NULL && stream != stdin && stream != stdout &&
           stream != stderr;
}

int fflush(FILE *stream)
{
    REAL(fflush);
    if (own_stream(stream) && should_fail("fflush", EIO, 0))
    {
        errno = EIO;
        return EOF;
    }
    return real(stream);
}

// fclose() releases the stream even when it fails.
int fclose(FILE *stream)
{
    REAL(fclose);
    int fail = own_stream(stream) && should_fail("fclose", EIO, 0);
    int result = real(stream);
    if (fail)
    {
        errno = EIO;
        return EOF;
    }
    return result;
}

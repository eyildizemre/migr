// Fault injection for tests/fault_sweep.sh, loaded into migr with
// LD_PRELOAD. A call site is the call's name and the innermost frames of
// migr's own code that lead to it, so every caller of a shared helper is a
// site of its own.
//
//   MIGR_FAULT_LIST=FILE  appends each site to FILE the first time it runs
//   MIGR_FAULT=SITE       fails the first call at SITE, and appends SITE to
//                         MIGR_FAULT_HIT when that file is named
//
// Calls that write or create fail with ENOSPC, the others with EIO.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <link.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define SITE_FRAMES 4
#define SEEN_SLOTS 65536U

static uintptr_t exe_start;
static uintptr_t exe_end;
static int list_fd = -1;
static const char *fault_site;
static const char *hit_path;
static int fault_fired;
static uint64_t seen[SEEN_SLOTS];
static __thread int inside;

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
    fault_site = getenv("MIGR_FAULT");
    hit_path = getenv("MIGR_FAULT_HIT");
}

// Writes the site of the running call to out.
static void site_of(const char *name, char *out, size_t size)
{
    void *frames[32];
    int count = backtrace(frames, 32);
    int used = snprintf(out, size, "%s", name);
    int kept = 0;
    // Frame 0 is site_of, frame 1 is should_fail, frame 2 the wrapper.
    for (int i = 3; i < count && kept < SITE_FRAMES; i++)
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

static int should_fail(const char *name)
{
    if (inside || (list_fd < 0 && (fault_site == NULL || fault_fired)))
        return 0;
    inside = 1;
    char site[256];
    site_of(name, site, sizeof(site));
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
                strcat(site, "\n");
                append_line(NULL, list_fd, site);
                break;
            }
        }
    }
    else if (strcmp(site, fault_site) == 0)
    {
        fault_fired = 1;
        fail = 1;
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

#define WRAP(type, name, error, params, args) \
    type name params \
    { \
        REAL(name); \
        if (should_fail(#name)) \
        { \
            errno = error; \
            return -1; \
        } \
        return real args; \
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
    if (should_fail("open"))
    {
        errno = (flags & O_CREAT) ? ENOSPC : EIO;
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
    if (should_fail("openat"))
    {
        errno = (flags & O_CREAT) ? ENOSPC : EIO;
        return -1;
    }
    return real(dir_fd, path, flags, mode);
}

// Linux releases the descriptor even when close() fails.
int close(int fd)
{
    REAL(close);
    int fail = should_fail("close");
    int result = real(fd);
    if (fail)
    {
        errno = EIO;
        return -1;
    }
    return result;
}

WRAP(ssize_t, read, EIO, (int fd, void *buffer, size_t count),
     (fd, buffer, count))
WRAP(ssize_t, pread, EIO, (int fd, void *buffer, size_t count, off_t offset),
     (fd, buffer, count, offset))
WRAP(ssize_t, write, ENOSPC, (int fd, const void *buffer, size_t count),
     (fd, buffer, count))
WRAP(ssize_t, copy_file_range, ENOSPC,
     (int in_fd, off_t *in_offset, int out_fd, off_t *out_offset,
      size_t length, unsigned int flags),
     (in_fd, in_offset, out_fd, out_offset, length, flags))
WRAP(int, fsync, EIO, (int fd), (fd))
WRAP(int, syncfs, EIO, (int fd), (fd))
WRAP(int, ftruncate, ENOSPC, (int fd, off_t length), (fd, length))
WRAP(int, mkdir, ENOSPC, (const char *path, mode_t mode), (path, mode))
WRAP(int, mkdirat, ENOSPC, (int dir_fd, const char *path, mode_t mode),
     (dir_fd, path, mode))
WRAP(int, mkfifoat, ENOSPC, (int dir_fd, const char *path, mode_t mode),
     (dir_fd, path, mode))
WRAP(int, symlinkat, ENOSPC,
     (const char *target, int dir_fd, const char *path),
     (target, dir_fd, path))
WRAP(int, link, ENOSPC, (const char *from, const char *to), (from, to))
WRAP(int, linkat, ENOSPC,
     (int from_dir, const char *from, int to_dir, const char *to, int flags),
     (from_dir, from, to_dir, to, flags))
WRAP(int, rename, EIO, (const char *from, const char *to), (from, to))
WRAP(int, renameat, EIO,
     (int from_dir, const char *from, int to_dir, const char *to),
     (from_dir, from, to_dir, to))
WRAP(int, renameat2, EIO,
     (int from_dir, const char *from, int to_dir, const char *to,
      unsigned int flags),
     (from_dir, from, to_dir, to, flags))
WRAP(int, unlink, EIO, (const char *path), (path))
WRAP(int, unlinkat, EIO, (int dir_fd, const char *path, int flags),
     (dir_fd, path, flags))
WRAP(int, fchmod, EIO, (int fd, mode_t mode), (fd, mode))
WRAP(int, fchmodat, EIO, (int dir_fd, const char *path, mode_t mode, int flags),
     (dir_fd, path, mode, flags))
WRAP(int, fchown, EIO, (int fd, uid_t owner, gid_t group), (fd, owner, group))
WRAP(int, fchownat, EIO,
     (int dir_fd, const char *path, uid_t owner, gid_t group, int flags),
     (dir_fd, path, owner, group, flags))
WRAP(int, futimens, EIO, (int fd, const struct timespec times[2]), (fd, times))
WRAP(int, utimensat, EIO,
     (int dir_fd, const char *path, const struct timespec times[2], int flags),
     (dir_fd, path, times, flags))
WRAP(int, fsetxattr, ENOSPC,
     (int fd, const char *name, const void *value, size_t size, int flags),
     (fd, name, value, size, flags))
WRAP(int, lsetxattr, ENOSPC,
     (const char *path, const char *name, const void *value, size_t size,
      int flags),
     (path, name, value, size, flags))
WRAP(int, fremovexattr, EIO, (int fd, const char *name), (fd, name))

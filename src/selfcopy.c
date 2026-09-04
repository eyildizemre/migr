#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "selfcopy.h"
#include "utils.h"

static int pread_exact(int fd, void *buf, size_t size, off_t offset)
{
    unsigned char *out = buf;
    size_t done = 0;

    while (done < size)
    {
        ssize_t n = pread(fd, out + done, size - done,
                          offset + (off_t)done);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return 0;
        done += (size_t)n;
    }
    return 1;
}

static MigrStaticStatus store_arch(uint16_t machine, char *arch_out,
                                   size_t arch_size)
{
    const char *name;

    switch (machine)
    {
        case EM_X86_64:
            name = "x86_64";
            break;
        case EM_AARCH64:
            name = "aarch64";
            break;
        case EM_386:
            name = "i386";
            break;
        case EM_RISCV:
            name = "riscv64";
            break;
        default:
            return MIGR_STATIC_UNKNOWN_ARCH;
    }

    size_t needed = strlen(name) + 1U;
    if (needed > arch_size)
    {
        errno = ENOSPC;
        return MIGR_STATIC_IO_ERROR;
    }
    memcpy(arch_out, name, needed);
    return MIGR_STATIC_OK;
}

MigrStaticStatus migr_static_validate_fd(int fd, char *arch_out,
                                         size_t arch_size)
{
    if (arch_out != NULL && arch_size > 0)
        arch_out[0] = '\0';
    if (fd < 0 || arch_out == NULL || arch_size == 0)
    {
        errno = EINVAL;
        return MIGR_STATIC_IO_ERROR;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
        return MIGR_STATIC_IO_ERROR;
    if (!S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(Elf64_Ehdr))
        return MIGR_STATIC_NOT_ELF;

    Elf64_Ehdr ehdr;
    int read_status = pread_exact(fd, &ehdr, sizeof(ehdr), 0);
    if (read_status < 0)
        return MIGR_STATIC_IO_ERROR;
    if (read_status == 0)
        return MIGR_STATIC_NOT_ELF;

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
        return MIGR_STATIC_NOT_ELF;

    /*
     * migr currently builds only 64-bit little-endian binaries. Supporting
     * another ELF layout requires parsing that layout explicitly rather than
     * interpreting its fields as Elf64 structures.
     */
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA] != ELFDATA2LSB)
        return MIGR_STATIC_NOT_ELF;

    if (ehdr.e_phentsize < sizeof(Elf64_Phdr))
        return MIGR_STATIC_NOT_ELF;

    uint64_t phoff = ehdr.e_phoff;
    uint64_t phentsize = ehdr.e_phentsize;
    uint64_t phnum = ehdr.e_phnum;
    if (phnum != 0 && phentsize > (UINT64_MAX - phoff) / phnum)
        return MIGR_STATIC_NOT_ELF;

    uint64_t phend = phoff + phnum * phentsize;
    if (st.st_size < 0 || phend > (uint64_t)st.st_size)
        return MIGR_STATIC_NOT_ELF;

    for (uint64_t i = 0; i < phnum; i++)
    {
        uint64_t raw_offset = phoff + i * phentsize;
        if (raw_offset > (uint64_t)st.st_size)
            return MIGR_STATIC_NOT_ELF;

        Elf64_Phdr phdr;
        read_status = pread_exact(fd, &phdr, sizeof(phdr),
                                  (off_t)raw_offset);
        if (read_status < 0)
            return MIGR_STATIC_IO_ERROR;
        if (read_status == 0)
            return MIGR_STATIC_NOT_ELF;
        if (phdr.p_type == PT_INTERP)
            return MIGR_STATIC_NOT_STATIC;
    }

    return store_arch(ehdr.e_machine, arch_out, arch_size);
}

MigrStaticStatus migr_static_probe(int *out_fd, char *arch_out,
                                   size_t arch_size)
{
    if (out_fd == NULL)
    {
        errno = EINVAL;
        return MIGR_STATIC_IO_ERROR;
    }
    *out_fd = -1;
    if (arch_out != NULL && arch_size > 0)
        arch_out[0] = '\0';
    if (arch_out == NULL || arch_size == 0)
    {
        errno = EINVAL;
        return MIGR_STATIC_IO_ERROR;
    }

    char executable[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", executable,
                              sizeof(executable));
    if (length < 0)
        return MIGR_STATIC_IO_ERROR;
    if ((size_t)length >= sizeof(executable))
    {
        errno = ENAMETOOLONG;
        return MIGR_STATIC_IO_ERROR;
    }
    executable[length] = '\0';

    char *slash = strrchr(executable, '/');
    if (slash == NULL)
    {
        errno = EINVAL;
        return MIGR_STATIC_IO_ERROR;
    }
    if (slash == executable)
        slash[1] = '\0';
    else
        *slash = '\0';

    char candidate[PATH_MAX];
    if (path_join(candidate, sizeof(candidate), executable,
                  "migr-static") != 0)
    {
        errno = ENAMETOOLONG;
        return MIGR_STATIC_IO_ERROR;
    }

    int fd = open(candidate, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
    {
        if (errno == ENOENT)
            return MIGR_STATIC_NOT_FOUND;
        return MIGR_STATIC_IO_ERROR;
    }

    MigrStaticStatus status = migr_static_validate_fd(fd, arch_out,
                                                      arch_size);
    if (status != MIGR_STATIC_OK)
    {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return status;
    }

    *out_fd = fd;
    return MIGR_STATIC_OK;
}

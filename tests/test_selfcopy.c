#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "selfcopy.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define YELLOW "\033[0;33m"
#define NC    "\033[0m"

static int failures = 0;
static const char *sibling_path = "tests/migr-static";

static void check(int condition, const char *label)
{
    if (condition)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void fixture_fatal(const char *label)
{
    perror(label);
    exit(1);
}

static void remove_sibling(void)
{
    struct stat st;
    if (lstat(sibling_path, &st) != 0)
    {
        if (errno == ENOENT)
            return;
        fixture_fatal("fixture: inspect sibling migr-static");
    }

    if (S_ISDIR(st.st_mode))
    {
        if (rmdir(sibling_path) != 0)
            fixture_fatal("fixture: remove sibling directory");
    }
    else if (unlink(sibling_path) != 0)
    {
        fixture_fatal("fixture: remove sibling file");
    }
}

static int new_fixture_fd(void)
{
    char path[] = "/tmp/migr_selfcopy_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        fixture_fatal("fixture: mkstemp");
    if (unlink(path) != 0)
    {
        close(fd);
        fixture_fatal("fixture: unlink temporary file");
    }
    return fd;
}

static void write_exact_at(int fd, const void *buf, size_t size, off_t offset)
{
    const unsigned char *bytes = buf;
    size_t done = 0;
    while (done < size)
    {
        ssize_t n = pwrite(fd, bytes + done, size - done,
                           offset + (off_t)done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            fixture_fatal("fixture: pwrite");
        done += (size_t)n;
    }
}

static Elf64_Ehdr base_header(uint16_t machine)
{
    Elf64_Ehdr ehdr;
    memset(&ehdr, 0, sizeof(ehdr));
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_type = ET_EXEC;
    ehdr.e_machine = machine;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    ehdr.e_phoff = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 1;
    return ehdr;
}

static int make_elf_fixture(uint16_t machine, uint32_t phdr_type)
{
    int fd = new_fixture_fd();
    Elf64_Ehdr ehdr = base_header(machine);
    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(phdr));
    phdr.p_type = phdr_type;
    write_exact_at(fd, &ehdr, sizeof(ehdr), 0);
    write_exact_at(fd, &phdr, sizeof(phdr), (off_t)ehdr.e_phoff);
    return fd;
}

static void make_elf_path(const char *path, uint16_t machine,
                          uint32_t phdr_type)
{
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    if (fd < 0)
        fixture_fatal("fixture: create ELF path");

    Elf64_Ehdr ehdr = base_header(machine);
    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(phdr));
    phdr.p_type = phdr_type;
    write_exact_at(fd, &ehdr, sizeof(ehdr), 0);
    write_exact_at(fd, &phdr, sizeof(phdr), (off_t)ehdr.e_phoff);
    if (close(fd) != 0)
        fixture_fatal("fixture: close ELF path");
}

static void test_real_binaries(void)
{
    printf(BLUE "::" NC " selfcopy: real static and dynamic binaries\n");

    char arch[MIGR_ARCH_MAX];
    int fd = open("migr-static", O_RDONLY | O_CLOEXEC);
    if (fd >= 0)
    {
        check(migr_static_validate_fd(fd, arch, sizeof(arch)) ==
                  MIGR_STATIC_OK,
              "the real migr-static validates as static");
        check(strcmp(arch, "x86_64") == 0,
              "the real migr-static reports x86_64 from e_machine");
        check(lseek(fd, 0, SEEK_CUR) == 0,
              "validation leaves the static binary offset at zero");
        close(fd);
    }
    else if (errno == ENOENT)
    {
        printf("  " YELLOW "-" NC
               " real migr-static unavailable; synthetic static ELF cases remain active\n");
    }
    else
    {
        fixture_fatal("fixture: open migr-static");
    }

    fd = open("migr", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fixture_fatal("fixture: open migr");
    memset(arch, 'x', sizeof(arch));
    check(migr_static_validate_fd(fd, arch, sizeof(arch)) ==
              MIGR_STATIC_NOT_STATIC,
          "the real dynamic migr is rejected by its PT_INTERP header");
    check(arch[0] == '\0',
          "a rejected dynamic binary leaves no architecture result");
    close(fd);
}

static void test_locator_paths(void)
{
    printf(BLUE "::" NC " selfcopy: sibling locator and path refusals\n");
    remove_sibling();

    int fd = 123;
    char arch[MIGR_ARCH_MAX] = "dirty";
    check(migr_static_probe(&fd, arch, sizeof(arch)) ==
              MIGR_STATIC_NOT_FOUND,
          "an absent sibling migr-static is reported as not found");
    check(fd == -1 && arch[0] == '\0',
          "the absent-file result leaves no descriptor or architecture");

    make_elf_path(sibling_path, EM_X86_64, PT_LOAD);
    fd = -1;
    check(migr_static_probe(&fd, arch, sizeof(arch)) == MIGR_STATIC_OK,
          "the locator validates a static ELF sibling");
    check(fd >= 0 && strcmp(arch, "x86_64") == 0,
          "the successful locator returns the open binary and architecture");
    check(fd >= 0 && lseek(fd, 0, SEEK_CUR) == 0,
          "the returned descriptor remains positioned at offset zero");
    if (fd >= 0)
        close(fd);
    remove_sibling();

    if (mkdir(sibling_path, 0700) != 0)
        fixture_fatal("fixture: create sibling directory");
    fd = 123;
    check(migr_static_probe(&fd, arch, sizeof(arch)) == MIGR_STATIC_NOT_ELF,
          "a directory at the sibling path is not accepted as an ELF binary");
    check(fd == -1,
          "the directory refusal leaves no descriptor open");
    remove_sibling();

    if (symlink("../migr-static", sibling_path) != 0)
        fixture_fatal("fixture: create sibling symlink");
    fd = 123;
    errno = 0;
    check(migr_static_probe(&fd, arch, sizeof(arch)) == MIGR_STATIC_IO_ERROR &&
              errno == ELOOP,
          "O_NOFOLLOW refuses a symlink at the sibling path");
    check(fd == -1,
          "the symlink refusal leaves no descriptor open");
    remove_sibling();
}

static void test_malformed_elf(void)
{
    printf(BLUE "::" NC " selfcopy: malformed ELF bounds\n");
    char arch[MIGR_ARCH_MAX];

    int fd = new_fixture_fd();
    const unsigned char short_file[8] = {0x7f, 'E', 'L', 'F'};
    write_exact_at(fd, short_file, sizeof(short_file), 0);
    check(migr_static_validate_fd(fd, arch, sizeof(arch)) ==
              MIGR_STATIC_NOT_ELF,
          "a short file is rejected before reading an ELF header");
    close(fd);

    fd = new_fixture_fd();
    Elf64_Ehdr wrong_magic = base_header(EM_X86_64);
    memset(wrong_magic.e_ident, 0, SELFMAG);
    write_exact_at(fd, &wrong_magic, sizeof(wrong_magic), 0);
    check(migr_static_validate_fd(fd, arch, sizeof(arch)) ==
              MIGR_STATIC_NOT_ELF,
          "a full-size header with the wrong ELF magic is rejected");
    close(fd);

    fd = new_fixture_fd();
    Elf64_Ehdr truncated = base_header(EM_X86_64);
    write_exact_at(fd, &truncated, sizeof(truncated), 0);
    check(migr_static_validate_fd(fd, arch, sizeof(arch)) ==
              MIGR_STATIC_NOT_ELF,
          "a program-header table extending past EOF is rejected");
    close(fd);

    fd = new_fixture_fd();
    Elf64_Ehdr small_entry = base_header(EM_X86_64);
    small_entry.e_phentsize = sizeof(Elf64_Phdr) - 1U;
    write_exact_at(fd, &small_entry, sizeof(small_entry), 0);
    check(migr_static_validate_fd(fd, arch, sizeof(arch)) ==
              MIGR_STATIC_NOT_ELF,
          "a program-header entry smaller than Elf64_Phdr is rejected");
    close(fd);

    fd = new_fixture_fd();
    Elf64_Ehdr overflowing = base_header(EM_X86_64);
    overflowing.e_phoff = UINT64_MAX - 15U;
    overflowing.e_phnum = 2;
    write_exact_at(fd, &overflowing, sizeof(overflowing), 0);
    check(migr_static_validate_fd(fd, arch, sizeof(arch)) ==
              MIGR_STATIC_NOT_ELF,
          "overflow in the program-header extent is rejected");
    close(fd);

    fd = make_elf_fixture(EM_X86_64, PT_LOAD);
    Elf64_Ehdr unsupported_class = base_header(EM_X86_64);
    unsupported_class.e_ident[EI_CLASS] = ELFCLASS32;
    write_exact_at(fd, &unsupported_class, sizeof(unsupported_class), 0);
    check(migr_static_validate_fd(fd, arch, sizeof(arch)) ==
              MIGR_STATIC_NOT_ELF,
          "an unsupported ELF class is rejected rather than half-parsed");
    close(fd);

    fd = make_elf_fixture(EM_X86_64, PT_LOAD);
    Elf64_Ehdr unsupported_data = base_header(EM_X86_64);
    unsupported_data.e_ident[EI_DATA] = ELFDATA2MSB;
    write_exact_at(fd, &unsupported_data, sizeof(unsupported_data), 0);
    check(migr_static_validate_fd(fd, arch, sizeof(arch)) ==
              MIGR_STATIC_NOT_ELF,
          "an unsupported ELF byte order is rejected rather than half-parsed");
    close(fd);
}

static void test_architecture_mapping(void)
{
    printf(BLUE "::" NC " selfcopy: architecture mapping\n");

    struct {
        uint16_t machine;
        const char *name;
    } cases[] = {
        {EM_X86_64, "x86_64"},
        {EM_AARCH64, "aarch64"},
        {EM_386, "i386"},
        {EM_RISCV, "riscv64"}
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        int fd = make_elf_fixture(cases[i].machine, PT_LOAD);
        char arch[MIGR_ARCH_MAX];
        MigrStaticStatus status = migr_static_validate_fd(fd, arch,
                                                          sizeof(arch));
        check(status == MIGR_STATIC_OK && strcmp(arch, cases[i].name) == 0,
              "a supported e_machine maps to its manifest architecture name");
        close(fd);
    }

    int fd = make_elf_fixture(EM_NONE, PT_LOAD);
    char arch[MIGR_ARCH_MAX] = "dirty";
    check(migr_static_validate_fd(fd, arch, sizeof(arch)) ==
              MIGR_STATIC_UNKNOWN_ARCH,
          "an unknown e_machine is refused");
    check(arch[0] == '\0',
          "an unknown architecture leaves no architecture result");
    close(fd);
}

int main(void)
{
    test_real_binaries();
    test_locator_paths();
    test_malformed_elf();
    test_architecture_mapping();
    remove_sibling();

    if (failures == 0)
        printf(GREEN "selfcopy tests passed" NC "\n");
    else
        printf(RED "selfcopy tests: %d failure(s)" NC "\n", failures);
    return failures == 0 ? 0 : 1;
}

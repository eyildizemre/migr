#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "utils.h"

int verbose = 0;
int dry_run = 0;

int path_join_n(char *buf, size_t size, const char *dir,
                const char *name, size_t name_len)
{
    // The "%.*s" precision is an int; a name_len past INT_MAX would overflow the
    // cast. Production callers stay under PATH_MAX, but reject it rather than
    // rely on that invariant holding forever.
    if (name_len > INT_MAX)
        return -1;
    int n = snprintf(buf, size, "%s/%.*s", dir, (int)name_len, name);
    if (n < 0 || (size_t)n >= size)
        return -1;
    return 0;
}

int path_join(char *buf, size_t size, const char *dir, const char *name)
{
    return path_join_n(buf, size, dir, name, strlen(name));
}

void print_help(void)
{
    printf("Usage: ./migr <COMMAND> [ARGUMENTS] [OPTIONS]\n");
    printf("\n");
    printf("Commands:\n");
    printf("  report                Show backup analysis report (default when no command given)\n");
    printf("  backup <PATH>         Create a resumable backup container under PATH\n");
    printf("  packages <FILE>       Export the installed package list to FILE\n");
    printf("  restore <SOURCE>      Restore files and packages from a backup at SOURCE\n");
    printf("  help                  Show this help\n");
    printf("\n");
    printf("Backup scope (backup only, mutually exclusive):\n");
    printf("  --critical            Documents, Downloads, Pictures, and dotfiles (default)\n");
    printf("  --comprehensive       Everything --critical covers, plus Desktop, Videos, Music\n");
    printf("  <PATH...>             Paths listed after the destination are backed up\n");
    printf("                        exactly as given, with no assumptions\n");
    printf("\n");
    printf("Options:\n");
    printf("  -n, --dry-run         Preview actions without making changes\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -h, --help            Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  ./migr backup /mnt/drive\n");
    printf("  ./migr backup /mnt/drive --comprehensive\n");
    printf("  ./migr backup /mnt/drive ~/Documents ~/Projects\n");
    printf("  ./migr restore /mnt/drive/migr_backup_20260720_143012\n");
}

int confirm_action(const char *message)
{
    printf("%s [y/N]: ", message);
    
    char response[16];
    if (fgets(response, sizeof(response), stdin) == NULL)
    {
        return 0;
    }
    
    return (response[0] == 'y' || response[0] == 'Y');
}

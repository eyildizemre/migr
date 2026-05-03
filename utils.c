#include <stdio.h>

#include "utils.h"

int verbose = 0;
int dry_run = 0;

void print_help(void)
{
    printf("Usage: ./migr [COMMAND] [OPTIONS]\n");
    printf("\n");
    printf("Commands:\n");
    printf("  -report               Show backup analysis report (default when no arguments given)\n");
    printf("  -backup <PATH>        Copy critical files and packages to PATH\n");
    printf("  -packages [FILE]      List installed packages; optionally save to FILE\n");
    printf("  -restore <SOURCE>     Restore files and packages from a backup at SOURCE\n");
    printf("\n");
    printf("Options:\n");
    printf("  -n, --dry-run         Preview actions without making changes\n");
    printf("  -v                    Verbose output (combine with any flag)\n");
    printf("  -help                 Show help\n");
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

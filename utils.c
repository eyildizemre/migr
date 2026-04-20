#include <stdio.h>
#include <string.h>

#include "utils.h"

int verbose = 0;
int dry_run = 0;

void print_help(void)
{
    printf("Usage: migr [OPTIONS]\n");
    printf("Options:\n");
    printf("  -report               Generate a report of files & directories that need to be backup\n");
    printf("  -backup <PATH>        Backup the files & directories to the specified PATH\n");
    printf("  -packages             List packages that are installed on the setup\n");
    printf("  -restore <SOURCE>     Restore files & directories from the specified source\n");
    printf(" -n, --dry-run Preview actions without making changes\n");
    printf("  -help                 Display this help message\n");
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

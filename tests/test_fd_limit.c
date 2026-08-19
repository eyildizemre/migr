#define _GNU_SOURCE

#include <stdio.h>
#include <sys/resource.h>

#include "utils.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures;

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

int main(void)
{
    printf(BLUE "::" NC " raise_fd_limit (unit)\n");

    struct rlimit original;
    check(getrlimit(RLIMIT_NOFILE, &original) == 0,
          "fixture: read the starting open-file limit");

    struct rlimit lowered = original;
    lowered.rlim_cur = original.rlim_max > 1
        ? original.rlim_max - 1 : original.rlim_max;
    int could_lower = setrlimit(RLIMIT_NOFILE, &lowered) == 0;
    check(could_lower, "fixture: the soft limit can be set below the hard limit");

    if (could_lower)
    {
        struct rlimit confirmed;
        check(getrlimit(RLIMIT_NOFILE, &confirmed) == 0 &&
                  confirmed.rlim_cur == lowered.rlim_cur,
              "fixture: the soft limit is now below the hard limit");

        raise_fd_limit();

        struct rlimit raised;
        check(getrlimit(RLIMIT_NOFILE, &raised) == 0 &&
                  raised.rlim_cur == raised.rlim_max,
              "raise_fd_limit restores the soft limit to the hard limit");
        check(raised.rlim_max == original.rlim_max,
              "raise_fd_limit never changes the hard limit itself");

        raise_fd_limit();
        struct rlimit again;
        check(getrlimit(RLIMIT_NOFILE, &again) == 0 &&
                  again.rlim_cur == again.rlim_max,
              "raise_fd_limit is idempotent once already at the ceiling");
    }

    printf("fd limit tests: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}

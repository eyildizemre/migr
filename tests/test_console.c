#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "console.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures = 0;
static char sessions[] = "/tmp/migr-console-XXXXXX";

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

// Writes a logind session file the way systemd-logind lays it out.
static void write_session(const char *id, const char *uid, const char *type,
                          const char *class, const char *state)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", sessions, id);
    FILE *file = fopen(path, "w");
    if (file == NULL)
        fixture_fatal("fixture: write session");
    fprintf(file, "# This is private data. Do not parse.\nUID=%s\n"
                  "USER=someone\nACTIVE=1\nSTATE=%s\nTYPE=%s\n"
                  "ORIGINAL_TYPE=%s\nCLASS=%s\nSCOPE=session-%s.scope\n"
                  "SEAT=seat0\nVTNR=2\n",
            uid, state, type, type, class, id);
    if (fclose(file) != 0)
        fixture_fatal("fixture: close session");
}

static void remove_session(const char *id)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", sessions, id);
    if (unlink(path) != 0)
        fixture_fatal("fixture: remove session");
}

static const char desktop_cgroup[] =
    "0::/user.slice/user-1000.slice/session-2.scope\n";

static void test_graphical_session(void)
{
    printf(BLUE "::" NC " a restore leaves only the one graphical session\n");
    if (mkdtemp(sessions) == NULL)
        fixture_fatal("fixture: mkdtemp");

    write_session("2", "1000", "wayland", "user", "active");
    // Its reference FIFO sits beside it and must not be opened.
    char fifo[512];
    snprintf(fifo, sizeof(fifo), "%s/2.ref", sessions);
    if (mkfifo(fifo, 0600) != 0)
        fixture_fatal("fixture: mkfifo");
    // The greeter and a logout still in progress are not logins to end.
    write_session("c1", "42", "wayland", "greeter", "online");
    write_session("5", "1001", "x11", "user", "closing");
    check(console_test_graphical_session(sessions, desktop_cgroup, 1000) == 1,
          "the invoker's Wayland session, next to a greeter and a closing "
          "one, is the only one");
    check(console_test_graphical_session(sessions, desktop_cgroup, 1001) == 0,
          "a session of another user than the invoker is not taken");
    check(console_test_graphical_session(
              sessions, "0::/user.slice/user-1000.slice/user@1000.service/"
                        "app.slice/ptyxis-spawn-1.scope\n", 1000) == 1,
          "a terminal the desktop's service manager started is on the desktop");
    check(console_test_graphical_session(
              sessions, "0::/user.slice/user-1001.slice/user@1001.service/"
                        "app.slice/app-org.kde.konsole-2.scope/tab(3).scope\n",
              1000) == 0,
          "another user's service manager is not the invoker's desktop");
    check(console_test_graphical_session(
              sessions, "0::/system.slice/sshd.service\n", 1000) == 0,
          "a process outside a session and the service manager stays in place");
    check(console_test_graphical_session(
              sessions, "0::/user.slice/user-1000.slice/session-9.scope\n",
              1000) == 0,
          "a session logind does not list stays in place");

    write_session("3", "1000", "tty", "user", "active");
    check(console_test_graphical_session(
              sessions, "0::/user.slice/user-1000.slice/session-3.scope\n",
              1000) == 0,
          "an SSH or console login stays in place");

    write_session("6", "1001", "x11", "user", "online");
    check(console_test_graphical_session(sessions, desktop_cgroup, 1000) == 0,
          "with another user's desktop open, the restore stays in place");
    check(console_test_graphical_session(
              sessions, "0::/user.slice/user-1000.slice/user@1000.service/"
                        "app.slice/ptyxis-spawn-1.scope\n", 1000) == 0,
          "so does one from a terminal the service manager started");

    remove_session("2");
    check(console_test_graphical_session(
              sessions, "0::/user.slice/user-1000.slice/user@1000.service/"
                        "app.slice/ptyxis-spawn-1.scope\n", 1000) == 0,
          "without a desktop of the invoker's own, the restore stays in place");
    remove_session("2.ref");
    remove_session("c1");
    remove_session("5");
    remove_session("3");
    remove_session("6");
    if (rmdir(sessions) != 0)
        fixture_fatal("fixture: rmdir");
}

static void test_free_vt(void)
{
    printf(BLUE "::" NC " the console is the first free one above the gettys\n");
    check(console_test_free_vt(0) == 7,
          "with nothing open, tty7");
    check(console_test_free_vt((1U << 1) | (1U << 2) | (1U << 7)) == 8,
          "a display manager on tty7 moves it to tty8");
    check(console_test_free_vt(0xff80) == 0,
          "with tty7 to tty15 open, there is none");
}

static void test_escape(void)
{
    printf(BLUE "::" NC " a source path reaches the service as written\n");
    char out[64];
    check(console_test_escape("/run/media/u/A$B ${HOME}", out,
                              sizeof(out)) == 0 &&
              strcmp(out, "/run/media/u/A$$B $${HOME}") == 0,
          "each $ is doubled so systemd expands nothing");
    char small[4];
    errno = 0;
    check(console_test_escape("a$b", small, sizeof(small)) == -1 &&
              errno == ENAMETOOLONG,
          "a path that does not fit is refused");
}

int main(void)
{
    test_graphical_session();
    test_free_vt();
    test_escape();

    if (failures == 0)
        printf(GREEN "console tests passed" NC "\n");
    else
        printf(RED "console tests: %d failure(s)" NC "\n", failures);
    return failures == 0 ? 0 : 1;
}

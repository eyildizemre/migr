#define _GNU_SOURCE
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fileops.h"

char *backup_test_collect_vscode_extensions(void);

static int failures;
static int skips;

static void check(int condition, const char *label)
{
    if (condition)
        printf("  ok: %s\n", label);
    else
    {
        printf("  FAIL: %s\n", label);
        failures++;
    }
}

static void skip_case(const char *label, const char *reason)
{
    printf("  - %s skipped: %s\n", label, reason);
    skips++;
}

static int parse_passwd_id(const char *text, uintmax_t *value)
{
    if (text == NULL || text[0] == '\0')
        return -1;
    uintmax_t parsed = 0;
    for (const unsigned char *p = (const unsigned char *)text;
         *p != '\0'; p++)
    {
        if (*p < '0' || *p > '9')
            return -1;
        unsigned int digit = (unsigned int)(*p - '0');
        if (parsed > (UINTMAX_MAX - digit) / 10U)
            return -1;
        parsed = parsed * 10U + digit;
    }
    *value = parsed;
    return 0;
}

static int find_local_unprivileged_identity(uid_t *uid_out, gid_t *gid_out,
                                            char home_out[PATH_MAX])
{
    FILE *passwd = fopen("/etc/passwd", "r");
    if (passwd == NULL)
        return 0;

    char *line = NULL;
    size_t capacity = 0;
    int found = 0;
    while (getline(&line, &capacity, passwd) >= 0)
    {
        char *fields[7] = { line, NULL, NULL, NULL, NULL, NULL, NULL };
        size_t colons = 0;
        for (char *p = line; *p != '\0'; p++)
        {
            if (*p != ':')
                continue;
            *p = '\0';
            if (colons < 6U)
                fields[colons + 1U] = p + 1;
            colons++;
        }
        if (colons != 6U || fields[5] == NULL || fields[5][0] != '/' ||
            strlen(fields[5]) >= PATH_MAX)
            continue;

        uintmax_t uid_value;
        uintmax_t gid_value;
        if (parse_passwd_id(fields[2], &uid_value) != 0 || uid_value == 0U ||
            parse_passwd_id(fields[3], &gid_value) != 0)
            continue;

        uid_t uid = (uid_t)uid_value;
        gid_t gid = (gid_t)gid_value;
        if ((uintmax_t)uid != uid_value || uid == (uid_t)-1 ||
            (uintmax_t)gid != gid_value || gid == (gid_t)-1)
            continue;

        *uid_out = uid;
        *gid_out = gid;
        memcpy(home_out, fields[5], strlen(fields[5]) + 1U);
        found = 1;
        break;
    }

    free(line);
    fclose(passwd);
    return found;
}

#define UNSET_SENTINEL "<unset>"
#define CALLER_HOME "/migr-test-caller-home"
#define CALLER_XDG_CONFIG "/migr-test-caller-home/.config-override"

static const char *env_or_unset(const char *name)
{
    const char *value = getenv(name);
    return value != NULL ? value : UNSET_SENTINEL;
}

static int matches_child(const char *output, uid_t uid, gid_t gid,
                         const char *home, const char *xdg_config_home)
{
    char expected[PATH_MAX * 2 + 64];
    int length = snprintf(expected, sizeof(expected), "%ju %ju %s %s\n",
                          (uintmax_t)uid, (uintmax_t)gid, home,
                          xdg_config_home);
    return length > 0 && (size_t)length < sizeof(expected) &&
           strcmp(output, expected) == 0;
}

static char *collect_and_check_plain_identity(const char *label,
                                             uid_t uid, gid_t gid)
{
    char *output = backup_test_collect_vscode_extensions();
    check(output != NULL &&
              matches_child(output, uid, gid, CALLER_HOME, CALLER_XDG_CONFIG),
          label);
    return output;
}

static int env_equals(char **env, const char *const *expected)
{
    size_t i = 0;
    for (; expected[i] != NULL; i++)
    {
        if (env[i] == NULL || strcmp(env[i], expected[i]) != 0)
            return 0;
    }
    return env[i] == NULL;
}

static void test_identity_environment(void)
{
    char *const base[] = {
        "PATH=/usr/bin", "HOME=/root", "HOMEDIR=/keep",
        "XDG_CONFIG_HOME=/root/.config", "XDG_CONFIG_HOME_X=/keep",
        "XDG_DATA_HOME=/root/.local/share", "XDG_CACHE_HOME=/root/.cache",
        "XDG_STATE_HOME=/root/.local/state", "XDG_RUNTIME_DIR=/run/user/1000",
        "LANG=C.UTF-8", NULL
    };
    const char *const expected[] = {
        "PATH=/usr/bin", "HOMEDIR=/keep", "XDG_CONFIG_HOME_X=/keep",
        "XDG_RUNTIME_DIR=/run/user/1000", "LANG=C.UTF-8",
        "HOME=/home/target", NULL
    };
    char *home_entry = NULL;
    char **env = fileops_test_build_identity_environment(
        base, "/home/target", &home_entry);
    check(env != NULL && env_equals(env, expected),
          "identity environment replaces HOME, drops XDG base-dir overrides, "
          "and keeps other entries in order");
    free(home_entry);
    free(env);

    char *const base_without_home[] = { "PATH=/usr/bin", NULL };
    const char *const expected_added[] = {
        "PATH=/usr/bin", "HOME=/home/target", NULL
    };
    home_entry = NULL;
    env = fileops_test_build_identity_environment(
        base_without_home, "/home/target", &home_entry);
    check(env != NULL && env_equals(env, expected_added),
          "identity environment adds HOME when the caller has none");
    free(home_entry);
    free(env);

    home_entry = NULL;
    check(fileops_test_build_identity_environment(
              base, "relative/home", &home_entry) == NULL &&
              home_entry == NULL,
          "identity environment rejects a non-absolute home");
    check(fileops_test_build_identity_environment(
              base, NULL, &home_entry) == NULL && home_entry == NULL,
          "identity environment rejects a missing home");
}

int main(int argc, char *argv[])
{
    if (argc == 3 && strcmp(argv[0], "code") == 0 &&
        strcmp(argv[1], "--list-extensions") == 0 &&
        strcmp(argv[2], "--show-versions") == 0)
    {
        printf("%ju %ju %s %s\n", (uintmax_t)getuid(), (uintmax_t)getgid(),
               env_or_unset("HOME"), env_or_unset("XDG_CONFIG_HOME"));
        return 0;
    }

    char fixture_dir[] = "/tmp/migr-vscode-capture-XXXXXX";
    if (mkdtemp(fixture_dir) == NULL)
    {
        perror("mkdtemp vscode fixture");
        return 1;
    }

    char code_path[PATH_MAX];
    if (snprintf(code_path, sizeof(code_path), "%s/code", fixture_dir) >=
            (int)sizeof(code_path) ||
        chmod(fixture_dir, 0755) != 0 ||
        symlink("/proc/self/exe", code_path) != 0)
    {
        perror("prepare vscode command fixture");
        rmdir(fixture_dir);
        return 1;
    }

    const char *old_path_value = getenv("PATH");
    char *old_path = old_path_value != NULL ? strdup(old_path_value) : NULL;
    if (setenv("PATH", fixture_dir, 1) != 0)
    {
        perror("setenv PATH");
        unlink(code_path);
        rmdir(fixture_dir);
        free(old_path);
        return 1;
    }

    test_identity_environment();

    if (setenv("HOME", CALLER_HOME, 1) != 0 ||
        setenv("XDG_CONFIG_HOME", CALLER_XDG_CONFIG, 1) != 0)
    {
        perror("setenv caller HOME/XDG_CONFIG_HOME");
        unlink(code_path);
        rmdir(fixture_dir);
        free(old_path);
        return 1;
    }

    uid_t invoking_uid = getuid();
    gid_t invoking_gid = getgid();
    unsetenv("SUDO_UID");
    char *output = collect_and_check_plain_identity(
        "without SUDO_UID, VS Code capture keeps the invoking identity",
        invoking_uid, invoking_gid);
    free(output);

    uid_t target_uid = (uid_t)-1;
    gid_t target_gid = (gid_t)-1;
    char target_home[PATH_MAX] = {0};
    int have_target = find_local_unprivileged_identity(&target_uid,
                                                        &target_gid,
                                                        target_home);
    char *const command[] = {
        "code", "--list-extensions", "--show-versions", NULL
    };

    char untouched_output[] = "untouched";
    check(run_command_capture_as_identity(
              command, untouched_output, sizeof(untouched_output),
              invoking_uid, invoking_gid, NULL) == -1 &&
              run_command_capture_as_identity(
                  command, untouched_output, sizeof(untouched_output),
                  invoking_uid, invoking_gid, "relative/home") == -1 &&
              strcmp(untouched_output, "untouched") == 0,
          "identity capture without an absolute home fails before forking");

    if (geteuid() != 0)
    {
        check(setenv("SUDO_UID", "0", 1) == 0,
              "set inherited SUDO_UID for unprivileged regression");
        output = collect_and_check_plain_identity(
            "non-root capture ignores SUDO_UID and does not drop identity",
            invoking_uid, invoking_gid);
        free(output);

        char failure_output[128] = "must be cleared";
        int failure_status = run_command_capture_as_identity(
            command, failure_output, sizeof(failure_output), (uid_t)-1,
            (gid_t)-1, "/home/target");
        check(failure_status >= 125 && failure_status <= 127 &&
                  failure_output[0] == '\0',
              "invalid target identity exits before the command can execute");
        skip_case("root-only successful identity drop and sudo selection",
                  "the test process is not running as root");
    }
    else if (!have_target)
    {
        skip_case("root-only successful identity drop and sudo selection",
                  "no non-root local passwd identity with a valid gid was found");
        unsetenv("SUDO_UID");
        output = collect_and_check_plain_identity(
            "root without SUDO_UID keeps the existing capture path",
            invoking_uid, invoking_gid);
        free(output);
    }
    else
    {
        char uid_text[32];
        snprintf(uid_text, sizeof(uid_text), "%ju", (uintmax_t)target_uid);
        check(setenv("SUDO_UID", uid_text, 1) == 0,
              "set SUDO_UID to a local non-root identity");

        char probe_output[128] = {0};
        int probe_status = run_command_capture_as_identity(
            command, probe_output, sizeof(probe_output), target_uid, target_gid,
            target_home);
        if (probe_status >= 125 && probe_status <= 127)
        {
            skip_case("root child drop to the SUDO_UID account",
                      "the root test process cannot complete the identity drop");
            skip_case("root child fail-closed case",
                      "the root test process cannot complete the identity drop");
        }
        else
        {
            check(probe_status == 0 &&
                      matches_child(probe_output, target_uid, target_gid,
                                    target_home, UNSET_SENTINEL),
                  "capture child runs with the target uid, primary gid, and "
                  "home, without the caller's XDG_CONFIG_HOME");

            output = backup_test_collect_vscode_extensions();
            check(output != NULL &&
                      matches_child(output, target_uid, target_gid,
                                    target_home, UNSET_SENTINEL),
                  "sudo VS Code capture resolves and uses the local account "
                  "identity and home");
            free(output);

            char failure_output[128] = "must be cleared";
            int failure_status = run_command_capture_as_identity(
                command, failure_output, sizeof(failure_output), target_uid,
                (gid_t)-1, target_home);
            check(failure_status == 126 && failure_output[0] == '\0',
                  "failed setgid exits before the command can execute");
        }

        check(setenv("SUDO_UID", "invalid", 1) == 0,
              "set malformed SUDO_UID to verify best-effort fallback");
        output = collect_and_check_plain_identity(
            "unresolvable SUDO_UID falls back to the existing capture path",
            invoking_uid, invoking_gid);
        free(output);
    }

    if (old_path != NULL)
    {
        if (setenv("PATH", old_path, 1) != 0)
            perror("restore PATH");
    }
    else
    {
        unsetenv("PATH");
    }
    free(old_path);
    unlink(code_path);
    rmdir(fixture_dir);

    if (skips != 0)
        printf("%d VS Code capture case(s) skipped\n", skips);
    if (failures != 0)
    {
        printf("%d VS Code capture test(s) failed\n", failures);
        return 1;
    }
    return 0;
}

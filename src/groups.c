#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "groups.h"
#include "packages.h"
#include "packages_internal.h"
#include "utils.h"

#ifdef GROUPS_TEST_HOOKS
static const char *groups_test_group_file;

void groups_test_set_group_file(const char *path)
{
    groups_test_group_file = path;
}
#endif

static const char *group_file_path(void)
{
#ifdef GROUPS_TEST_HOOKS
    if (groups_test_group_file != NULL)
        return groups_test_group_file;
#endif
    return "/etc/group";
}

// Group names as useradd accepts them. Anything else in a restored list is
// skipped, so it can neither become a usermod option nor split the
// comma-separated group argument.
static int group_name_is_safe(const char *name)
{
    size_t length = strlen(name);
    return length != 0 && length < ACCOUNT_NAME_MAX && name[0] != '-' &&
           strspn(name, "abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") == length;
}

// Splits one group file line in place into its name, gid, and member list.
// Returns -1 for a line that is not name:password:gid:members.
static int group_line_split(char *line, char **name, gid_t *gid,
                            char **members)
{
    line[strcspn(line, "\n")] = '\0';
    char *password = strchr(line, ':');
    char *gid_field = password != NULL ? strchr(password + 1, ':') : NULL;
    char *list = gid_field != NULL ? strchr(gid_field + 1, ':') : NULL;
    if (list == NULL || strchr(list + 1, ':') != NULL)
        return -1;
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(gid_field + 1, &end, 10);
    if (errno != 0 || end == gid_field + 1 || end != list ||
        (unsigned long)(gid_t)value != value || (gid_t)value == (gid_t)-1)
        return -1;
    *password = '\0';
    *name = line;
    *gid = (gid_t)value;
    *members = list + 1;
    return 0;
}

typedef int (*GroupLineCallback)(const char *name, gid_t gid,
                                 const char *members, void *context);

// Calls line_callback for every well-formed line of the local group file,
// read without NSS as D38 reads accounts, until it returns nonzero. Returns
// -1 when the file cannot be read or line_callback returns -1.
static int group_file_foreach(GroupLineCallback line_callback, void *context)
{
    FILE *groups = fopen(group_file_path(), "re");
    if (groups == NULL)
        return -1;
    char *line = NULL;
    size_t capacity = 0;
    int stop = 0;
    while (stop == 0 && getline(&line, &capacity, groups) >= 0)
    {
        char *name;
        gid_t gid;
        char *members;
        if (group_line_split(line, &name, &gid, &members) == 0)
            stop = line_callback(name, gid, members, context);
    }
    int failed = stop < 0 || ferror(groups) != 0;
    free(line);
    fclose(groups);
    return failed ? -1 : 0;
}

static int group_members_include(const char *members, const char *user)
{
    size_t user_length = strlen(user);
    for (const char *member = members; *member != '\0';)
    {
        size_t length = strcspn(member, ",");
        if (length == user_length && memcmp(member, user, length) == 0)
            return 1;
        member += length;
        if (*member == ',')
            member++;
    }
    return 0;
}

typedef struct {
    const char *user;
    FILE *out;
} GroupCollect;

static int collect_group(const char *name, gid_t gid, const char *members,
                         void *context)
{
    (void)gid;
    const GroupCollect *collect = context;
    if (!group_name_is_safe(name) ||
        !group_members_include(members, collect->user))
        return 0;
    return fprintf(collect->out, "%s\n", name) < 0 ? -1 : 0;
}

char *groups_collect(const char *user)
{
    char *list = NULL;
    size_t list_size = 0;
    GroupCollect collect = { user, open_memstream(&list, &list_size) };
    if (collect.out == NULL)
        return NULL;
    int failed = group_file_foreach(collect_group, &collect) != 0;
    failed |= fclose(collect.out) != 0;
    if (failed)
    {
        free(list);
        return NULL;
    }
    return list;
}

typedef struct {
    const char *name;
    gid_t gid;
    int matches;
} GroupLookup;

static int lookup_group(const char *name, gid_t gid, const char *members,
                        void *context)
{
    (void)members;
    GroupLookup *lookup = context;
    if (strcmp(name, lookup->name) == 0)
    {
        lookup->gid = gid;
        lookup->matches++;
    }
    return 0;
}

int local_group_gid(const char *name, gid_t *gid)
{
    GroupLookup lookup = { name, 0, 0 };
    if (group_file_foreach(lookup_group, &lookup) != 0 || lookup.matches != 1)
        return -1;
    *gid = lookup.gid;
    return 0;
}

static void print_group_names(char **names, const int *pick, int count)
{
    const char *separator = "";
    for (int i = 0; i < count; i++)
    {
        if (!pick[i])
            continue;
        printf("%s%s", separator, names[i]);
        separator = ", ";
    }
}

// Joins the picked names with commas, as usermod -G takes them.
static char *join_group_names(char **names, const int *pick, int count)
{
    size_t size = 1;
    for (int i = 0; i < count; i++)
        if (pick[i])
            size += strlen(names[i]) + 1U;
    char *joined = malloc(size);
    if (joined == NULL)
        return NULL;
    joined[0] = '\0';
    for (int i = 0; i < count; i++)
    {
        if (!pick[i])
            continue;
        if (joined[0] != '\0')
            strcat(joined, ",");
        strcat(joined, names[i]);
    }
    return joined;
}

typedef struct {
    char **names;
    int count;
    const char *user;
    int *wanted;
    int *missing;
} GroupMatch;

static int match_group(const char *name, gid_t gid, const char *members,
                       void *context)
{
    (void)gid;
    GroupMatch *match = context;
    for (int i = 0; i < match->count; i++)
    {
        if (!match->missing[i] || strcmp(match->names[i], name) != 0)
            continue;
        match->missing[i] = 0;
        match->wanted[i] = !group_members_include(members, match->user);
    }
    return 0;
}

void restore_groups(int source_root_fd, const char *user, FILE *todo,
                    int *had_error)
{
    FILE *list = NULL;
    if (package_open_control_file(source_root_fd, "groups.txt", &list, had_error) !=
        CONTROL_FILE_OPEN)
        return;

    printf("\nGroups\n");
    char **names = NULL;
    int count = 0;
    read_package_list(list, &names, &count, had_error);
    fclose(list);

    int *wanted = NULL;
    int *missing = NULL;
    if (count == 0)
    {
        printf("  The backup saved no group memberships.\n");
        goto done;
    }
    wanted = calloc((size_t)count, sizeof(*wanted));
    missing = calloc((size_t)count, sizeof(*missing));
    if (user == NULL || wanted == NULL || missing == NULL)
    {
        print_error("Error: Could not match the saved group memberships "
                    "against this system\n");
        *had_error = 1;
        goto done;
    }

    // A recorded group is missing until the group file has it, and wanted
    // when it does and does not list the user yet.
    for (int i = 0; i < count; i++)
        missing[i] = group_name_is_safe(names[i]);
    GroupMatch match = { names, count, user, wanted, missing };
    if (group_file_foreach(match_group, &match) != 0)
    {
        print_error("Error: Could not read %s\n", group_file_path());
        *had_error = 1;
        goto done;
    }

    int wanted_count = 0;
    int missing_count = 0;
    for (int i = 0; i < count; i++)
    {
        wanted_count += wanted[i];
        missing_count += missing[i];
    }

    if (wanted_count == 0)
        printf("  %s is already in every saved group this system has.\n",
               user);
    else if (dry_run)
    {
        printf("  Would add %s to ", user);
        print_group_names(names, wanted, count);
        printf(".\n");
    }
    else
    {
        char *joined = join_group_names(names, wanted, count);
        if (joined == NULL)
        {
            print_error("Error: Could not allocate the group list\n");
            *had_error = 1;
            goto done;
        }
        char *argv[] = {
            "usermod", "-a", "-G", joined, "--", (char *)user, NULL
        };
        int status = package_run_command(argv);
        free(joined);
        if (status != 0)
        {
            print_error("Error: Could not add %s to the saved groups "
                        "(usermod exited with %d)\n", user, status);
            *had_error = 1;
            goto done;
        }
        printf("  Added %s to ", user);
        print_group_names(names, wanted, count);
        printf(". This takes effect at the next login.\n");
    }

    if (missing_count != 0)
    {
        printf("  Left out, not on this system: ");
        print_group_names(names, missing, count);
        printf(".\n");
        char *joined = join_group_names(names, missing, count);
        if (joined != NULL)
            fprintf(todo, "  Groups this system does not have; once the "
                          "software that brings them is installed, run:\n"
                          "    sudo usermod -a -G %s %s\n", joined, user);
        free(joined);
    }

done:
    free(wanted);
    free(missing);
    package_free_name_list(names, count);
}


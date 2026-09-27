#ifndef GROUPS_H
#define GROUPS_H

#include <stdio.h>
#include <sys/types.h>

#ifdef GROUPS_TEST_HOOKS
/* Replaces /etc/group; NULL restores it. */
void groups_test_set_group_file(const char *path);
#endif

/**
 * @brief Lists the groups whose member list in /etc/group names user, one
 *        name per line.
 *
 * These are the user's supplementary memberships, by name since GIDs differ
 * between installs. The file is read directly, without NSS, as D38 reads
 * accounts: a directory service's groups are not the install's. Names a
 * restore would not accept are left out.
 *
 * @return A heap string, empty when user is in no group; NULL when the file
 *         cannot be read.
 */
char *groups_collect(const char *user);

/**
 * @brief Looks a group's gid up in /etc/group, read the same way.
 *
 * @return 0, or -1 when the group is absent, listed twice, or the file cannot
 *         be read.
 */
int local_group_gid(const char *name, gid_t *gid);

/**
 * @brief Adds user to the groups a restored groups.txt lists.
 *
 * Runs after restore_packages(), since packages create groups (the libvirt
 * package creates libvirt). Groups this system has and user is not yet in
 * are added with one usermod; groups it lacks are listed, with the command
 * to add them later, and never created, since one comes with software that
 * would give it a system GID. An absent groups.txt is skipped silently. A
 * dry run only says what it would add.
 *
 * @param user      Login name to add; NULL when it could not be resolved,
 *                  which fails the step if there is anything to add.
 * @param had_error Set to 1 on a real failure; untouched otherwise.
 */
void restore_groups(int source_root_fd, const char *user, FILE *todo,
                    int *had_error);

#endif

#ifndef MIGR_PACKAGES_INTERNAL_H
#define MIGR_PACKAGES_INTERNAL_H

#include <stdio.h>

/* Shared by the restore steps in packages.c, groups.c, and flatpak.c. */

enum { PACKAGE_QUERY_BUFFER_SIZE = 5 * 1024 * 1024 };

enum { CONTROL_FILE_OPEN, CONTROL_FILE_ABSENT, CONTROL_FILE_UNUSABLE };

/* Opens a list at the container root as *out; returns a CONTROL_FILE_ value.
 * Sets *had_error when the list is there but cannot be read. */
int package_open_control_file(int source_root_fd, const char *leaf,
                              FILE **out, int *had_error);
void package_free_name_list(char **names, int count);

/* run_command() and run_command_capture(), or the test hooks in their place. */
int package_run_command(char *const argv[]);
/* Prints line and runs an install command without its progress output; on a
 * terminal the time it has taken follows line. What the command reports as
 * errors is shown only when it fails. Returns its exit status. */
int package_install_command(char *const argv[], const char *line);
int package_capture_command(char *const argv[], char *output,
                            size_t output_size);

/* The output of argv in a heap buffer, or NULL with an error printed and
 * *had_error set. */
char *package_capture_query(char *const argv[], const char *label,
                            int *had_error);

/* Nonzero when list has a line that is exactly name. */
int package_plain_list_contains(const char *list, const char *name);

#endif

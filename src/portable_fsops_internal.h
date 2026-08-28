#ifndef MIGR_PORTABLE_FSOPS_INTERNAL_H
#define MIGR_PORTABLE_FSOPS_INTERNAL_H

#include <stddef.h>

/* Shared between portable.c and portable_fsops.c only. */

/* portable.c -- needed by portable_fsops.c. */
size_t bounded_strlen(const char *value, size_t maximum);
int copy_text(char *destination, size_t destination_size,
             const char *source);
int safe_component(const char *component);
int safe_relative_path(const char *path);

/* portable_fsops.c -- needed by portable.c. */
int append_logical(char *destination, size_t destination_size,
                   const char *parent, const char *name);
int append_physical(char *destination, size_t destination_size,
                    const char *parent, const char *encoded_leaf);
int open_child_directory(int parent_fd, const char *name);
int remove_directory_tree(int parent_fd, const char *name);
int remove_leaf(int parent_fd, const char *name);
int open_existing_payload_parent(int data_fd, const char *relative,
                                 int *parent_out, char *leaf,
                                 size_t leaf_size);
int ensure_directory_leaf(int parent_fd, const char *leaf, int *out_fd);
int ensure_regular_leaf(int parent_fd, const char *leaf, int *out_fd);

#endif

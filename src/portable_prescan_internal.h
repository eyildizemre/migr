#ifndef MIGR_PORTABLE_PRESCAN_INTERNAL_H
#define MIGR_PORTABLE_PRESCAN_INTERNAL_H

#include <stddef.h>
#include <sys/stat.h>

#include "portable.h"

/* Shared between portable.c and portable_prescan.c only. */

/* portable.c -- needed by portable_prescan.c. */
int append_physical(char *destination, size_t destination_size,
                    const char *parent, const char *encoded_leaf);
int append_logical(char *destination, size_t destination_size,
                   const char *parent, const char *name);
size_t bounded_strlen(const char *value, size_t maximum);
int copy_text(char *destination, size_t destination_size,
             const char *source);
int open_child_directory(int parent_fd, const char *name);
int open_source_node(int source_parent, const char *source_name,
                     const char *root_path, const struct stat *st);
int read_source_stat(int source_parent, const char *source_name,
                     const char *root_path, struct stat *out);
int remove_directory_tree(int parent_fd, const char *name);
int root_spec_valid(const PortableRootSpec *root);
int safe_component(const char *component);
int safe_relative_path(const char *path);
void case_probe_count(void);
void case_fs_probe_count(void);

/* portable_prescan.c -- needed by portable.c. */
int prescan_request(int container_fd,
                    const PortableCaptureRequest *request,
                    PortablePrescanReport *report);
const PortableRootSpec *portable_collision_plan_root(
    const PortableCaptureRequest *request, const char *root_id);
void skeleton_copy(char *destination, size_t destination_size,
                   const char *source);

#endif

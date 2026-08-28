#define _GNU_SOURCE

#include "metadata.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

typedef struct {
    int fd;
    const char *path;
} MetadataXattrTarget;

static int metadata_xattr_unsupported_errno(int value)
{
    return value == ENOTSUP || value == EOPNOTSUPP || value == ENODATA;
}

static ssize_t metadata_xattr_list(const MetadataXattrTarget *target,
                                   char *names, size_t size)
{
    if (target == NULL)
        return -1;
    if (target->fd >= 0)
        return flistxattr(target->fd, names, size);
    if (target->path != NULL)
        return llistxattr(target->path, names, size);
    errno = EINVAL;
    return -1;
}

static int metadata_xattr_remove(const MetadataXattrTarget *target,
                                 const char *name)
{
    if (target == NULL || name == NULL)
        return -1;
    if (target->fd >= 0)
        return fremovexattr(target->fd, name);
    if (target->path != NULL)
        return lremovexattr(target->path, name);
    errno = EINVAL;
    return -1;
}

static int metadata_xattr_set(const MetadataXattrTarget *target,
                              const char *name, const void *value,
                              size_t value_length)
{
    if (target == NULL || name == NULL || (value == NULL && value_length != 0))
        return -1;
    if (target->fd >= 0)
        return fsetxattr(target->fd, name, value, value_length, 0);
    if (target->path != NULL)
        return lsetxattr(target->path, name, value, value_length, 0);
    errno = EINVAL;
    return -1;
}

static int metadata_xattr_input_valid(const SidecarXattr *xattrs, size_t count)
{
    if (count > SIDECAR_MAX_XATTRS_PER_ENTRY ||
        (count != 0 && xattrs == NULL))
        return -1;

    for (size_t index = 0; index < count; index++)
    {
        const SidecarXattr *current = &xattrs[index];
        if (current->name.data == NULL || current->name.length == 0 ||
            current->name.length > SIDECAR_MAX_XATTR_NAME ||
            memchr(current->name.data, '\0', current->name.length) != NULL ||
            current->value.length > SIDECAR_MAX_XATTR_VALUE ||
            (current->value.length != 0 && current->value.data == NULL))
            return -1;
        for (size_t previous = 0; previous < index; previous++)
            if (xattrs[previous].name.length == current->name.length &&
                memcmp(xattrs[previous].name.data, current->name.data,
                       current->name.length) == 0)
                return -1;
    }
    return 0;
}

static int metadata_xattr_names_valid(const char *names, size_t length,
                                      size_t *count)
{
    if ((length != 0 && names == NULL) || count == NULL)
        return -1;

    size_t found = 0;
    size_t offset = 0;
    while (offset < length)
    {
        size_t name_length = strnlen(names + offset, length - offset);
        if (name_length == 0 || name_length > SIDECAR_MAX_XATTR_NAME ||
            name_length == length - offset ||
            found == SIDECAR_MAX_XATTRS_PER_ENTRY)
            return -1;
        found++;
        offset += name_length + 1U;
    }
    *count = found;
    return 0;
}

static int metadata_xattr_names_read(const MetadataXattrTarget *target,
                                     char **out_names, size_t *out_count)
{
    if (target == NULL || out_names == NULL || out_count == NULL)
        return -1;
    *out_names = NULL;
    *out_count = 0;

    errno = 0;
    ssize_t required = metadata_xattr_list(target, NULL, 0);
    if (required < 0)
    {
        if (metadata_xattr_unsupported_errno(errno))
            return 0;
        return -1;
    }
    if ((uintmax_t)required >
        (uintmax_t)SIDECAR_MAX_XATTRS_PER_ENTRY *
            (uintmax_t)(SIDECAR_MAX_XATTR_NAME + 1U))
        return -1;
    if (required == 0)
        return 0;

    char *names = malloc((size_t)required);
    if (names == NULL)
        return -1;
    ssize_t received = metadata_xattr_list(target, names, (size_t)required);
    if (received != required || metadata_xattr_names_valid(
                                    names, (size_t)received, out_count) != 0)
    {
        free(names);
        return -1;
    }
    *out_names = names;
    return 0;
}

unsigned int metadata_xattr_namespace_bytes(const unsigned char *name,
                                            size_t length)
{
    static const struct {
        const char *prefix;
        size_t prefix_length;
        unsigned int bit;
    } prefixes[] = {
        { "user.", 5, METADATA_XATTR_NS_USER },
        { "security.", 9, METADATA_XATTR_NS_SECURITY },
        { "system.", 7, METADATA_XATTR_NS_SYSTEM },
        { "trusted.", 8, METADATA_XATTR_NS_TRUSTED }
    };
    if (name == NULL)
        return 0;
    for (size_t index = 0;
         index < sizeof(prefixes) / sizeof(prefixes[0]); index++)
        if (length >= prefixes[index].prefix_length &&
            memcmp(name, prefixes[index].prefix,
                   prefixes[index].prefix_length) == 0)
            return prefixes[index].bit;
    return 0;
}

static unsigned int metadata_xattr_namespace(const char *name)
{
    if (name == NULL)
        return 0;
    return metadata_xattr_namespace_bytes((const unsigned char *)name,
                                          strlen(name));
}

static int metadata_xattr_namespaces_target(const MetadataXattrTarget *target,
                                            unsigned int *out)
{
    if (target == NULL || out == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    *out = 0;
    char *names = NULL;
    size_t count = 0;
    if (metadata_xattr_names_read(target, &names, &count) != 0)
        return -1;

    size_t offset = 0;
    for (size_t index = 0; index < count; index++)
    {
        const char *name = names + offset;
        *out |= metadata_xattr_namespace(name);
        offset += strlen(name) + 1U;
    }
    free(names);
    return 0;
}

int metadata_xattr_namespaces_fd(int fd, unsigned int *out)
{
    if (fd < 0)
    {
        errno = EINVAL;
        return -1;
    }
    MetadataXattrTarget target = { .fd = fd, .path = NULL };
    return metadata_xattr_namespaces_target(&target, out);
}

int metadata_xattr_namespaces_path(const char *path, unsigned int *out)
{
    if (path == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    MetadataXattrTarget target = { .fd = -1, .path = path };
    return metadata_xattr_namespaces_target(&target, out);
}

static int metadata_xattr_input_contains(const SidecarXattr *xattrs,
                                         size_t count, const char *name)
{
    size_t name_length = strlen(name);
    for (size_t index = 0; index < count; index++)
        if (xattrs[index].name.length == name_length &&
            memcmp(xattrs[index].name.data, name, name_length) == 0)
            return 1;
    return 0;
}

static int metadata_apply_xattrs_target(const MetadataXattrTarget *target,
                                        const SidecarXattr *xattrs,
                                        size_t count,
                                        size_t *skipped_security_count)
{
    if (skipped_security_count != NULL)
        *skipped_security_count = 0;
    if (target == NULL ||
        metadata_xattr_input_valid(xattrs, count) != 0)
        return -1;

    char *existing_names = NULL;
    size_t existing_count = 0;
    if (metadata_xattr_names_read(target, &existing_names,
                                  &existing_count) != 0)
        return -1;

    size_t offset = 0;
    for (size_t index = 0; index < existing_count; index++)
    {
        char *name = existing_names + offset;
        size_t name_length = strlen(name);
        if (!metadata_xattr_input_contains(xattrs, count, name))
        {
            if (metadata_xattr_remove(target, name) != 0)
            {
                /*
                 * ENODATA means it's already gone -- idempotent success.
                 * security.* additionally tolerates EACCES/EPERM: the
                 * destination's LSM (SELinux/AppArmor) auto-assigns this
                 * namespace's values, and an unprivileged caller predictably
                 * can't remove one (mirrors the capability probe's own
                 * security.* rationale). A privileged caller that genuinely
                 * can remove a stale security.* attribute still does --
                 * this only tolerates the failure, it doesn't skip the
                 * attempt, so E-8's exact-set guarantee still holds
                 * wherever it's actually achievable.
                 */
                int tolerated = errno == ENODATA ||
                    (metadata_xattr_namespace(name) ==
                         METADATA_XATTR_NS_SECURITY &&
                     (errno == EACCES || errno == EPERM));
                if (tolerated && errno != ENODATA &&
                    skipped_security_count != NULL &&
                    *skipped_security_count != SIZE_MAX)
                    (*skipped_security_count)++;
                if (!tolerated)
                {
                    free(existing_names);
                    return -1;
                }
            }
        }
        offset += name_length + 1U;
    }

    for (size_t index = 0; index < count; index++)
    {
        const SidecarXattr *current = &xattrs[index];
        char *name = malloc(current->name.length + 1U);
        if (name == NULL)
        {
            free(existing_names);
            return -1;
        }
        memcpy(name, current->name.data, current->name.length);
        name[current->name.length] = '\0';

        static const unsigned char empty_value;
        const void *value = current->value.length == 0 ? &empty_value :
                                                         current->value.data;
        int failed = metadata_xattr_set(target, name, value,
                                        current->value.length);
        int tolerated = failed != 0 &&
            metadata_xattr_namespace(name) == METADATA_XATTR_NS_SECURITY &&
            (errno == EACCES || errno == EPERM);
        if (tolerated && skipped_security_count != NULL &&
            *skipped_security_count != SIZE_MAX)
            (*skipped_security_count)++;
        free(name);
        if (failed != 0)
        {
            if (!tolerated)
            {
                free(existing_names);
                return -1;
            }
        }
    }
    free(existing_names);
    return 0;
}

static int metadata_safe_xattr_component(const char *component)
{
    if (component == NULL || component[0] == '\0' ||
        strcmp(component, ".") == 0 || strcmp(component, "..") == 0 ||
        strchr(component, '/') != NULL || strlen(component) > NAME_MAX)
        return 0;
    return 1;
}

int metadata_symlink_xattr_path(int dir_fd, const char *leaf,
                                char *path, size_t path_size)
{
    if (dir_fd < 0 || path == NULL || path_size == 0 ||
        !metadata_safe_xattr_component(leaf))
        return -1;
    int length = snprintf(path, path_size, "/proc/self/fd/%d/%s", dir_fd,
                          leaf);
    return length < 0 || (size_t)length >= path_size ? -1 : 0;
}

int metadata_apply_xattrs_fd(int fd, const SidecarXattr *xattrs, size_t count)
{
    return metadata_apply_xattrs_fd_report(fd, xattrs, count, NULL);
}

int metadata_apply_xattrs_fd_report(int fd, const SidecarXattr *xattrs,
                                    size_t count,
                                    size_t *skipped_security_count)
{
    MetadataXattrTarget target = { .fd = fd, .path = NULL };
    return metadata_apply_xattrs_target(&target, xattrs, count,
                                        skipped_security_count);
}

int metadata_apply_xattrs_symlink_at(int dir_fd, const char *leaf,
                                     const SidecarXattr *xattrs, size_t count)
{
    return metadata_apply_xattrs_symlink_at_report(dir_fd, leaf, xattrs,
                                                   count, NULL);
}

int metadata_apply_xattrs_symlink_at_report(
    int dir_fd, const char *leaf, const SidecarXattr *xattrs, size_t count,
    size_t *skipped_security_count)
{
    char path[PATH_MAX];
    if (metadata_symlink_xattr_path(dir_fd, leaf, path, sizeof(path)) != 0)
        return -1;

    struct stat st;
    if (fstatat(dir_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISLNK(st.st_mode))
        return -1;

    MetadataXattrTarget target = { .fd = -1, .path = path };
    return metadata_apply_xattrs_target(&target, xattrs, count,
                                        skipped_security_count);
}

typedef enum {
    METADATA_XATTR_PROBE_DIRECTORY,
    METADATA_XATTR_PROBE_SYMLINK
} MetadataXattrProbeKind;

typedef struct {
    unsigned int namespace_bit;
    const char *name;
    const unsigned char *value;
    size_t value_length;
} MetadataXattrProbeAttribute;

static const unsigned char metadata_system_acl_probe[44] = {
    0x02, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x02, 0x00, 0x04, 0x00, 0xfe, 0xff, 0x00, 0x00,
    0x04, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x10, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x20, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff
};

static const MetadataXattrProbeAttribute metadata_probe_attributes[] = {
    { METADATA_XATTR_NS_USER, "user.migr_probe",
      (const unsigned char *)"probe", 5 },
    { METADATA_XATTR_NS_SYSTEM, "system.posix_acl_access",
      metadata_system_acl_probe,
      sizeof(metadata_system_acl_probe) },
    { METADATA_XATTR_NS_TRUSTED, "trusted.migr_probe",
      (const unsigned char *)"probe", 5 }
};

#define METADATA_XATTR_NS_ALL \
    (METADATA_XATTR_NS_USER | METADATA_XATTR_NS_SECURITY | \
     METADATA_XATTR_NS_SYSTEM | METADATA_XATTR_NS_TRUSTED)

#define METADATA_XATTR_NS_PROBED \
    (METADATA_XATTR_NS_USER | METADATA_XATTR_NS_SYSTEM | \
     METADATA_XATTR_NS_TRUSTED)

static unsigned long metadata_probe_serial;

static int metadata_create_named_probe(int anchor_fd,
                                       MetadataXattrProbeKind kind,
                                       char *name, size_t name_size)
{
    if (anchor_fd < 0 || name == NULL || name_size == 0)
    {
        errno = EINVAL;
        return -1;
    }

    for (unsigned int attempt = 0; attempt < 1000U; attempt++)
    {
        unsigned long serial = metadata_probe_serial++;
        int length = snprintf(name, name_size, ".migr-xattr-probe-%ld-%lu-%u",
                              (long)getpid(), serial, attempt);
        if (length < 0 || (size_t)length >= name_size)
        {
            errno = ENAMETOOLONG;
            return -1;
        }

        int result;
        if (kind == METADATA_XATTR_PROBE_DIRECTORY)
            result = mkdirat(anchor_fd, name, 0700);
        else
            result = symlinkat("migr-xattr-probe-target", anchor_fd, name);
        if (result == 0)
            return 0;
        if (errno != EEXIST)
            return -1;
    }

    errno = EEXIST;
    return -1;
}

static int metadata_probe_attribute_target(const MetadataXattrTarget *target,
                                           const MetadataXattrProbeAttribute *attribute)
{
    /* Deliberately calls metadata_xattr_set/metadata_xattr_remove directly
     * rather than metadata_apply_xattrs_fd/_symlink_at: those do exact-set
     * reconciliation against whatever the probe object already carries, and
     * a freshly-created object already carries an LSM-assigned
     * security.selinux attribute on an SELinux-enabled filesystem.
     * Reconciliation would try to remove that unrelated attribute as
     * "not in the target set," which fails with EACCES for a non-root
     * process -- a failure that has nothing to do with whether the probed
     * namespace itself is usable. The probe only needs "can I set and
     * remove this one name," so it must not touch anything else already on
     * the object. */
    int failed = metadata_xattr_set(target, attribute->name, attribute->value,
                                    attribute->value_length);
    int saved_errno = failed != 0 ? errno : 0;
    if (metadata_xattr_remove(target, attribute->name) != 0)
    {
        if (saved_errno == 0)
            saved_errno = errno;
        failed = 1;
    }
    if (failed && saved_errno != 0)
        errno = saved_errno;
    return failed ? -1 : 0;
}

static int metadata_probe_attribute_loop(const MetadataXattrTarget *target,
                                         unsigned int namespaces)
{
    for (size_t i = 0;
         i < sizeof(metadata_probe_attributes) /
                 sizeof(metadata_probe_attributes[0]);
         i++)
    {
        if ((namespaces & metadata_probe_attributes[i].namespace_bit) == 0)
            continue;
        if (metadata_probe_attribute_target(target,
                                            &metadata_probe_attributes[i]) != 0)
            return -1;
    }
    return 0;
}

static int metadata_probe_regular_xattrs(int anchor_fd,
                                         unsigned int namespaces)
{
    if (namespaces == 0)
        return 0;

    int fd = openat(anchor_fd, ".",
                    O_TMPFILE | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    MetadataXattrTarget target = { .fd = fd, .path = NULL };
    int failed = metadata_probe_attribute_loop(&target, namespaces) != 0;
    int saved_errno = failed ? errno : 0;

    if (close(fd) != 0)
    {
        if (!failed)
            saved_errno = errno;
        failed = 1;
    }
    if (failed && saved_errno != 0)
        errno = saved_errno;
    return failed ? -1 : 0;
}

static int metadata_probe_named_xattrs(int anchor_fd,
                                       MetadataXattrProbeKind kind,
                                       unsigned int namespaces)
{
    if (namespaces == 0)
        return 0;

    char name[NAME_MAX + 1];
    if (metadata_create_named_probe(anchor_fd, kind, name, sizeof(name)) != 0)
        return -1;

    int object_fd = -1;
    int failed = 0;
    int saved_errno = 0;
    char symlink_path[PATH_MAX];
    MetadataXattrTarget target = { .fd = -1, .path = NULL };

    if (kind == METADATA_XATTR_PROBE_DIRECTORY)
    {
        object_fd = openat(anchor_fd, name,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (object_fd < 0)
        {
            failed = 1;
            saved_errno = errno;
        }
        target.fd = object_fd;
        target.path = NULL;
    }
    else
    {
        if (metadata_symlink_xattr_path(anchor_fd, name, symlink_path,
                                        sizeof(symlink_path)) != 0)
        {
            failed = 1;
            saved_errno = errno;
        }
        target.fd = -1;
        target.path = symlink_path;
    }

    if (!failed && metadata_probe_attribute_loop(&target, namespaces) != 0)
    {
        failed = 1;
        saved_errno = errno;
    }

    if (object_fd >= 0 && close(object_fd) != 0)
    {
        if (!failed)
            saved_errno = errno;
        failed = 1;
    }
    int unlink_flags = kind == METADATA_XATTR_PROBE_DIRECTORY ? AT_REMOVEDIR : 0;
    if (unlinkat(anchor_fd, name, unlink_flags) != 0)
    {
        if (!failed)
            saved_errno = errno;
        failed = 1;
    }
    if (failed && saved_errno != 0)
        errno = saved_errno;
    return failed ? -1 : 0;
}

int metadata_xattr_capability_probe(
    int anchor_fd, const MetadataXattrRequirements *required)
{
    if (anchor_fd < 0 || required == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if ((required->regular_namespaces & ~METADATA_XATTR_NS_ALL) != 0 ||
        (required->directory_namespaces & ~METADATA_XATTR_NS_ALL) != 0 ||
        (required->symlink_namespaces & ~METADATA_XATTR_NS_ALL) != 0)
    {
        errno = EINVAL;
        return -1;
    }
    if (required->regular_namespaces == 0 &&
        required->directory_namespaces == 0 &&
        required->symlink_namespaces == 0)
        return 0;

    unsigned int regular_namespaces =
        required->regular_namespaces & METADATA_XATTR_NS_PROBED;
    unsigned int directory_namespaces =
        required->directory_namespaces & METADATA_XATTR_NS_PROBED;
    unsigned int symlink_namespaces =
        required->symlink_namespaces & METADATA_XATTR_NS_PROBED;
    if (regular_namespaces == 0 && directory_namespaces == 0 &&
        symlink_namespaces == 0)
        return 0;

    if (metadata_probe_regular_xattrs(anchor_fd, regular_namespaces) != 0)
        return -1;
    if (metadata_probe_named_xattrs(anchor_fd,
                                    METADATA_XATTR_PROBE_DIRECTORY,
                                    directory_namespaces) != 0)
        return -1;
    if (metadata_probe_named_xattrs(anchor_fd,
                                    METADATA_XATTR_PROBE_SYMLINK,
                                    symlink_namespaces) != 0)
        return -1;
    return 0;
}

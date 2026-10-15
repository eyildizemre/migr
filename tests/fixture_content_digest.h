#ifndef FIXTURE_CONTENT_DIGEST_H
#define FIXTURE_CONTENT_DIGEST_H

#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hash.h"
#include "sidecar.h"

/* Copies entries into out, giving each regular entry whose digest is still 0
 * the FNV-1a digest of its payload at data/<root_id>/<physical path>. The
 * physical path follows the physical leaves of ancestors present in the same
 * array (the logical component otherwise), so fixtures that write payloads
 * before their sidecar get the digest capture would have recorded. A payload
 * that cannot be read keeps digest 0. */
static inline void fixture_fill_content_digests(int data_fd,
                                                const SidecarEntry *entries,
                                                size_t count,
                                                SidecarEntry *out)
{
    for (size_t index = 0; index < count; index++)
    {
        out[index] = entries[index];
        const SidecarEntry *entry = &entries[index];
        if (entry->kind != SIDECAR_KIND_REGULAR || entry->content_digest != 0)
            continue;

        // Walk one component at a time: deep fixtures exceed PATH_MAX.
        char component[NAME_MAX + 1U];
        snprintf(component, sizeof(component), "%.*s",
                 (int)entry->root_id.length,
                 (const char *)entry->root_id.data);
        int fd = openat(data_fd, component,
                        O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        size_t logical_length = entry->logical_path.length;
        const char *logical = (const char *)entry->logical_path.data;
        size_t start = 0;
        while (fd >= 0 && start < logical_length)
        {
            const char *slash = memchr(logical + start, '/',
                                       logical_length - start);
            size_t end = slash != NULL ? (size_t)(slash - logical)
                                       : logical_length;
            const unsigned char *leaf = (const unsigned char *)logical + start;
            size_t leaf_length = end - start;
            if (end == logical_length)
            {
                leaf = entry->physical_leaf.data;
                leaf_length = entry->physical_leaf.length;
            }
            else
            {
                for (size_t other = 0; other < count; other++)
                {
                    const SidecarEntry *candidate = &entries[other];
                    if (candidate->root_id.length == entry->root_id.length &&
                        memcmp(candidate->root_id.data, entry->root_id.data,
                               entry->root_id.length) == 0 &&
                        candidate->logical_path.length == end &&
                        memcmp(candidate->logical_path.data, logical, end) == 0)
                    {
                        leaf = candidate->physical_leaf.data;
                        leaf_length = candidate->physical_leaf.length;
                        break;
                    }
                }
            }
            snprintf(component, sizeof(component), "%.*s", (int)leaf_length,
                     (const char *)leaf);
            int next = openat(fd, component, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            close(fd);
            fd = next;
            start = end + 1U;
        }
        if (fd < 0)
            continue;
        uint64_t hash = HASH_FNV1A_OFFSET_BASIS;
        unsigned char buffer[65536];
        ssize_t received;
        while ((received = read(fd, buffer, sizeof(buffer))) > 0)
            hash = hash_fnv1a_bytes(hash, buffer, (size_t)received);
        close(fd);
        if (received == 0)
            out[index].content_digest = hash;
    }
}

#endif

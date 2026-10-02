#define _GNU_SOURCE

#include "podman_state.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// layers.json holds a few hundred bytes per layer.
#define PODMAN_LAYERS_JSON_MAX (64U * 1024U * 1024U)

static int layer_id_at(const char *text, const char *end)
{
    if (end - text < PODMAN_LAYER_ID_LENGTH + 1)
        return 0;
    for (int index = 0; index < PODMAN_LAYER_ID_LENGTH; index++)
        if (!((text[index] >= '0' && text[index] <= '9') ||
              (text[index] >= 'a' && text[index] <= 'f')))
            return 0;
    return text[PODMAN_LAYER_ID_LENGTH] == '"';
}

// Where the JSON string that starts at text ends: its closing quote.
static const char *string_end(const char *text, const char *end)
{
    for (const char *cursor = text; cursor < end; cursor++)
    {
        if (*cursor == '\\')
            cursor++;
        else if (*cursor == '"')
            return cursor;
    }
    return NULL;
}

// The value keys of containers.json that matter here are plain fields of
// each container; "metadata" holds JSON as an escaped string, so its quotes
// never match these patterns.
int podman_containers_parse(const char *json, size_t length,
                            PodmanContainers *out)
{
    memset(out, 0, sizeof(*out));
    const char *end = json + length;
    static const char layer_key[] = "\"layer\":\"";
    static const char names_key[] = "\"names\":[\"";

    for (const char *cursor = json;
         (cursor = memmem(cursor, (size_t)(end - cursor), layer_key,
                          sizeof(layer_key) - 1U)) != NULL;)
    {
        cursor += sizeof(layer_key) - 1U;
        if (!layer_id_at(cursor, end))
            continue;
        void *layers = realloc(out->layers,
                               (out->layer_count + 1U) * sizeof(*out->layers));
        if (layers == NULL)
            goto fail;
        out->layers = layers;
        memcpy(out->layers[out->layer_count], cursor, PODMAN_LAYER_ID_LENGTH);
        out->layers[out->layer_count++][PODMAN_LAYER_ID_LENGTH] = '\0';
    }

    for (const char *cursor = json;
         (cursor = memmem(cursor, (size_t)(end - cursor), names_key,
                          sizeof(names_key) - 1U)) != NULL;)
    {
        cursor += sizeof(names_key) - 1U;
        const char *close = string_end(cursor, end);
        if (close == NULL)
            break;
        char **names = realloc(out->names,
                               (out->name_count + 1U) * sizeof(*out->names));
        if (names == NULL)
            goto fail;
        out->names = names;
        out->names[out->name_count] = strndup(cursor, (size_t)(close - cursor));
        if (out->names[out->name_count] == NULL)
            goto fail;
        out->name_count++;
        cursor = close;
    }
    return 0;

fail:
    podman_containers_free(out);
    return -1;
}

void podman_containers_free(PodmanContainers *containers)
{
    for (size_t index = 0; index < containers->name_count; index++)
        free(containers->names[index]);
    free(containers->names);
    free(containers->layers);
    memset(containers, 0, sizeof(*containers));
}

static int containers_have_layer(const PodmanContainers *containers,
                                 const char *id, size_t length)
{
    if (length != PODMAN_LAYER_ID_LENGTH)
        return 0;
    for (size_t index = 0; index < containers->layer_count; index++)
        if (memcmp(containers->layers[index], id, length) == 0)
            return 1;
    return 0;
}

int podman_state_left_out(const PodmanContainers *containers,
                          const char *relative, const char *link_target)
{
    static const char *const database[] = {
        "db.sql", "db.sql-journal", "db.sql-wal", "db.sql-shm",
        "libpod/bolt_state.db"
    };
    for (size_t index = 0; index < sizeof(database) / sizeof(database[0]);
         index++)
        if (strcmp(relative, database[index]) == 0)
            return 1;

    static const char registry[] = "overlay-containers";
    size_t registry_length = sizeof(registry) - 1U;
    if (strncmp(relative, registry, registry_length) == 0 &&
        (relative[registry_length] == '\0' ||
         relative[registry_length] == '/'))
        return 1;

    if (strncmp(relative, "overlay/", 8) != 0)
        return 0;
    const char *layer = relative + 8;
    if (strncmp(layer, "l/", 2) == 0 && layer[2] != '\0' &&
        strchr(layer + 2, '/') == NULL)
    {
        // A short link names its layer as ../<id>/diff.
        size_t length = link_target != NULL ? strlen(link_target) : 0;
        return length == 3U + PODMAN_LAYER_ID_LENGTH + 5U &&
               strncmp(link_target, "../", 3) == 0 &&
               strcmp(link_target + 3 + PODMAN_LAYER_ID_LENGTH, "/diff") == 0 &&
               containers_have_layer(containers, link_target + 3,
                                     PODMAN_LAYER_ID_LENGTH);
    }
    const char *slash = strchr(layer, '/');
    return containers_have_layer(containers, layer,
                                 slash != NULL ? (size_t)(slash - layer)
                                               : strlen(layer));
}

// Where the JSON object that starts at text ends: its closing brace.
static const char *object_end(const char *text, const char *end)
{
    int depth = 0;
    for (const char *cursor = text; cursor < end; cursor++)
    {
        if (*cursor == '"')
        {
            cursor = string_end(cursor + 1, end);
            if (cursor == NULL)
                return NULL;
        }
        else if (*cursor == '{' || *cursor == '[')
            depth++;
        else if ((*cursor == '}' || *cursor == ']') && --depth == 0)
            return cursor;
    }
    return NULL;
}

static const char *skip_space(const char *cursor, const char *end)
{
    while (cursor < end && (*cursor == ' ' || *cursor == '\n' ||
                            *cursor == '\t' || *cursor == '\r'))
        cursor++;
    return cursor;
}

// Whether the layer object [object, close] has its folder below storage_fd.
static int layer_folder_present(int storage_fd, const char *object,
                                const char *close)
{
    static const char id_key[] = "\"id\":\"";
    const char *id = memmem(object, (size_t)(close - object), id_key,
                            sizeof(id_key) - 1U);
    if (id == NULL)
        return 1;
    id += sizeof(id_key) - 1U;
    if (!layer_id_at(id, close))
        return 1;
    char folder[sizeof("overlay/") + PODMAN_LAYER_ID_LENGTH];
    snprintf(folder, sizeof(folder), "overlay/%.*s", PODMAN_LAYER_ID_LENGTH,
             id);
    struct stat st;
    return fstatat(storage_fd, folder, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISDIR(st.st_mode);
}

// Writes length bytes of text over layers.json in folder_fd, through a new
// file renamed into place, with st's owner, mode, and times.
static int replace_layers_json(int folder_fd, const char *text, size_t length,
                               const struct stat *st)
{
    static const char temporary[] = ".layers.json.migr";
    (void)unlinkat(folder_fd, temporary, 0);
    int fd = openat(folder_fd, temporary,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    st->st_mode & 07777);
    if (fd < 0)
        return -1;
    int failed = 0;
    for (size_t written = 0; !failed && written < length;)
    {
        ssize_t count = write(fd, text + written, length - written);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            failed = 1;
        else
            written += (size_t)count;
    }
    struct timespec times[2] = { st->st_atim, st->st_mtim };
    failed = failed || fchown(fd, st->st_uid, st->st_gid) != 0 ||
             fchmod(fd, st->st_mode & 07777) != 0 ||
             futimens(fd, times) != 0 || fsync(fd) != 0;
    int saved = errno;
    if (close(fd) != 0 && !failed)
    {
        failed = 1;
        saved = errno;
    }
    if (!failed && renameat(folder_fd, temporary, folder_fd, "layers.json") != 0)
    {
        failed = 1;
        saved = errno;
    }
    if (failed)
    {
        (void)unlinkat(folder_fd, temporary, 0);
        errno = saved;
        return -1;
    }
    return 0;
}

int podman_layers_json_drop_missing(int storage_fd)
{
    int folder_fd = openat(storage_fd, "overlay-layers",
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (folder_fd < 0)
        return errno == ENOENT ? 0 : -1;
    int fd = openat(folder_fd, "layers.json",
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
    {
        int saved = errno;
        close(folder_fd);
        errno = saved;
        return saved == ENOENT ? 0 : -1;
    }

    int result = -1;
    char *text = NULL, *kept = NULL;
    struct stat st;
    if (fstat(fd, &st) != 0)
        goto done;
    if (!S_ISREG(st.st_mode) || st.st_size > PODMAN_LAYERS_JSON_MAX)
    {
        errno = EINVAL;
        goto done;
    }
    size_t length = (size_t)st.st_size;
    text = malloc(length + 1U);
    kept = malloc(length + 1U);
    if (text == NULL || kept == NULL)
        goto done;
    for (size_t read_total = 0; read_total < length;)
    {
        ssize_t count = read(fd, text + read_total, length - read_total);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
        {
            if (count == 0)
                errno = EIO;
            goto done;
        }
        read_total += (size_t)count;
    }

    // [ {layer}, {layer}, ... ] followed by whatever the file ends with.
    const char *end = text + length;
    const char *cursor = skip_space(text, end);
    size_t used = 0;
    int dropped = 0;
    errno = EINVAL;
    if (cursor == end || *cursor != '[')
        goto done;
    kept[used++] = '[';
    cursor = skip_space(cursor + 1, end);
    while (cursor < end && *cursor != ']')
    {
        const char *close = *cursor == '{' ? object_end(cursor, end) : NULL;
        if (close == NULL)
            goto done;
        if (layer_folder_present(storage_fd, cursor, close))
        {
            if (used > 1U)
                kept[used++] = ',';
            memcpy(kept + used, cursor, (size_t)(close + 1 - cursor));
            used += (size_t)(close + 1 - cursor);
        }
        else
            dropped = 1;
        cursor = skip_space(close + 1, end);
        if (cursor < end && *cursor == ',')
            cursor = skip_space(cursor + 1, end);
    }
    if (cursor == end)
        goto done;
    memcpy(kept + used, cursor, (size_t)(end - cursor));
    used += (size_t)(end - cursor);

    result = 0;
    if (dropped)
        result = replace_layers_json(folder_fd, kept, used, &st) == 0 ? 1 : -1;

done:;
    int saved = errno;
    free(text);
    free(kept);
    close(fd);
    close(folder_fd);
    errno = saved;
    return result;
}

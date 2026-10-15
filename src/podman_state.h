#ifndef PODMAN_STATE_H
#define PODMAN_STATE_H

#include <stddef.h>

/*
 * Rootless podman's container state, which a restore leaves out when the
 * containers cannot work on the new system: another home, or SELinux lost
 * (D94). Images and volumes are restored either way.
 */

/* Podman's storage folder, below the home. */
#define PODMAN_STORAGE ".local/share/containers/storage"

/* The registry of containers below the storage folder. */
#define PODMAN_CONTAINERS_JSON "overlay-containers/containers.json"

#define PODMAN_LAYER_ID_LENGTH 64

typedef struct {
    /* Each container's writable layer, the folder overlay/<id>. */
    char (*layers)[PODMAN_LAYER_ID_LENGTH + 1];
    size_t layer_count;
    /* Each container's first name, for telling the user which were left
     * out. */
    char **names;
    size_t name_count;
} PodmanContainers;

/* Reads containers.json's text. Returns 0, or -1 when out of memory; a
 * text it cannot read gives no containers. */
int podman_containers_parse(const char *json, size_t length,
                            PodmanContainers *out);
void podman_containers_free(PodmanContainers *containers);

/*
 * Whether relative, a path below the storage folder, is container state a
 * restore leaves out: the database, the container registry, and each
 * container's writable layer with its short link in overlay/l. link_target
 * is the target of a symlink, NULL for anything else.
 */
int podman_state_left_out(const PodmanContainers *containers,
                          const char *relative, const char *link_target);

/*
 * Drops from overlay-layers/layers.json below storage_fd the layers whose
 * folder overlay/<id> is not there, keeping the file's owner, mode, and
 * times. Returns 1 when it rewrote the file, 0 when nothing changed or there
 * is no such file, and -1 with errno.
 */
int podman_layers_json_drop_missing(int storage_fd);

#endif

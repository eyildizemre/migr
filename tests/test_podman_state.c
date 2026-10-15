#define _GNU_SOURCE

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "podman_state.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define BLUE  "\033[0;34m"
#define NC    "\033[0m"

static int failures = 0;

static void check(int condition, const char *label)
{
    if (condition)
        printf("  " GREEN "v" NC " %s\n", label);
    else
    {
        printf("  " RED "x" NC " %s\n", label);
        failures++;
    }
}

static void fixture_fatal(const char *label)
{
    perror(label);
    exit(1);
}

#define IMAGE_LAYER "74d97c428c51a828f9051a7a40a53ff1fc99e54fc30323ce36760701b0b7f711"
#define KEEP_LAYER  "36e4a73b816d1df10ebd79e384109824196fd9ee2150abc61b9843fc46cbe7a3"
#define TOOLBOX_LAYER "1111111111111111111111111111111111111111111111111111111111111111"

// As podman 5.8 writes it, with the metadata's own JSON as an escaped string.
static const char containers_json[] =
    "[{\"id\":\"6346c02634735c1ce9eafe8f7bb6c65719e1cfee37bbc1c8575dd1cf0921b426\","
    "\"names\":[\"keep\"],\"image\":\"320994c3\",\"layer\":\"" KEEP_LAYER "\","
    "\"metadata\":\"{\\\"image-name\\\":\\\"alpine\\\",\\\"layer\\\":\\\"" IMAGE_LAYER "\\\"}\","
    "\"flags\":{\"MountLabel\":\"system_u:object_r:container_file_t:s0:c1,c2\"}},"
    "{\"id\":\"77\",\"names\":[\"fedora-toolbox-44\",\"alias\"],"
    "\"layer\":\"" TOOLBOX_LAYER "\"}]";

static void test_parse(void)
{
    printf(BLUE "::" NC " containers.json names each container's writable layer\n");
    PodmanContainers containers;
    check(podman_containers_parse(containers_json, strlen(containers_json),
                                  &containers) == 0 &&
              containers.layer_count == 2 &&
              strcmp(containers.layers[0], KEEP_LAYER) == 0 &&
              strcmp(containers.layers[1], TOOLBOX_LAYER) == 0,
          "both layers, and not the image layer quoted in the metadata");
    check(containers.name_count == 2 &&
              strcmp(containers.names[0], "keep") == 0 &&
              strcmp(containers.names[1], "fedora-toolbox-44") == 0,
          "each container's first name");
    podman_containers_free(&containers);
    check(podman_containers_parse("not json", 8, &containers) == 0 &&
              containers.layer_count == 0 && containers.name_count == 0,
          "a text it cannot read names no containers");
}

static void test_left_out(void)
{
    printf(BLUE "::" NC " the containers' state is left out, images and volumes are not\n");
    PodmanContainers containers;
    if (podman_containers_parse(containers_json, strlen(containers_json),
                                &containers) != 0)
        fixture_fatal("fixture: parse");
    check(podman_state_left_out(&containers, "db.sql", NULL) &&
              podman_state_left_out(&containers, "db.sql-journal", NULL) &&
              podman_state_left_out(&containers, "libpod/bolt_state.db", NULL),
          "the database, whichever podman wrote");
    check(podman_state_left_out(&containers, "overlay-containers", NULL) &&
              podman_state_left_out(&containers,
                                    "overlay-containers/77/userdata/config.json",
                                    NULL),
          "the container registry and everything below it");
    check(podman_state_left_out(&containers, "overlay/" KEEP_LAYER, NULL) &&
              podman_state_left_out(&containers,
                                    "overlay/" TOOLBOX_LAYER "/diff/usr/bin/vim",
                                    NULL),
          "each container's writable layer");
    check(podman_state_left_out(&containers, "overlay/l/K6LM3P6IB2YO3I43YM2T",
                                "../" KEEP_LAYER "/diff"),
          "the short link of a writable layer");
    check(!podman_state_left_out(&containers, "overlay/l/PLACHLCG66DHYMY6CKNM",
                                 "../" IMAGE_LAYER "/diff") &&
              !podman_state_left_out(&containers, "overlay/" IMAGE_LAYER "/diff",
                                     NULL) &&
              !podman_state_left_out(&containers, "overlay/l", NULL) &&
              !podman_state_left_out(&containers, "overlay-images/images.json",
                                     NULL) &&
              !podman_state_left_out(&containers, "volumes/data/_data/v", NULL) &&
              !podman_state_left_out(&containers, "overlay-layers/layers.json",
                                     NULL) &&
              !podman_state_left_out(&containers, "db.sql.backup", NULL),
          "image layers, their links, images, volumes, and the layer list stay");
    podman_containers_free(&containers);
}

static void make_dir(const char *base, const char *relative)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", base, relative);
    if (mkdir(path, 0700) != 0)
        fixture_fatal("fixture: mkdir");
}

static void write_text(const char *path, const char *text)
{
    FILE *file = fopen(path, "w");
    if (file == NULL || fputs(text, file) == EOF || fclose(file) != 0)
        fixture_fatal("fixture: write");
}

static int file_is(const char *path, const char *text)
{
    char buffer[4096] = "";
    FILE *file = fopen(path, "r");
    if (file == NULL)
        return 0;
    size_t length = fread(buffer, 1, sizeof(buffer) - 1, file);
    fclose(file);
    buffer[length] = '\0';
    return strcmp(buffer, text) == 0;
}

// A layer that braces and an escaped quote inside a string must not end.
#define IMAGE_OBJECT \
    "{\"id\":\"" IMAGE_LAYER "\",\"diff-size\":8704000,\"gidset\":[0,42]}"
#define KEEP_OBJECT \
    "{\"id\":\"" KEEP_LAYER "\",\"names\":[\"keep-layer\"]," \
    "\"parent\":\"" IMAGE_LAYER "\",\"mountlabel\":\"a}b]c\\\"d\"}"

static void test_layers_json(void)
{
    printf(BLUE "::" NC " layers.json keeps only the layers that were restored\n");
    char storage[] = "/tmp/migr-podman-XXXXXX";
    if (mkdtemp(storage) == NULL)
        fixture_fatal("fixture: mkdtemp");
    make_dir(storage, "overlay");
    make_dir(storage, "overlay/" IMAGE_LAYER);
    make_dir(storage, "overlay-layers");
    char layers[PATH_MAX];
    snprintf(layers, sizeof(layers), "%s/overlay-layers/layers.json", storage);
    write_text(layers, "[" IMAGE_OBJECT "," KEEP_OBJECT "]\n");
    struct timespec times[2] = { { 946684800, 0 }, { 946684801, 5 } };
    if (utimensat(AT_FDCWD, layers, times, 0) != 0 || chmod(layers, 0600) != 0)
        fixture_fatal("fixture: metadata");

    int storage_fd = open(storage, O_RDONLY | O_DIRECTORY);
    if (storage_fd < 0)
        fixture_fatal("fixture: open");
    // Times first: reading the file to compare it sets its access time.
    struct stat st;
    int rewritten = podman_layers_json_drop_missing(storage_fd) == 1;
    check(rewritten && stat(layers, &st) == 0 &&
              (st.st_mode & 07777) == 0600 &&
              st.st_mtim.tv_sec == 946684801 && st.st_mtim.tv_nsec == 5 &&
              st.st_atim.tv_sec == 946684800,
          "the rewritten file keeps its mode and times");
    check(rewritten && file_is(layers, "[" IMAGE_OBJECT "]\n"),
          "a layer whose folder was left out is dropped, the rest kept "
          "byte for byte");
    check(podman_layers_json_drop_missing(storage_fd) == 0 &&
              file_is(layers, "[" IMAGE_OBJECT "]\n"),
          "with every folder there, nothing changes");

    write_text(layers, "[" IMAGE_OBJECT ",");
    check(podman_layers_json_drop_missing(storage_fd) == -1 &&
              file_is(layers, "[" IMAGE_OBJECT ","),
          "a list it cannot read is an error and stays as it is");
    unlink(layers);
    check(podman_layers_json_drop_missing(storage_fd) == 0,
          "without layers.json there is nothing to do");
    close(storage_fd);

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/overlay/" IMAGE_LAYER, storage);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/overlay", storage);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/overlay-layers", storage);
    rmdir(path);
    if (rmdir(storage) != 0)
        fixture_fatal("fixture: rmdir");
}

int main(void)
{
    test_parse();
    test_left_out();
    test_layers_json();

    if (failures == 0)
        printf(GREEN "podman state tests passed" NC "\n");
    else
        printf(RED "podman state tests: %d failure(s)" NC "\n", failures);
    return failures == 0 ? 0 : 1;
}

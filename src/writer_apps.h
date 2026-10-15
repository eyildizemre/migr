#ifndef WRITER_APPS_H
#define WRITER_APPS_H

#include <stddef.h>
#include <sys/types.h>

/* Running writers tracked at once: the table's, and open Flatpak apps. */
#define WRITER_APPS_MAX 40U
#define WRITER_APPS_FLATPAK_ID_MAX 128

/**
 * A running application that rewrites its settings while it runs or when it
 * exits, and one path below HOME it owns; an application that owns several
 * appears once per path. Restore restores these settings last (D66, D69),
 * and a backup reading them live captures them last (D84).
 */
typedef struct {
    char label[WRITER_APPS_FLATPAK_ID_MAX];
    char settings[WRITER_APPS_FLATPAK_ID_MAX + sizeof(".var/app/")]; /* "" for none */
} RunningWriter;

/* Collects the known writer applications and open Flatpak apps run by uid;
 * returns how many entries it filled, at most max. */
size_t writer_apps_running(uid_t uid, RunningWriter *writers, size_t max);

/* The distinct labels of writers, in order; returns how many. labels needs
 * room for count entries and points into writers. */
size_t writer_apps_labels(const RunningWriter *writers, size_t count,
                          const char **labels);

/* Prints "A", "A and B", or "A, B and C". */
void writer_apps_print_labels(const char *const *labels, size_t count);

/* The user whose applications matter: the sudo invoker under sudo (D38). */
int writer_apps_session_uid(uid_t *uid);

#ifdef WRITER_APPS_TEST_HOOKS
void writer_apps_test_set_proc_root(const char *path);
#endif

#endif

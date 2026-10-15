#ifndef FLATPAK_H
#define FLATPAK_H

#include <stdio.h>

/**
 * @brief Lists the system installation's Flatpak applications as
 *        "<remote>\t<app-id>" lines, the output of
 *        `flatpak list --system --app --columns=origin,application`.
 *
 * A user installation needs no list: it is captured as files (D57).
 *
 * @return A heap string, or NULL when flatpak is missing or lists nothing.
 */
char *flatpak_apps_collect(void);

/**
 * @brief Installs the applications a restored flatpak-apps.txt lists into
 *        the system installation (D76).
 *
 * Runs after restore_packages(), which may bring Flatpak itself. Apps
 * already installed are skipped; the rest are installed with one
 * `flatpak install --system -y` per remote the system has. A missing
 * flathub is added first from Flathub's own address (D102); apps whose
 * remote it still lacks are listed with the command to run once the remote
 * is added or turned on: adding any other needs its signing key, which the
 * backup does not have.
 * An absent list is skipped silently, and a system without flatpak gets the
 * apps listed in todo. A dry run only says what it would install. Without a
 * network (online 0) nothing is installed, and the apps are listed to
 * install later (D90).
 *
 * @param had_error Set to 1 on a real failure; untouched otherwise.
 */
void restore_flatpak_apps(int source_root_fd, int online, FILE *todo,
                          int *had_error);

#endif

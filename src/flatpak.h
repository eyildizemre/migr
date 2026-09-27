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
 * `flatpak install --system -y` per remote the system has. Apps whose
 * remote it lacks are listed with the command to run once the remote is
 * added: adding one needs its signing key, which the backup does not have.
 * An absent list is skipped silently, and a system without flatpak gets the
 * apps listed in todo. A dry run only says what it would install.
 *
 * @param had_error Set to 1 on a real failure; untouched otherwise.
 */
void restore_flatpak_apps(int source_root_fd, FILE *todo, int *had_error);

#endif

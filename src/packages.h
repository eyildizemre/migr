#ifndef PACKAGES_H
#define PACKAGES_H

#include <stdio.h>
#include <sys/types.h>

#ifdef PACKAGES_TEST_HOOKS
#include "detect.h"

typedef int (*PackagesTestRunHook)(char *const argv[], void *context);
typedef int (*PackagesTestCaptureHook)(char *const argv[], char *output,
                                       size_t output_size, void *context);

void packages_test_set_restore_hooks(distro_t distro,
                                     PackagesTestRunHook run_hook,
                                     PackagesTestCaptureHook capture_hook,
                                     void *context);
void packages_test_set_group_file(const char *path);
void packages_test_clear_restore_hooks(void);
int packages_test_drop_kernel_pinned(char *buffer);
#endif

/**
 * @brief Exports the same package list into an open container directory.
 *
 * How production writes packages.txt: the container's directory fd is already
 * open and locked, so the file is created with openat() and O_NOFOLLOW rather
 * than through a rebuilt path string a symlink could redirect.
 *
 * Nothing already occupying leaf is ever opened or written into: the name is
 * removed first and the list is written to an inode this call creates with
 * O_EXCL. That is what keeps a FIFO from blocking the backup forever, and a
 * hardlink to a file outside the container from being truncated and
 * overwritten with the package list.
 *
 * A failed export never leaves something usable-looking behind either. leaf is
 * cleared when the list cannot be produced, cannot be created safely, or
 * cannot be written in full -- so a container that goes on to be finalized
 * carries either a complete package list or none at all, never a stale,
 * hostile, or truncated one. The three return values exist because those are
 * three different situations for the caller: a system without a package list
 * is tolerable, a destination that could not store one is not.
 *
 * @param container_fd Directory fd of the container; not closed here.
 * @param leaf         File name to create beneath it; a single component.
 * @return 0 when a complete list was written; 1 when no list could be
 *         produced and the slot was left empty; -1 with errno when the list
 *         could not be written or the slot made safe, in which case the
 *         container must not be finalized.
 */
int packages_at(int container_fd, const char *leaf);

/**
 * @brief Safely writes a text control artifact beneath an open container fd.
 *
 * Uses the same clear-before-create and clear-on-failure contract documented
 * for packages_at(), without attaching package-specific collection or output.
 * A NULL buffer means there is nothing to write and still clears any stale
 * object occupying the slot; an empty non-NULL buffer is written as an empty
 * file.
 *
 * @param container_fd Directory fd of the container; not closed here.
 * @param leaf         File name to create beneath it; a single component.
 * @param buffer       Complete NUL-terminated contents, or NULL for no content.
 * @return 0 when the buffer was written; 1 when there was no content and the
 *         slot was left empty; -1 with errno when the buffer could not be
 *         written or the slot made safe, in which case the container must not
 *         be finalized.
 */
int write_container_text_file_at(int container_fd, const char *leaf,
                                 const char *buffer);

/**
 * @brief Ensures no object occupies a control-artifact slot in a container.
 *
 * Used where a package list must not be present at all -- an explicit-paths
 * backup exports none, and an adopted container may still hold one a previous
 * run (or someone else) left behind. Restore acts on whatever packages.txt it
 * finds without re-deriving the backup's scope, so leaving a stale one inside a
 * finalized container would let it drive package installs the backup never
 * recorded.
 *
 * A symlink is removed as itself, never followed.
 *
 * @param container_fd Directory fd of the container; not closed here.
 * @param leaf         File name to clear beneath it; a single component.
 * @return 0 when nothing occupies leaf afterwards (including when nothing did),
 *         -1 when something is still there.
 */
int packages_clear_at(int container_fd, const char *leaf);

/**
 * @brief Reports whether a package name is safe to use as a package-manager
 * argv element.
 *
 * Real backups only ever write plain names (docs/DECISIONS.md D12); a token
 * beginning with '-' would otherwise be interpreted by apt-get/dnf/pacman as
 * an option rather than a package name when it reaches the privileged install
 * invocation. Exposed for direct testing.
 *
 * @param token NUL-terminated candidate package name; NULL is rejected.
 * @return 1 if safe to use as an argv element, 0 otherwise.
 */
int package_token_is_safe(const char *token);

/**
 * @brief Reads and validates the package-name list from an open packages.txt
 * stream.
 *
 * Every line's first whitespace-delimited token is checked with
 * package_token_is_safe(); a rejected token is skipped the same way an
 * old-format dpkg "pkg\tdeinstall" entry is already skipped. A stream error,
 * failed growth allocation, or failed per-entry allocation sets *had_error.
 * Successfully parsed entries before a failure are still returned.
 *
 * On return, *pkgs_out is either NULL when the initial array allocation failed
 * or an array of *pkg_count_out heap-owned strings. The caller owns the
 * strings and the array.
 *
 * @param pkg_file      Open, readable stream positioned at the file start.
 * @param pkgs_out      Receives the parsed package-name array.
 * @param pkg_count_out Receives the number of entries in *pkgs_out.
 * @param had_error     Set to 1 on any read/allocation failure; untouched
 *                      otherwise.
 */
void read_package_list(FILE *pkg_file, char ***pkgs_out, int *pkg_count_out,
                       int *had_error);

/**
 * @brief Installs packages listed in a restored packages.txt.
 *
 * Reads packages.txt from source_root_fd, detects the distro, and invokes the
 * distro's package manager. A dry run only previews; a missing or non-regular
 * packages.txt and an unrecognized distro are skipped without making the
 * restore fatal, while failures to read or inspect the file set had_error.
 *
 * This and the restore steps below write what is left for the user to do
 * by hand to todo, one paragraph each with the command to run.
 *
 * @param source_root_fd Directory fd the restored packages.txt is read from.
 * @param todo           Receives the packages the system does not have after
 *                       the install.
 * @param had_error      Set to 1 on a real failure; untouched otherwise.
 */
void restore_packages(int source_root_fd, FILE *todo, int *had_error);

/**
 * @brief Lists the groups whose member list in /etc/group names user, one
 *        name per line.
 *
 * These are the user's supplementary memberships, by name since GIDs differ
 * between installs. The file is read directly, without NSS, as D38 reads
 * accounts: a directory service's groups are not the install's. Names a
 * restore would not accept are left out.
 *
 * @return A heap string, empty when user is in no group; NULL when the file
 *         cannot be read.
 */
char *groups_collect(const char *user);

/**
 * @brief Looks a group's gid up in /etc/group, read the same way.
 *
 * @return 0, or -1 when the group is absent, listed twice, or the file cannot
 *         be read.
 */
int local_group_gid(const char *name, gid_t *gid);

/**
 * @brief Adds user to the groups a restored groups.txt lists.
 *
 * Runs after restore_packages(), since packages create groups (the libvirt
 * package creates libvirt). Groups this system has and user is not yet in
 * are added with one usermod; groups it lacks are listed, with the command
 * to add them later, and never created, since one comes with software that
 * would give it a system GID. An absent
 * groups.txt is skipped silently. A dry run only says what it would add.
 *
 * @param user      Login name to add; NULL when it could not be resolved,
 *                  which fails the step if there is anything to add.
 * @param had_error Set to 1 on a real failure; untouched otherwise.
 */
void restore_groups(int source_root_fd, const char *user, FILE *todo,
                    int *had_error);

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

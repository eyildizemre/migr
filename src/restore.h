#ifndef RESTORE_H
#define RESTORE_H

#ifdef RESTORE_TEST_HOOKS
typedef int (*RestoreTestNetworkReloadHook)(char *const argv[], void *context);

void restore_test_set_network_config_dest_dir(const char *backend_name,
                                              const char *dest_dir);
void restore_test_set_network_reload_hook(RestoreTestNetworkReloadHook hook,
                                          void *context);
#endif

/**
 * @brief Restores files and packages from a backup directory to HOME.
 *
 * Refuses a ".partial" (in-progress or abandoned) container, an unknown or
 * malformed manifest.txt, or a finalized versioned container with a missing
 * or legacy manifest before prompting or mutating the destination. A valid v1
 * manifest selects between two independent representation-driven code paths:
 * a native tree (fd-anchored, exact metadata) or a portable sidecar
 * (percent-encoded names, xattrs sidecar, hardlink groups). Legacy or
 * unversioned backups use the native path. A free-space preflight check can
 * abort the restore before any confirmation prompt if the destination can't
 * hold it. --dry-run previews the same plan and checks without prompting or
 * mutating anything. manifest.txt (when present) resolves cross-locale XDG
 * directory names (e.g. "Belgeler" on the source system maps to Documents
 * on an English target system); its absence falls back to the target system's
 * basename. If packages.txt is present, installs the listed packages via the
 * distro's package manager. A v1 manifest that records network configuration
 * also restores container-root network/ backend directories after the main
 * payload succeeds. NetworkManager profiles are reloaded best-effort; netplan
 * and systemd-networkd configuration is written with manual apply instructions.
 *
 * @param source Path to the dated backup directory (e.g. /mnt/drive/migr_backup_20260519).
 * @return 0 on success or user cancellation, 1 on error.
 */
int restore(const char *source);

#endif

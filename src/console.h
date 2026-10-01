#ifndef CONSOLE_H
#define CONSOLE_H

#include <sys/types.h>

/* A restore started on the desktop continues on a text console, with no
 * desktop session running while it writes (docs/DECISIONS.md D89). */

/**
 * @brief The virtual console a restore run here can continue on, or 0 when it
 *        stays in this session: migr runs under sudo from the only graphical
 *        session, systemd runs a display manager, and a console above the
 *        ones logind gives gettys is free.
 */
int console_restore_vt(void);

/**
 * @brief Starts the restore of source again as a system service on console
 *        vt, with this run's options and invoker, and says so.
 * @return 0 once the service runs; -1 after an error message, with nothing
 *         changed.
 */
int console_restore_hand_over(int vt, const char *source,
                              int skip_content_verification);

/** @brief Nonzero in the service console_restore_hand_over() started. */
int console_restore_service(void);

/**
 * @brief In that service: waits for the desktop run to exit, closes the
 *        desktop, ends the invoker's remaining processes, and shows the
 *        service's console.
 * @return 0, or -1 after an error message when the desktop could not be
 *         closed.
 */
int console_restore_take_over(void);

/** @brief In that service: waits for Enter, after which the display manager
 *         starts again. */
void console_restore_finish(void);

#ifdef CONSOLE_TEST_HOOKS
int console_test_graphical_session(const char *sessions_dir,
                                   const char *cgroup, uid_t uid);
int console_test_free_vt(unsigned short in_use);
int console_test_escape(const char *text, char *out, size_t size);
#endif

#endif

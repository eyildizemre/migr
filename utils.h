#ifndef UTILS_H
#define UTILS_H

extern int verbose; /**< Non-zero when -v is passed; enables per-file progress output. */
extern int dry_run; /**< Non-zero when -n/--dry-run is passed; suppresses all writes. */

/**
 * @brief Prints usage information for all commands and options to stdout.
 */
void print_help(void);

/**
 * @brief Prompts the user with a yes/no question and reads their response from stdin.
 *
 * Displays message followed by " [y/N]: " and reads one line from stdin.
 * EOF is treated as a negative response.
 *
 * @param message The prompt string displayed before the [y/N] indicator.
 * @return 1 if the response starts with 'y' or 'Y', 0 otherwise.
 */
int confirm_action(const char *message);

#endif

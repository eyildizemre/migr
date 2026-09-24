#ifndef VERIFY_H
#define VERIFY_H

/**
 * @brief Checks a finished portable backup against its own capture record.
 *
 * Every live journal entry must have its payload node in the container, and
 * every regular file must still have the size and content digest recorded
 * when it was captured (docs/DECISIONS.md D59). Reads only; nothing in the
 * backup is changed.
 *
 * @return 0 when everything matches, 1 on a mismatch or any error.
 */
int verify_backup(const char *path);

#endif

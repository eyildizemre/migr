#ifndef REPORT_H
#define REPORT_H

/**
 * @brief Prints a formatted backup analysis report to stdout.
 *
 * Scans HOME for main user directories, dotfiles and config, developer tool
 * caches, and browser profiles, displaying the size of each present item.
 * Also computes and prints an estimated critical backup size covering
 * Documents, Downloads, Pictures, .ssh, .gnupg, .gitconfig, and .bashrc.
 *
 * @return 0 on success, 1 if the HOME environment variable is not set.
 */
int report(void);

#endif
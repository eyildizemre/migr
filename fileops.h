#ifndef FILEOPS_H
#define FILEOPS_H

#include <sys/types.h>

// Recursively clones a file or directory from src to dest
int clone_recursive(const char *src, const char *dest);

// Calculates the total size of a directory recursively
int get_dir_size(const char *path, off_t *size);

// Executes a command without a shell and waits for it to finish
int run_command(char *const argv[]);

// Executes a command and captures its standard output into a buffer
int run_command_capture(char *const argv[], char *output, size_t output_size);

#endif
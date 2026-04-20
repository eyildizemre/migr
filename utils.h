#ifndef UTILS_H
#define UTILS_H

extern int verbose;
extern int dry_run;

void print_help(void);
int confirm_action(const char *message);

#endif

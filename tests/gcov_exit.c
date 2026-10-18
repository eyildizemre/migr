// For coverage builds only: tests run code in forked children that end with
// _exit(), which skips writing their counters. Linked into every binary with
// -Wl,--wrap=_exit, this writes them first.

extern void __gcov_dump(void);
extern void __real__exit(int status) __attribute__((noreturn));
void __wrap__exit(int status) __attribute__((noreturn));

void __wrap__exit(int status)
{
    __gcov_dump();
    __real__exit(status);
}

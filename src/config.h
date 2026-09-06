#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>

#define CONFIG_MAX_BYTES (1024U * 1024U)
#define CONFIG_MAX_RULES 4096U

typedef enum { CONFIG_CRITICAL, CONFIG_COMPREHENSIVE } ConfigScope;
typedef enum { CONFIG_INCLUDE, CONFIG_EXCLUDE } ConfigAction;

typedef struct {
    ConfigScope scope;
    ConfigAction action;
    char *path;
    size_t line;
} ConfigRule;

typedef struct {
    ConfigRule *rules;
    size_t count;
} Config;

/* Output objects must be empty. On failure they remain empty. Paths are decoded,
 * not resolved: selection compilation owns HOME expansion and normalization. */
int config_parse(const char *data, size_t length, const char *source, Config *out);
int config_load(const char *path, Config *out);
void config_free(Config *config);
/* Allocates an absolute path using the invocation's HOME/XDG environment. */
int config_path(char **out);
/* Creates only a missing template, runs the chosen editor, then validates. */
int config_edit(void);

#endif

#ifndef BACKUP_H
#define BACKUP_H

typedef enum {
    BACKUP_CRITICAL,
    BACKUP_COMPREHENSIVE,
    BACKUP_PATHS
} BackupMode;

int backup(const char *target, BackupMode mode, char **paths);

#endif

#!/bin/sh
# Runs a command as an unprivileged user inside a fresh container, from the
# current directory, the way a packager's build runs: ownership tests mean
# nothing as root, and migr refuses to adopt or update a backup without the
# /etc/machine-id that bare images lack.
set -eu
[ -s /etc/machine-id ] ||
    tr -d '-' < /proc/sys/kernel/random/uuid > /etc/machine-id
id builder >/dev/null 2>&1 || useradd -m builder
chown -R builder: .
exec runuser -u builder -- "$@"

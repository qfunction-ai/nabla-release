#!/bin/sh
set -e

# Fix volume ownership on container restart.
# Docker volumes retain the UID from the previous container run,
# which may differ if the image is rebuilt with a different UID.
if [ -d "/data" ]; then
    # Run chown as root before dropping privileges
    if [ "$(id -u)" = "0" ]; then
        chown appuser:appgroup /data 2>/dev/null || true
        # Also fix subdirectories if they exist
        # Use -h to operate on symlinks themselves (not targets), preventing
        # symlink-based privilege escalation via chown following symlinks
        find /data -mindepth 1 -maxdepth 1 ! -type l -exec chown appuser:appgroup {} \; 2>/dev/null || true
    fi
fi

exec "$@"

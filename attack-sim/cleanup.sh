#!/usr/bin/env bash
# Removes everything persist-sim.sh created.
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }
U=svc-backup
systemctl disable sys-update.service >/dev/null 2>&1
rm -f /etc/systemd/system/sys-update.service
systemctl daemon-reload
rm -f /etc/cron.d/sys-update /etc/sudoers.d/90-$U
id "$U" >/dev/null 2>&1 && userdel -r "$U" 2>/dev/null
echo "===== CLEANUP DONE ====="

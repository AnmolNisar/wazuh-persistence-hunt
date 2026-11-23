#!/usr/bin/env bash
# SAFE persistence simulation for a lab VM. Plants five classic Linux backdoors
# that do nothing harmful: the cron job and service point at /bin/true, the new
# account has no password and is blocked from SSH by AllowUsers.
# Undo everything with: sudo bash cleanup.sh
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }
U=svc-backup

echo "[1/5] T1136.001  Create local account '$U'"
id "$U" >/dev/null 2>&1 || useradd -m -s /bin/bash -c "Backup service" "$U"
sleep 2

echo "[2/5] T1053.003  Cron job in /etc/cron.d"
echo "*/30 * * * * root /bin/true # sys-update" > /etc/cron.d/sys-update
chmod 644 /etc/cron.d/sys-update
sleep 2

echo "[3/5] T1098.004  SSH key in /home/$U/.ssh/authorized_keys"
install -d -m 700 -o "$U" -g "$U" "/home/$U/.ssh"
TMPK=$(mktemp -u)
ssh-keygen -q -t ed25519 -N "" -C "attacker@lab" -f "$TMPK"
cat "$TMPK.pub" >> "/home/$U/.ssh/authorized_keys"
rm -f "$TMPK" "$TMPK.pub"          # private key destroyed: the key can never be used
chown "$U:$U" "/home/$U/.ssh/authorized_keys"; chmod 600 "/home/$U/.ssh/authorized_keys"
sleep 2

echo "[4/5] T1548.003  Passwordless sudo in /etc/sudoers.d"
echo "$U ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-$U
chmod 440 /etc/sudoers.d/90-$U
visudo -cf /etc/sudoers.d/90-$U >/dev/null || { rm -f /etc/sudoers.d/90-$U; echo "   sudoers check failed - skipped"; }
sleep 2

echo "[5/5] T1543.002  systemd service in /etc/systemd/system"
cat > /etc/systemd/system/sys-update.service <<'X'
[Unit]
Description=System Update Helper
[Service]
Type=oneshot
ExecStart=/bin/true
[Install]
WantedBy=multi-user.target
X
systemctl daemon-reload
systemctl enable sys-update.service >/dev/null 2>&1

echo "===== 5 PERSISTENCE MECHANISMS PLANTED ====="

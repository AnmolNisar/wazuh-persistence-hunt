#!/usr/bin/env bash
# Manual Linux persistence hunt: sweeps the common hiding places and flags
# anything recent or unusual. Read-only - it changes nothing.
# Run: sudo bash persistence-hunt.sh [days]   (default: look back 7 days)
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }
DAYS="${1:-7}"
flag() { echo "  [!] $*"; }
hdr()  { echo; echo "== $* =="; }

hunt() {
echo "Linux persistence hunt on $(hostname) - $(date -u '+%Y-%m-%d %H:%M UTC') - lookback ${DAYS}d"

hdr "H1  Accounts (T1136)"
awk -F: '$3==0 && $1!="root"{print "  [!] UID 0 account: "$1}' /etc/passwd
awk -F: '$3>=1000 && $3<65534 {print $1" "$3" "$7}' /etc/passwd | while read -r n uid sh; do
  echo "  user $n (uid $uid, shell $sh)"
done
[[ -n "$(find /etc/passwd -mtime -"$DAYS")" ]] && flag "/etc/passwd changed in the last ${DAYS} days"

hdr "H2  Sudo rights (T1548.003)"
grep -rhvE '^\s*(#|$|Defaults)' /etc/sudoers.d/ 2>/dev/null | sed 's/^/  /'
grep -rlE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read -r f; do flag "NOPASSWD rule in $f"; done

hdr "H3  Scheduled tasks (T1053.003)"
find /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron/crontabs -type f -mtime -"$DAYS" 2>/dev/null | while read -r f; do flag "recent cron file: $f -> $(grep -v '^#' "$f" | head -n 1)"; done

hdr "H4  SSH authorized keys (T1098.004)"
find /root /home -name authorized_keys 2>/dev/null | while read -r f; do
  echo "  $f: $(grep -c . "$f") key(s), modified $(date -r "$f" '+%Y-%m-%d %H:%M')"
  [[ -n "$(find "$f" -mtime -"$DAYS")" ]] && flag "recently changed key file: $f"
done

hdr "H5  systemd services (T1543.002)"
find /etc/systemd/system -maxdepth 1 -name '*.service' -type f 2>/dev/null | while read -r f; do
  dpkg -S "$f" >/dev/null 2>&1 || flag "service not owned by any package: $f -> $(grep -m1 ExecStart "$f")"
done

}

OUT="$(hunt)"
echo "$OUT"
hdr "Summary"
echo "  $(grep -c '\[!\]' <<<"$OUT") finding(s) to investigate"

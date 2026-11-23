#!/usr/bin/env bash
# Adds the persistence FIM paths and rules to Wazuh, validates, restarts.
# Run from the folder holding rules/ and config/:  sudo bash install.sh
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
TS=$(date +%s)
cp /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.bak.$TS"
cp /var/ossec/etc/rules/local_rules.xml "/var/ossec/etc/rules/local_rules.xml.bak.$TS"

if ! grep -q 'restrict="authorized_keys\$"' /var/ossec/etc/ossec.conf; then
  sed '/^<!--/,/-->/d' "$HERE/config/fim-persistence-snippet.xml" >> /var/ossec/etc/ossec.conf
fi
if ! grep -q 'id="100300"' /var/ossec/etc/rules/local_rules.xml; then
  sed '/^<!--/,/-->/d' "$HERE/rules/local_rules_persistence.xml" >> /var/ossec/etc/rules/local_rules.xml
fi

if /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
  systemctl restart wazuh-manager && echo "===== PERSISTENCE DETECTION INSTALLED ====="
else
  echo "Rule/config test failed - restoring backups, nothing changed."
  cp "/var/ossec/etc/ossec.conf.bak.$TS" /var/ossec/etc/ossec.conf
  cp "/var/ossec/etc/rules/local_rules.xml.bak.$TS" /var/ossec/etc/rules/local_rules.xml
  /var/ossec/bin/wazuh-analysisd -t
fi

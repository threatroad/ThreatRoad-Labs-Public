#!/bin/bash
# linux-fundamentals-lab-cleanup.sh
set -e
sudo rm -rf /opt/linux_lab
sudo userdel -r labuser 2>/dev/null || true   # tolerate root-owned files in the home dir
sudo rm -f /etc/sudoers.d/labuser
sudo rm -f /root/.bonus_hint
sudo rm -f /etc/profile.d/threatroad_lab1_submit_flag.sh
echo "[+] Lab removed. All artifacts cleaned."

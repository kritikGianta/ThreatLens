#!/bin/bash
set -e
touch /var/log/lab/auth.log /var/log/lab/access.log /var/log/lab/commands.log
chmod 666 /var/log/lab/commands.log
nginx
echo "[victim] nginx and sshd running — logs in /var/log/lab"
# -D: foreground, -E: write sshd's own log (auth events) to a file the shipper tails
exec /usr/sbin/sshd -D -E /var/log/lab/auth.log

#!/bin/bash
# Records every SSH command with the client IP, then runs it — command-line telemetry for the SOC.
SRC_IP="${SSH_CLIENT%% *}"
CMD="${SSH_ORIGINAL_COMMAND:-interactive-shell}"
printf '%s lab-victim sshd-audit[%s]: user=%s src_ip=%s cmd="%s"\n' \
  "$(date -u '+%b %d %H:%M:%S')" "$$" "$USER" "$SRC_IP" "${CMD//\"/\'}" >> /var/log/lab/commands.log
if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
  exec /bin/bash -c "$SSH_ORIGINAL_COMMAND"
fi
exec /bin/bash -l

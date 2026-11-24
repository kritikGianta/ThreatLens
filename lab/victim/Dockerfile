# ThreatLens attack lab — deliberately weak "victim" server (SSH + web app).
# Lives on an isolated Docker network; never expose it to the internet.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server nginx-light procps curl cron \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /var/log/lab /var/www/acme

# A weak administrator password that appears in common password lists (on purpose).
ARG VICTIM_PASSWORD=sunshine2024
RUN useradd -m -s /bin/bash admin && echo "admin:${VICTIM_PASSWORD}" | chpasswd

COPY sshd_config /etc/ssh/sshd_config
COPY audit-shell.sh /usr/local/bin/audit-shell
COPY nginx.conf /etc/nginx/nginx.conf
COPY site/ /var/www/acme/
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/local/bin/audit-shell /entrypoint.sh && ssh-keygen -A

EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]

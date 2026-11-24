# ThreatLens attack lab — attacker toolkit (real tools against the lab victim only).
FROM alpine:3.20

RUN apk add --no-cache bash curl hydra nmap nmap-scripts openssh-client sshpass python3 py3-pip \
 && pip install --no-cache-dir --break-system-packages sqlmap==1.8.11

COPY wordlist.txt /opt/wordlist.txt
COPY stage2.sh /opt/c2/stage2.sh
COPY attack.sh /usr/local/bin/attack
RUN chmod 755 /usr/local/bin/attack

ENTRYPOINT ["/usr/local/bin/attack"]
# Idle by default: `compose up` must never start an attack. Run one with `compose run --rm attacker all`.
CMD ["help"]

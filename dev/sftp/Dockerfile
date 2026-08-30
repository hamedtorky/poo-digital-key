FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 poo \
    && useradd --uid 10001 --gid poo --home-dir /files --shell /usr/sbin/nologin poo \
    && passwd -d poo \
    && mkdir -p /run/sshd /etc/ssh/authorized_keys /srv/sftp/files \
    && chown poo:poo /srv/sftp/files

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

CMD ["/bin/sh", "-c", "ssh-keygen -A && exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config"]

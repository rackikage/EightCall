FROM alpine:3.20
RUN apk add --no-cache nginx tor openssh-server tini \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh gw && passwd -u gw \
 && mkdir -p /home/gw/.ssh /var/lib/tor/hs /run/nginx \
 && chown -R tor /var/lib/tor && chmod 700 /var/lib/tor/hs
COPY config/nginx/default.conf /etc/nginx/http.d/default.conf
COPY config/tor/torrc /etc/tor/torrc
COPY config/ssh/sshd_config /etc/ssh/sshd_config
COPY --chown=gw:gw --chmod=600 config/ssh/authorized_keys /home/gw/.ssh/authorized_keys
COPY --chmod=755 entrypoint.sh /entrypoint.sh
EXPOSE 80 22
ENTRYPOINT ["/sbin/tini","--","/entrypoint.sh"]

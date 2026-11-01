ARG EDGE_BASE_IMAGE=debian:bookworm-slim
FROM ${EDGE_BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive \
    APACHE_RUN_DIR=/run/apache2 \
    APACHE_LOCK_DIR=/run/apache2 \
    APACHE_LOG_DIR=/run/apache2 \
    APACHE_PID_FILE=/run/apache2/apache2.pid \
    APACHE_RUN_USER=www-data \
    APACHE_RUN_GROUP=www-data \
    KRB5RCACHEDIR=/tmp

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      apache2 \
      libapache2-mod-auth-gssapi \
      curl \
      ca-certificates \
      python3-minimal \
      openssl \
 && rm -rf /var/lib/apt/lists/* \
 && a2enmod ssl headers proxy proxy_http ldap authnz_ldap auth_gssapi rewrite \
 && rm -f /etc/apache2/sites-enabled/000-default.conf \
 && printf '# Ports are declared in /run/apache2/radiance.conf\n' > /etc/apache2/ports.conf \
 && printf 'IncludeOptional /run/apache2/radiance.conf\n' > /etc/apache2/conf-enabled/zz-radiance.conf \
 && mkdir -p /var/www/health /run/apache2 /run/radiance

COPY render.py /opt/edge/render.py
COPY vhost.conf.tmpl /opt/edge/vhost.conf.tmpl
COPY health/healthz /var/www/health/healthz
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh /opt/edge/render.py \
 && chmod 0644 /var/www/health/healthz /opt/edge/vhost.conf.tmpl

EXPOSE 8443 8081
ENTRYPOINT ["/entrypoint.sh"]

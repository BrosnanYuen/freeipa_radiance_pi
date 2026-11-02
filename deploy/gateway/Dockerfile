ARG GATEWAY_BASE_IMAGE=debian:bookworm-slim
FROM ${GATEWAY_BASE_IMAGE}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    KRB5RCACHEDIR=/tmp/gateway

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 \
      python3-gssapi \
      python3-ldap \
      ca-certificates \
      curl \
      openssl \
      util-linux \
      libkrb5-3 \
      libsasl2-2 \
      libldap-2.5-0 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 gateway \
 && useradd --system --uid 10001 --gid gateway --no-create-home --shell /usr/sbin/nologin gateway

COPY gateway.py /opt/gateway/gateway.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh /opt/gateway/gateway.py \
 && python3 -m py_compile /opt/gateway/gateway.py

EXPOSE 8443 8081
ENTRYPOINT ["/entrypoint.sh"]

ARG PI_BASE_IMAGE=node:22-bookworm
FROM ${PI_BASE_IMAGE}

ARG PI_VERSION
ARG PI_INTEGRITY

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN test -n "$PI_VERSION" && test -n "$PI_INTEGRITY"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      krb5-user \
      python3 \
      python3-gssapi \
      ripgrep \
 && rm -rf /var/lib/apt/lists/*

# Install Pi from the exact tarball and verify the registry integrity value.
RUN set -eux; \
    npm pack "@earendil-works/pi-coding-agent@${PI_VERSION}" \
        --pack-destination /tmp >/dev/null; \
    set -- /tmp/earendil-works-pi-coding-agent-*.tgz; \
    pkg="$1"; \
    node -e 'const crypto=require("crypto"),fs=require("fs"); \
      const h=crypto.createHash("sha512").update(fs.readFileSync(process.argv[1])).digest("base64"); \
      if ("sha512-"+h !== process.argv[2]) { console.error("npm tarball integrity mismatch"); process.exit(1); }' \
      "$pkg" "${PI_INTEGRITY}"; \
    npm install -g --ignore-scripts "$pkg"; \
    rm -f "$pkg"; \
    npm cache clean --force; \
    pi --version

COPY radiance_krb /opt/radiance-krb/radiance_krb
RUN chmod -R a+rX /opt/radiance-krb

RUN printf '%s\n' \
      '#!/bin/sh' \
      'set -eu' \
      'export PYTHONPATH="/opt/radiance-krb${PYTHONPATH:+:$PYTHONPATH}"' \
      'exec /usr/bin/python3 -m radiance_krb.token "$@"' \
      > /usr/local/bin/radiance-krb-token \
 && printf '%s\n' \
      '#!/bin/sh' \
      'set -eu' \
      'export PYTHONPATH="/opt/radiance-krb${PYTHONPATH:+:$PYTHONPATH}"' \
      'exec /usr/bin/python3 -m radiance_krb.shim "$@"' \
      > /usr/local/bin/radiance-krb-shim \
 && printf '%s\n' \
      '#!/bin/sh' \
      'set -eu' \
      'export PYTHONPATH="/opt/radiance-krb${PYTHONPATH:+:$PYTHONPATH}"' \
      'exec /usr/bin/python3 -m radiance_krb.pi_krb "$@"' \
      > /usr/local/bin/pi-krb \
 && chmod 0755 \
      /usr/local/bin/radiance-krb-token \
      /usr/local/bin/radiance-krb-shim \
      /usr/local/bin/pi-krb

# The shim and the agent run as the host UID/GID supplied by Compose.
CMD ["sleep", "infinity"]

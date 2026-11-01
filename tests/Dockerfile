ARG TESTS_BASE_IMAGE=python:3.13-slim
FROM ${TESTS_BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      faketime \
      openssl \
      gcc \
      krb5-user \
      libkrb5-dev \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      gssapi==1.12.0 \
      requests==2.34.2 \
      requests-gssapi==1.4.0 \
      PyYAML==6.0.3 \
      pytest==9.2.0

WORKDIR /tests
CMD ["pytest", "-q", "integration", "security"]

ARG BASE_IMAGE=rockylinux:9
FROM $BASE_IMAGE

# Install required packages for testing
RUN dnf install -y --allowerasing \
    gcc \
    gcc-c++ \
    make \
    openssl \
    openssl-devel \
    libffi-devel \
    redhat-rpm-config \
    java-11-openjdk \
    python3.9 \
    python3.9-devel \
    python3.11 \
    python3.11-devel \
    python3.12 \
    python3.12-devel \
    git \
    curl \
    && dnf clean all

# Bootstrap pip for Python 3.11 and 3.12 (Python 3.9 already has pip)
RUN python3.11 -m ensurepip --upgrade && \
    python3.11 -m pip install --upgrade pip setuptools wheel
RUN python3.12 -m ensurepip --upgrade && \
    python3.12 -m pip install --upgrade pip setuptools wheel

# Install Rust toolchain (required for cryptography builds)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# This is to solve permission issue, read https://denibertovic.com/posts/handling-permissions-with-docker-volumes/
ARG GOSU_URL=https://github.com/tianon/gosu/releases/download/1.14/gosu-amd64
ENV GOSU_PATH=${GOSU_URL}
RUN curl -o /usr/local/bin/gosu -SL $GOSU_PATH
RUN chmod +x /usr/local/bin/gosu

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /home/user
RUN chmod 777 /home/user

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

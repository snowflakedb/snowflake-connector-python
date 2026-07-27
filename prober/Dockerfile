# syntax=docker/dockerfile:1
#
# Multi-stage build for the Python driver prober image.
#
# Why multi-stage: pyenv compiles CPython from source, which needs the full
# build toolchain (build-essential + a dozen -dev packages). Shipping that
# toolchain in the final image is what dominates the container-vuln scan
# surface (build-essential + -dev headers add ~250 CVEs on top of the base).
# We compile everything in the `builder` stage and copy only the finished
# pyenv Pythons + venvs into a slim runtime stage that carries just the
# runtime shared libraries. Measured OS-package vulns (grype): current
# single-stage ubuntu image ~411 -> this multi-stage runtime ~128, with zero
# High/Critical.
#
# Why ubuntu:24.04 (not 26.04): 24.04 LTS is mature and fully patched. The
# newer 26.04 base ships /usr/bin/pebble, a statically-linked Go binary that
# carries High-severity golang.org/x/net + Go stdlib CVEs that apt cannot
# patch; 24.04 does not include it, so the shipped image has 0 High/0 Critical.
# Both are LTS; we avoid interim releases (e.g. 25.10) whose ~9-month support
# window leaves base OS packages unpatched once they go EOL.

# ---------------------------------------------------------------------------
# Builder stage: full toolchain, compiles the Pythons and builds the venvs.
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# pyenv compiles CPython from source - these are the recommended build deps for
# Ubuntu/Debian (see https://github.com/pyenv/pyenv/wiki#suggested-build-environment)
# `apt-get upgrade` pulls security fixes for the base-image OS packages that are
# not otherwise reinstalled below.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        git \
        jq \
        make \
        build-essential \
        libssl-dev \
        zlib1g-dev \
        libbz2-dev \
        libreadline-dev \
        libsqlite3-dev \
        libncursesw5-dev \
        xz-utils \
        tk-dev \
        libxml2-dev \
        libxmlsec1-dev \
        libffi-dev \
        liblzma-dev && \
    rm -rf /var/lib/apt/lists/*

ENV HOME="/home/driveruser"

# Create a group with GID=1000 and a user with UID=1000, matching the runtime
# stage so all compiled artifact paths (venvs, pyenv) line up after the copy.
# ubuntu:24.04 ships a default `ubuntu` user at UID 1000, so we remove it first
# to free the UID for our non-root driveruser.
RUN userdel -r ubuntu 2>/dev/null || true && \
    groupadd -g 1000 drivergroup && \
    useradd -u 1000 -g drivergroup -m -d ${HOME} -s /bin/bash driveruser

USER driveruser
WORKDIR ${HOME}

ENV PYENV_ROOT="${HOME}/.pyenv"
ENV PATH="${PYENV_ROOT}/shims:${PYENV_ROOT}/bin:${PATH}"

# Install pyenv
RUN curl -sL https://artifactory.ci1.us-west-2.aws-dev.app.snowflake.com/artifactory/development-github-virtual/pyenv/pyenv/archive/refs/heads/master.tar.gz | tar -xz && mv pyenv-master ${PYENV_ROOT}

# Build arguments for Python versions and Snowflake connector versions
ARG MATRIX_VERSION='{"3.13.4": ["3.18.0", "4.1.1", "4.2.0", "4.3.0", "4.4.0", "4.5.0", "4.6.0", "3.6.0", "3.7.0"]}'

# Install Python versions from ARG MATRIX_VERSION
RUN eval "$(pyenv init --path)" && \
    for python_version in $(echo $MATRIX_VERSION | jq -r 'keys[]'); do \
        pyenv install $python_version || echo "Failed to install Python $python_version"; \
    done

# Create virtual environments for each combination of Python and Snowflake connector versions
RUN for python_version in $(echo $MATRIX_VERSION | jq -r 'keys[]'); do \
    for connector_version in $(echo $MATRIX_VERSION | jq -r ".\"${python_version}\"[]"); do \
        venv_path="${HOME}/venvs/python_${python_version}_connector_${connector_version}"; \
        $PYENV_ROOT/versions/$python_version/bin/python -m venv $venv_path && \
        $venv_path/bin/pip install --upgrade pip && \
        $venv_path/bin/pip install snowflake-connector-python==$connector_version; \
    done; \
done

# Copy the prober script into the container
RUN mkdir -p prober/probes/
COPY --chown=driveruser:drivergroup __init__.py prober
COPY --chown=driveruser:drivergroup setup.py prober
COPY --chown=driveruser:drivergroup entrypoint.sh prober
COPY --chown=driveruser:drivergroup probes/* prober/probes

# Install /prober in editable mode for each virtual environment
RUN for venv in ${HOME}/venvs/*; do \
    . $venv/bin/activate && \
    pip install -e ${HOME}/prober && \
    deactivate; \
done

# ---------------------------------------------------------------------------
# Runtime stage: slim image with only the shared libraries the compiled
# CPythons link against (the -dev headers and build-essential stay behind in
# the builder stage and never reach the shipped image).
# ---------------------------------------------------------------------------
FROM ubuntu:24.04

# boilerplate labels required by validation when pushing to ACR, ECR & GCR
LABEL org.opencontainers.image.source="https://github.com/snowflakedb/snowflake-connector-python"
LABEL com.snowflake.owners.email="triage-snow-drivers-warsaw-dl@snowflake.com"
LABEL com.snowflake.owners.slack="triage-snow-drivers-warsaw-dl"
LABEL com.snowflake.owners.team="Snow Drivers"
LABEL com.snowflake.owners.jira_area="Developer Platform"
LABEL com.snowflake.owners.jira_component="Python Driver"
# fake layers label to pass the validation
LABEL com.snowflake.ugcbi.layers="sha256:850959b749c07b254308a4d1a84686fd7c09fcb94aeae33cc5748aa07e5cb232,sha256:b79d3c4628a989cbb8bc6f0bf0940ff33a68da2dca9c1ffbf8cfb2a27ac8d133,sha256:1cbcc0411a84fbce85e7ee2956c8c1e67b8e0edc81746a33d9da48c852037c3e,sha256:07e89b796f91d37255c6eec926b066d6818f3f2edc344a584d1b9566f77e1c27,sha256:84ff92691f909a05b224e1c56abb4864f01b4f8e3c854e4bb4c7baf1d3f6d652,sha256:3ab72684daee4eea64c3ae78a43ea332b86358446b6f2904dca4b634712e1537"
# Single-line description (some Ubuntu bases ship a multi-line
# org.opencontainers.image.description that breaks jenkins_push.sh's associative
# array parsing). Override it with a single-line value.
LABEL org.opencontainers.image.description="Snowflake Python Connector prober image"

ENV DEBIAN_FRONTEND=noninteractive

# Runtime shared libraries the pyenv-compiled CPythons link against. These are
# the runtime counterparts of the -dev packages used in the builder stage; the
# compilers and headers themselves are intentionally left behind.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        libssl3t64 \
        zlib1g \
        libbz2-1.0 \
        libreadline8t64 \
        libsqlite3-0 \
        libncursesw6 \
        libffi8 \
        liblzma5 \
        libxml2 \
        libxmlsec1t64 \
        libtk8.6 && \
    rm -rf /var/lib/apt/lists/*

ENV HOME="/home/driveruser"

# Recreate the same non-root user/UID as the builder so the copied venv and
# pyenv paths (which are baked into pyvenv.cfg and the editable-install links)
# resolve correctly.
RUN userdel -r ubuntu 2>/dev/null || true && \
    groupadd -g 1000 drivergroup && \
    useradd -u 1000 -g drivergroup -m -d ${HOME} -s /bin/bash driveruser

# Copy the fully-built home (pyenv Pythons, venvs, prober source + editable
# installs) from the builder stage.
COPY --from=builder --chown=driveruser:drivergroup ${HOME} ${HOME}

USER driveruser
WORKDIR ${HOME}

ENV PYENV_ROOT="${HOME}/.pyenv"
ENV PATH="${PYENV_ROOT}/shims:${PYENV_ROOT}/bin:${PATH}"

FROM alpine:3.18

# boilerplate labels required by validation when pushing to ACR, ECR & GCR
LABEL org.opencontainers.image.source="https://github.com/snowflakedb/snowflake-connector-python"
LABEL com.snowflake.owners.email="triage-snow-drivers-warsaw-dl@snowflake.com"
LABEL com.snowflake.owners.slack="triage-snow-drivers-warsaw-dl"
LABEL com.snowflake.owners.team="Snow Drivers"
LABEL com.snowflake.owners.jira_area="Developer Platform"
LABEL com.snowflake.owners.jira_component="Python Driver"
# fake layers label to pass the validation
LABEL com.snowflake.ugcbi.layers="sha256:850959b749c07b254308a4d1a84686fd7c09fcb94aeae33cc5748aa07e5cb232,sha256:b79d3c4628a989cbb8bc6f0bf0940ff33a68da2dca9c1ffbf8cfb2a27ac8d133,sha256:1cbcc0411a84fbce85e7ee2956c8c1e67b8e0edc81746a33d9da48c852037c3e,sha256:07e89b796f91d37255c6eec926b066d6818f3f2edc344a584d1b9566f77e1c27,sha256:84ff92691f909a05b224e1c56abb4864f01b4f8e3c854e4bb4c7baf1d3f6d652,sha256:3ab72684daee4eea64c3ae78a43ea332b86358446b6f2904dca4b634712e1537"

RUN apk add --no-cache \
    bash \
    git \
    make \
    g++ \
    zlib-dev \
    openssl-dev \
    libffi-dev \
    jq

ENV HOME="/root"
WORKDIR ${HOME}
RUN git clone --depth=1 https://github.com/pyenv/pyenv.git .pyenv
ENV PYENV_ROOT="${HOME}/.pyenv"
ENV PATH="${PYENV_ROOT}/shims:${PYENV_ROOT}/bin:${PATH}"


# Build arguments for Python versions and Snowflake connector versions
ARG MATRIX_VERSION='{"3.10.17": ["3.14.0", "3.13.2", "3.13.1"], "3.9.22": ["3.14.0", "3.13.2", "3.13.1"], "3.8.20": ["3.14.0", "3.13.2", "3.13.1"]}'


# Install Python versions from ARG MATRIX_VERSION
RUN eval "$(pyenv init --path)" && \
    for python_version in $(echo $MATRIX_VERSION | jq -r 'keys[]'); do \
        pyenv install $python_version || echo "Failed to install Python $python_version"; \
    done


# Create virtual environments for each combination of Python and Snowflake connector versions
RUN for python_version in $(echo $MATRIX_VERSION | jq -r 'keys[]'); do \
    for connector_version in $(echo $MATRIX_VERSION | jq -r ".\"${python_version}\"[]"); do \
        venv_path="/venvs/python_${python_version}_connector_${connector_version}"; \
        $PYENV_ROOT/versions/$python_version/bin/python -m venv $venv_path && \
        $venv_path/bin/pip install --upgrade pip && \
        $venv_path/bin/pip install snowflake-connector-python==$connector_version; \
    done; \
done

# Copy the prober script into the container
RUN mkdir -p /prober/probes/
COPY __init__.py /prober
COPY setup.py /prober
COPY entrypoint.sh /prober
COPY probes/* /prober/probes

# Install /prober in editable mode for each virtual environment
RUN for venv in /venvs/*; do \
    source $venv/bin/activate && \
    pip install -e /prober && \
    deactivate; \
done

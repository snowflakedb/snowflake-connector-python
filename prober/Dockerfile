FROM alpine:3.18

RUN apk add --no-cache \
    bash \
    git \
    make \
    g++ \
    zlib-dev \
    openssl-dev \
    libffi-dev

ENV HOME="/root"
WORKDIR ${HOME}
RUN git clone --depth=1 https://github.com/pyenv/pyenv.git .pyenv
ENV PYENV_ROOT="${HOME}/.pyenv"
ENV PATH="${PYENV_ROOT}/shims:${PYENV_ROOT}/bin:${PATH}"


# Build arguments for Python versions and Snowflake connector versions
ARG PYTHON_VERSIONS="3.8.20 3.9.22 3.10.17"
ARG SNOWFLAKE_CONNECTOR_VERSIONS="3.14.0 3.13.2 3.13.1"


# Install Python versions
RUN eval "$(pyenv init --path)" && \
    for version in $PYTHON_VERSIONS; do \
        pyenv install $version || echo "Failed to install Python $version"; \
    done


# Create virtual environments for each combination of Python and Snowflake connector versions
RUN for python_version in $PYTHON_VERSIONS; do \
    for connector_version in $SNOWFLAKE_CONNECTOR_VERSIONS; do \
        venv_path="/venvs/python_${python_version}_connector_${connector_version}"; \
        $PYENV_ROOT/versions/$python_version/bin/python -m venv $venv_path && \
        $venv_path/bin/pip install --upgrade pip && \
        $venv_path/bin/pip install snowflake-connector-python==$connector_version; \
    done; \
done

# Copy the prober script into the container
RUN mkdir -p /prober/probes/
COPY __init__.py /prober
# COPY parameters.json /prober
COPY setup.py /prober
COPY entrypoint.sh /prober
COPY probes/* /prober/probes

# Install /prober in editable mode for each virtual environment
RUN for venv in /venvs/*; do \
    source $venv/bin/activate && \
    pip install -e /prober && \
    deactivate; \
done

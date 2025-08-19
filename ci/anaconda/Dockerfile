
# Use different base images based on target platform
ARG ARCH
FROM artifactory.int.snowflakecomputing.com/development-docker-virtual/arm64v8/centos:8 AS base-aarch64
FROM artifactory.int.snowflakecomputing.com/development-docker-virtual/centos:8 AS base-x86_64

# Select the appropriate base image based on target architecture
FROM base-${ARCH} AS base
COPY miniconda-install.sh .

RUN chmod 0755 miniconda-install.sh

RUN mkdir -p /etc/miniconda && bash miniconda-install.sh -b -u -p /etc/miniconda/

RUN ln -s /etc/miniconda/bin/conda /usr/bin/conda && rm miniconda-install.sh

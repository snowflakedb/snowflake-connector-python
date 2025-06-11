#
# Dockerfile to build container with conda aarch64
# Used for stored_proc anaconda
#   Author: John Lin
#
FROM artifactory.int.snowflakecomputing.com/development-docker-virtual/arm64v8/centos:8

COPY miniconda_anaconda_aarch64.sh .

RUN chmod 0755 miniconda_anaconda_aarch64.sh

RUN mkdir -p /etc/miniconda && bash miniconda_anaconda_aarch64.sh -b -u -p /etc/miniconda/

RUN ln -s /etc/miniconda/bin/conda /usr/bin/conda && rm miniconda_anaconda_aarch64.sh

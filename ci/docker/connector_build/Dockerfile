ARG BASE_IMAGE=quay.io/pypa/manylinux2014_x86_64
FROM $BASE_IMAGE

# This is to solve permission issue, read https://denibertovic.com/posts/handling-permissions-with-docker-volumes/
ARG GOSU_URL=https://artifactory.ci1.us-west-2.aws-dev.app.snowflake.com/artifactory/development-github-virtual/tianon/gosu/releases/download/1.14/gosu-amd64
ENV GOSU_PATH $GOSU_URL
RUN curl -o /usr/local/bin/gosu -SL $GOSU_PATH
RUN chmod +x /usr/local/bin/gosu

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /home/user
RUN chmod 777 /home/user
RUN curl -sL https://artifactory.ci1.us-west-2.aws-dev.app.snowflake.com/artifactory/development-github-virtual/matthew-brett/multibuild/archive/bfc6d8b82d8c37b8ca1e386081fd800e81c6ab4a.tar.gz | tar -xz && mv multibuild-bfc6d8b82d8c37b8ca1e386081fd800e81c6ab4a multibuild

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

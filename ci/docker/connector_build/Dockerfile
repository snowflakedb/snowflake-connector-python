# We use manylinux1 base image because pyarrow_manylinux2010 has a bug and wheel failed to be audited
ARG BASE_IMAGE=quay.io/pypa/manylinux2010_x86_64
FROM $BASE_IMAGE

# This is to solve permission issue, read https://denibertovic.com/posts/handling-permissions-with-docker-volumes/
ARG GOSU_URL=https://github.com/tianon/gosu/releases/download/1.11/gosu-amd64
ENV GOSU_PATH $GOSU_URL
RUN curl -o /usr/local/bin/gosu -SL $GOSU_PATH
RUN chmod +x /usr/local/bin/gosu

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /home/user
RUN chmod 777 /home/user
RUN git clone https://github.com/matthew-brett/multibuild.git && cd /home/user/multibuild && git checkout bfc6d8b82d8c37b8ca1e386081fd800e81c6ab4a

ENV PATH="${PATH}:/opt/python/cp36-cp36m/bin:/opt/python/cp37-cp37m/bin:/opt/python/cp38-cp38/bin:/opt/python/cp39-cp39/bin:/opt/python/cp310-cp310/bin"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

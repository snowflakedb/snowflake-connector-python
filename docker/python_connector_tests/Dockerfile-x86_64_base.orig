# We use manylinux1 base image because pyarrow_manylinux2010 has a bug and wheel failed to be audited
ARG BASE_IMAGE
FROM $BASE_IMAGE

# This is to solve permission issue, read https://denibertovic.com/posts/handling-permissions-with-docker-volumes/
RUN curl -o /usr/local/bin/gosu -SL "https://github.com/tianon/gosu/releases/download/1.11/gosu-amd64"
RUN chmod +x /usr/local/bin/gosu

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh


WORKDIR /home/user
RUN chmod 777 /home/user
ENV PATH="${PATH}:/opt/python/cp35-cp35m/bin:/opt/python/cp36-cp36m/bin:/opt/python/cp37-cp37m/bin:/opt/python/cp38-cp38/bin/"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

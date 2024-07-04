FROM centos:8

# This is to solve permission issue, read https://denibertovic.com/posts/handling-permissions-with-docker-volumes/
RUN curl -o /usr/local/bin/gosu -SL "https://github.com/tianon/gosu/releases/download/1.14/gosu-amd64"
RUN chmod +x /usr/local/bin/gosu

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /home/user
RUN chmod 777 /home/user

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo && \
    sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo && \
    sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo

RUN yum clean all && \
    yum install -y redhat-rpm-config gcc libffi-devel openssl openssl-devel && \
    yum install -y python38 python38-devel && \
    yum clean all && \
    rm -rf /var/cache/yum
RUN python3 -m pip install --user --upgrade pip setuptools wheel

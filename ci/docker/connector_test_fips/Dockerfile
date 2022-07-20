FROM centos:7

# This is to solve permission issue, read https://denibertovic.com/posts/handling-permissions-with-docker-volumes/
RUN curl -o /usr/local/bin/gosu -SL "https://github.com/tianon/gosu/releases/download/1.11/gosu-amd64"
RUN chmod +x /usr/local/bin/gosu

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /home/user
RUN chmod 777 /home/user

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

RUN yum install -y redhat-rpm-config gcc libffi-devel openssl openssl-devel centos-release-scl
RUN yum install -y rh-python38 rh-python38-python-devel
RUN scl enable rh-python38 "python3.8 -m pip install --user --upgrade pip setuptools wheel"

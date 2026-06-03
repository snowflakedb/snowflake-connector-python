FROM rockylinux:9

# This is to solve permission issue, read https://denibertovic.com/posts/handling-permissions-with-docker-volumes/
RUN curl -o /usr/local/bin/gosu -SL "https://github.com/tianon/gosu/releases/download/1.14/gosu-amd64"
RUN chmod +x /usr/local/bin/gosu

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /home/user
RUN chmod 777 /home/user

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

RUN dnf clean all && \
    dnf install -y redhat-rpm-config gcc libffi-devel openssl openssl-devel && \
    dnf install -y python3.11 python3.11-devel && \
    dnf install -y java-11-openjdk && \
    dnf clean all && \
    rm -rf /var/cache/dnf
RUN python3.11 -m ensurepip --upgrade && \
    python3.11 -m pip install --user --upgrade pip setuptools wheel

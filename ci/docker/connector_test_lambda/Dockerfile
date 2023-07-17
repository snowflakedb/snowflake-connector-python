FROM public.ecr.aws/lambda/python:3.8

RUN yum install -y git

WORKDIR /home/user
RUN chmod 777 /home/user
ENV PATH="${PATH}:/opt/python/cp38-cp38/bin/"

RUN pip3 install --upgrade pip setuptools wheel tox

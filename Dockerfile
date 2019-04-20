FROM ubuntu:17.10

RUN apt-get update -qy && apt-get upgrade -y && \
    apt-get install -y iputils-ping python-pip python3-pip
RUN apt-get install -y iproute2

ADD . isis
WORKDIR isis

RUN pip3 install -U -r requirements.txt
RUN pip3 install -e .

ENTRYPOINT [ "pyisis" ]

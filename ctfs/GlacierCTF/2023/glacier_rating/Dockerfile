FROM ubuntu:22.04

RUN apt -y update
RUN apt -y upgrade
RUN apt -y install socat

EXPOSE 5000

RUN mkdir /app
WORKDIR /app

COPY ./app .
COPY ./libc.so.6 .
COPY ./libm.so.6 .
COPY ./ld-linux-x86-64.so.2 .
COPY ./libstdc++.so.6 .
COPY ./flag.txt .

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:./app"]


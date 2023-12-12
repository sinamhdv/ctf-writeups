FROM ubuntu:22.04

RUN apt -y update
RUN apt -y upgrade
RUN apt -y install python3 socat

EXPOSE 5000

RUN mkdir /app
WORKDIR /app

COPY ./vuln .
COPY generate_files.py .
RUN python3 generate_files.py

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:./vuln"]


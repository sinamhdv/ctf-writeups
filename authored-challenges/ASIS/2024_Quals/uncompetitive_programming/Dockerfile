FROM ubuntu:24.04

RUN useradd -m user

RUN apt -y update && apt -y upgrade
RUN apt -y install socat

WORKDIR /home/user
COPY chall .
RUN echo "flag{placeholder_for_flag}" > ./flag.txt

RUN chown -R root:root /home/user
RUN chmod -R 555 /home/user

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:'su user -c ./chall'"]

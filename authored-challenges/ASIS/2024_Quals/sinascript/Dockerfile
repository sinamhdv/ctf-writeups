FROM ubuntu:24.04

RUN useradd -m user

RUN apt -y update && apt -y upgrade
RUN apt -y install socat python3 python-is-python3

WORKDIR /home/user
COPY sinascript .
COPY ld-linux-x86-64.so.2 .
COPY libc.so.6 .
COPY run.py .
RUN echo "flag{placeholder_for_flag}" > ./flag.txt

RUN chown -R root:root /home/user
RUN chmod -R 555 /home/user

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:'su user -c ./run.py'"]

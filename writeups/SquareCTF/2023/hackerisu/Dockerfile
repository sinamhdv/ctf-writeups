FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install -y socat locales
RUN locale-gen en_US.UTF-8

RUN groupadd --gid 995 ctf
RUN useradd -m --uid 995 --gid 995 ctf

COPY ./game-distr.out /home/ctf/game-distr.out

WORKDIR /home/ctf/
EXPOSE 5000:5000
USER ctf

ENV LANG en_US.UTF-8

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:./game-distr.out,pty,echo=0"]


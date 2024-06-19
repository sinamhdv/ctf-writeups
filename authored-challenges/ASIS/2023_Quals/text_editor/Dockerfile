FROM ubuntu@sha256:aabed3296a3d45cede1dc866a24476c4d7e093aa806263c27ddaadbdce3c1054
RUN apt-get update
# RUN apt-get upgrade -y
RUN apt-get install xinetd -y
RUN useradd -m pwn
COPY ./xinetd.conf /etc/xinetd.d/xinetd
COPY ./chall /home/pwn/
RUN echo 'flag{placeholder_for_flag}' > /home/pwn/flag.txt
RUN chown -R root:root /home/pwn
RUN chmod -R 555 /home/pwn 
CMD ["/usr/sbin/xinetd","-dontfork"]

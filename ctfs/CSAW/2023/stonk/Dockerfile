FROM ubuntu

RUN apt-get update
RUN apt-get install -y python3 python3-pip
RUN pip install flask

RUN groupadd --gid 995 ctf
RUN useradd -m --uid 995 --gid 995 ctf

COPY ./app.py /home/ctf/app.py
COPY ./process.py /home/ctf/process.py
COPY ./flag.txt /home/ctf/flag.txt

WORKDIR /home/ctf/
EXPOSE 4657:4657
USER ctf

CMD ["python3", "app.py"]

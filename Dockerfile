# syntax=docker/dockerfile:1

FROM python:3.8-slim-buster

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY ocv ocv

ENTRYPOINT [ "python3", "ocv/run.py", "--batfish_host", "host.docker.internal", "/snap" ]

# syntax=docker/dockerfile:1

FROM python:3.8-slim-buster

#FROM ubuntu:20.04

RUN apt-get update && apt-get -y install telnet

WORKDIR /longevity

COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

COPY data_collector_pro.py . 

EXPOSE 8000

ENTRYPOINT ["python3", "./data_collector_pro.py"]

CMD ["10.195.78.254", "Router", "-p", "8765"]


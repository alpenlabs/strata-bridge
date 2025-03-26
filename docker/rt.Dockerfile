FROM --platform=linux/amd64 ubuntu:24.04
WORKDIR /app

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y curl
RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/*

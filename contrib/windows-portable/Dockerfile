FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends build-essential autoconf automake libtool pkg-config bsdextrautils python3 git curl ca-certificates g++-mingw-w64-x86-64-win32 gcc-mingw-w64-x86-64-win32 mingw-w64-x86-64-dev cmake zip unzip xz-utils file patch && rm -rf /var/lib/apt/lists/*

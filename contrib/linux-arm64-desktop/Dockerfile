FROM ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends build-essential autoconf automake libtool pkg-config bsdmainutils python3 ca-certificates curl xz-utils bzip2 patch file patchelf libssl-dev libevent-dev qtbase5-dev qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler libqrencode-dev libdbus-1-dev && rm -rf /var/lib/apt/lists/*

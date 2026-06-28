FROM --platform=linux/amd64 ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y \
    git \
    build-essential \
    wget \
    zlib1g-dev \
    python3 \
    python3-pip \
    python3-dev \
    cmake && \
    vim && \
    apt-get clean

# Install Go — x86_64 binary
RUN wget https://go.dev/dl/go1.18.10.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.18.10.linux-amd64.tar.gz && \
    rm go1.18.10.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin

WORKDIR /untracer_llvm

COPY ./build/install_llvm.sh ./build/install_llvm.sh
RUN PREFIX=/ ./build/install_llvm.sh

COPY ./build/install_tools.sh ./build/install_tools.sh
RUN ./build/install_tools.sh

COPY . .
RUN ./build/build.sh

VOLUME ["/data"]
CMD ["/bin/bash"]
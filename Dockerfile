FROM ubuntu:25.04

WORKDIR /home/ubuntu 

# Install system dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    libgmp-dev \
    libboost-all-dev \
    libcrypto++-dev \
    libgmpxx4ldbl \
    libgmp10 \
    libssl3 \
    zlib1g-dev \
    git \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-dev \
    libffi-dev \
    libssl-dev \
    tcpdump \
    wget \
    iproute2 \
    linux-perf

# Copies the src code into the container
COPY ./src /home/ubuntu/src

#Compiles and Install Catch2 and volePSI libraries 
WORKDIR /home/ubuntu
COPY ./install-dependencies.sh /home/ubuntu/install-dependencies.sh
RUN chmod +x /home/ubuntu/install-dependencies.sh
RUN /home/ubuntu/install-dependencies.sh
RUN touch /home/ubuntu/volepsi/include/volePSI/config.h

RUN git clone --branch sparsehash-2.0.4 https://github.com/sparsehash/sparsehash.git /home/ubuntu/sparsehash

RUN cd /home/ubuntu/sparsehash && ./configure && make && make install

RUN git clone --branch v0.8.2 --depth 1 https://github.com/Cyan4973/xxHash.git /home/ubuntu/xxHash && \
    cd /home/ubuntu/xxHash && make CFLAGS="-O3 -march=native" XXH_INLINE_ALL="ON" && make install

RUN git clone --branch v4.5.0 --depth 1 https://github.com/martinus/unordered_dense.git /home/ubuntu/unordered_dense && \
    cd /home/ubuntu/unordered_dense && mkdir build && cd build && \
    cmake .. && cmake --build . --target install

WORKDIR /home/ubuntu/src
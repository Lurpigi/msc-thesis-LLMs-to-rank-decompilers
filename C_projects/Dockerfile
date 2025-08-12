FROM ubuntu:24.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y build-essential git wget
    #crispy-doom dependencies
    #apt install -y autoconf && \
    #apt install -y libsdl2-2.0-0 libsdl2-dev libsdl2-gfx-1.0-0 libsdl2-gfx-dev libsdl2-image-2.0-0 libsdl2-image-dev libsdl2-mixer-2.0-0 libsdl2-mixer-dev libsdl2-net-2.0-0 libsdl2-net-dev


WORKDIR /app
RUN mkdir -p bin

##crispy-doom

#COPY crispy-doom /app/crispy-doom
#WORKDIR /app/crispy-doom
#RUN autoreconf -fiv && autoconf && ./configure && make

##calculator

COPY calculator /app/calculator
WORKDIR /app/calculator
RUN make all

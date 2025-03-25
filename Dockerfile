ARG DEBIAN_VERSION="12.9"

FROM --platform=$BUILDPLATFORM ubuntu:24.04 as builder

# Set the working directory to /artifacts
WORKDIR /artifacts

# Create the subdirectories for amd64 and arm64 in a single RUN command
RUN mkdir -p linux/amd64 linux/arm64


COPY localbin/udp-tracer linux/amd64/
# COPY linux/arm64/trace-udp linux/arm64/

FROM debian:${DEBIAN_VERSION}-slim

ARG TARGETPLATFORM

ENV DEBIAN_FRONTEND=noninteractive

# RUN rm /var/lib/dpkg/info/libc-bin.*
# RUN apt-get clean && apt-get update &&  apt-get install libc-bin -y
RUN apt-get update && apt-get install -y util-linux iproute2 libelf-dev

COPY --from=builder --chown=root:root --chmod=0755 /artifacts/$TARGETPLATFORM/udp-tracer /usr/local/bin

ENTRYPOINT ["/usr/local/bin/udp-tracer"]

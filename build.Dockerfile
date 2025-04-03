#ARG BASE_IMAGE=alpine
#ARG BASE_IMAGE_VERSION=3.17
ARG BASE_IMAGE=debian
ARG BASE_IMAGE_VERSION=bookworm
ARG BUILD_IMAGE=ocaml/opam
#ARG BUILD_IMAGE_VERSION=alpine-3.17-ocaml-4.14
ARG BUILD_IMAGE_VERSION=debian-12-ocaml-4.14
ARG RUST_VERSION=1.82.0
## The above default works if the built machine doesn't change and keeps layers cached.
## Alternatively, `build.Dockerfile` can be used to prepare a builder image to use as a base.
## docker build . -t internal-trace-consumer:build --target builder
# ARG BUILD_IMAGE=internal-trace-consumer
# ARG BUILD_IMAGE_VERSION=build
## Remote trace fetcher program (Rust)
FROM rust:${RUST_VERSION}-${BASE_IMAGE_VERSION}
#RUN apk add --no-cache libgcc libstdc++ openssl openssl-dev musl-dev
RUN apt-get update \
  && apt-get install -y pkg-config libssl-dev \
  && rm -rf /var/lib/apt/lists/*
# These RUSTFLAGS are required to properly build an alpine binary
# linked to OpenSSL that doesn't segfault
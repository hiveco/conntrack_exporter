# BUILDER IMAGE

FROM gcr.io/bazel-public/bazel:6.4.0 AS builder

USER root

RUN set -ex; \
    apt-get update -qq; \
    DEBIAN_FRONTEND=noninteractive apt-get install -qqy --no-install-recommends \
        libnetfilter-conntrack-dev

WORKDIR /src
ADD . /src/


# DEBUG BUILD

FROM builder AS build_debug

RUN bazel build -c dbg //:conntrack_exporter


# RELEASE BUILD

FROM builder AS build_release

RUN bazel build --strip=always -c opt //:conntrack_exporter


# BASE IMAGE

FROM ubuntu:22.04 AS base

RUN set -ex; \
    apt-get update -qq; \
    DEBIAN_FRONTEND=noninteractive apt-get install -qqy --no-install-recommends \
        libnetfilter-conntrack-dev

ENTRYPOINT ["conntrack_exporter"]


# DEBUG IMAGE

FROM base AS debug

COPY --from=build_debug /src/bazel-bin/conntrack_exporter /bin/


# RELEASE IMAGE

FROM base AS release

COPY --from=build_release /src/bazel-bin/conntrack_exporter /bin/

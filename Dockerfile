FROM ubuntu:16.04

RUN set -ex; \
    apt-get update -qq; \
    DEBIAN_FRONTEND=noninteractive apt-get install -qqy --no-install-recommends \
        libnetfilter-conntrack-dev

ADD conntrack_exporter /bin/

ENTRYPOINT ["conntrack_exporter"]

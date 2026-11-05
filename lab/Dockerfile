FROM alpine:3.22 AS build
RUN apk add --no-cache g++ make ncurses-dev ncurses-static linux-headers
WORKDIR /src
COPY Makefile ./
COPY src ./src
ARG VERSION=dev
RUN make wgmon VERSION=$VERSION LDFLAGS=-static && strip wgmon

# `make dist` exports just the static binary
FROM scratch AS out
COPY --from=build /src/wgmon /wgmon

# lab node: the same image runs as vps, phone and laptop
FROM alpine:3.22 AS lab
RUN apk add --no-cache wireguard-tools-wg iproute2 iptables bind-tools curl ncurses-terminfo-base
COPY --from=build /src/wgmon /usr/local/bin/wgmon
COPY lab/net.sh /usr/local/bin/net.sh

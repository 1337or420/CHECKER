# Stage 1: build
FROM golang:1.23-bookworm AS builder

WORKDIR /src
COPY scripts/ /src/

RUN test -f /src/go.mod

ENV CGO_ENABLED=0 GOOS=linux
RUN go mod download || true

RUN set -eux; \
    mkdir -p /out; \
    for cmd in csicl vpn routes nmap nxc ldapenum kerbrute reporter; do \
        go build -trimpath -ldflags="-s -w" -o /out/$cmd ./cmd/$cmd; \
    done

# Stage 2: runtime
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
        openconnect ldap-utils nmap python3 python3-pip python3-venv \
        python3-dev \
        pipx git curl wget ca-certificates iproute2 net-tools iputils-ping \
        iptables bind9-dnsutils \
        build-essential libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# nxc: стабильный релиз вместо master
RUN pipx install "git+https://github.com/Pennyw0rth/NetExec@v1.3.0"
ENV PATH="/root/.local/bin:${PATH}"

RUN set -eux; \
    KERB_VER=1.0.3; \
    curl -sSL -o /usr/local/bin/kerbrute \
      "https://github.com/ropnop/kerbrute/releases/download/v${KERB_VER}/kerbrute_linux_amd64"; \
    chmod +x /usr/local/bin/kerbrute

RUN mkdir -p /dev/net && \
    mknod /dev/net/tun c 10 200 2>/dev/null || true && \
    chmod 666 /dev/net/tun 2>/dev/null || true

COPY --from=builder /out/ /app/bin/
RUN chmod +x /app/bin/*

WORKDIR /app/work
ENTRYPOINT ["/app/bin/csicl"]
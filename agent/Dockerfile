FROM alpine:3.24

ARG VERSION=0.32.1
ENV PF_VERSION=${VERSION} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# libnatpmp provides natpmpc (Proton NAT-PMP), wireguard-tools provides wg + wg-quick, openssl the ACME keys and
# signatures, openssh-client the ssh of user redirect scripts
RUN apk add --no-cache python3 libnatpmp wireguard-tools iproute2 iptables openssl ca-certificates openssh-client tzdata

WORKDIR /app
COPY entrypoint.sh /app/entrypoint.sh
COPY app/ /app/app/
COPY web/ /app/web/
COPY examples/ /app/examples/
RUN chmod 755 /app/entrypoint.sh

EXPOSE 8090
VOLUME ["/data"]
ENTRYPOINT ["/app/entrypoint.sh"]

#!/bin/sh
# Lab node setup. Runs inside its container's own network namespace; the host is never touched.
#   net.sh vps
#   net.sh client NAME TUNNEL_IP DNS
set -eu
K=/keys

if [ "$1" = vps ]; then
    rm -f $K/*
    umask 077
    for n in vps phone laptop; do wg genkey | tee $K/$n.key | wg pubkey > $K/$n.pub; done
    ip link add wg0 type wireguard
    wg set wg0 listen-port 51820 private-key $K/vps.key \
        peer "$(cat $K/phone.pub)" allowed-ips 10.8.0.2/32 \
        peer "$(cat $K/laptop.pub)" allowed-ips 10.8.0.3/32
    ip addr add 10.8.0.1/24 dev wg0
    ip link set wg0 up
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
    touch $K/ready
    exec sleep infinity
fi

name=$2 addr=$3 dns=$4
vps=$(getent hosts vps | awk '{print $1}')
gw=$(ip route | awk '/default/ {print $3}')
ip link add wg0 type wireguard
wg set wg0 private-key $K/$name.key \
    peer "$(cat $K/vps.pub)" endpoint "$vps:51820" allowed-ips 0.0.0.0/0 persistent-keepalive 25
ip addr add "$addr/24" dev wg0
ip link set wg0 up
ip route add "$vps/32" via "$gw"   # keep the tunnel itself on eth0
ip route replace default dev wg0    # everything else goes through the tunnel

# Generate some realistic traffic forever.
while :; do
    for d in example.com wikipedia.org github.com cloudflare.com; do
        dig +short @"$dns" "$d" A > /dev/null || true
        curl -s -o /dev/null --max-time 5 "https://$d" || true
    done
    curl -s -o /dev/null --max-time 5 http://neverssl.com || true
    ping -c 1 -W 2 1.1.1.1 > /dev/null || true
    sleep 5
done

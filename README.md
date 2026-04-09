# Honeypot 401 NGINX

## Why?

Just for fun and to learn how to build defensive security tools as a cybersecurity learner.

I wanted to create a true identical nginx `Unauthorized` response to trap attacker scanners
hitting my own server. Identical means same response headers, same content-length, and same behavior.

I use a fake basic auth realm as `phpMyAdmin` to make attackers think this server is worth targeting.
Behind the scenes, everything that hits the server gets logged for analysis.

I chose nginx version `1.29.6` in the fake header because it is a known vulnerable version
(CVE-2026-27654), which attracts scanners probing for unpatched servers.

I learned how to craft HTTP request and response bodies using the Echo framework in Go.
One challenge was Go's HTTP headers being canonicalized to lowercase automatically,
so I had to use direct map assignment to preserve exact casing.

I don't want to use real nginx as a reverse proxy to bind `public:443` and terminate the SSL certificate,
so I terminate the SSL certificate at my own server and use nftables to forward the port
from `public:443` to `loopback:8080` instead.

## Concept

```
# redirect (same network)
# e.g. a:443 to a:8080
client
public:443 (server)
nftables (redirect) from public:443 to public:8080
response (no masquerade)

# dnat (different network)
# e.g. a:443 to b:8080
client
public:443 (server)
nftables (dnat) prerouting from public:443 to dummy:8080
response (masquerade) postrouting from dummy:8080 to public:443
```

## Setup

```bash
# install trace tools
sudo apt install -y dnsutils nftables whois nmap tcpdump

# add nftable rules (forward port from 80 to 8080)
sudo nft add rule ip nat prerouting tcp dport 80 redirect to :8080
# or /etc/nftables.conf
table ip nat {
 chain prerouting {
  type nat hook prerouting priority dstnat; policy accept;
  tcp dport 80 redirect to :8080
 }
}

# safer no expose wildcard ip
# from dport 80 to 127.0.0.1:8080
table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100;
        tcp dport 80 dnat to 192.168.0.1:8080
    }

    chain postrouting {
        type nat hook postrouting priority 100;

        # rewrite dst to original client
        masquerade
    }
}

# create private network for reaching loopback (dummy)
sudo ip addr add 192.168.0.1/32 dev lo

# opsec
sudo passwd -l root
sudo ln -sf /dev/null .bash_history

# create new user with least privilege
sudo useradd --no-create-home --shell /usr/sbin/nologin pot

# run binary
sudo -u pot ./server

# simple monitoring
tail -f honeypot.log
ss -tulnp

sudo tcpdump -i eth0 src port https
sudo conntrack -E
sudo nft monitor trace
```

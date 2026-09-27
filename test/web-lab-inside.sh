#!/bin/sh
# Runs inside the web lab's container (see web-lab.sh). Prints PASS or FAIL
# per check and exits non-zero on the first failure.
set -u
API=http://127.0.0.1:8080
fail() { echo "FAIL: $*"; echo "--- flowsightd log"; tail -40 /var/log/fsd.log; echo "--- squid cache.log";
	tail -20 /var/log/flowsight/squid/cache.log 2>/dev/null; echo "--- nft"; nft list table inet flowsight; exit 1; }
pass() { echo "PASS: $*"; }
client() { ip netns exec client curl -s -m 5 "$@"; }
save() { curl -s -m 10 -H 'X-Requested-With: Flowsight' -H 'Content-Type: application/json' \
	-d "{\"module\":\"$1\",\"settings\":$2}" $API/api/system/modules/save; echo; }
apply() { curl -s -m 60 -X POST -H 'X-Requested-With: Flowsight' $API/api/policy/apply | head -c 300; echo; }
health() { curl -s -m 10 $API/api/system/health | tr -d '\n'; }
# wait_for <seconds> <command...>: true once the command succeeds.
wait_for() { n=$1; shift; while [ "$n" -gt 0 ]; do "$@" >/dev/null 2>&1 && return 0; sleep 1; n=$((n - 1)); done; return 1; }

# The network: a client LAN, and a server standing in for the internet.
sysctl -qw net.ipv4.ip_forward=1
ip netns add client; ip netns add server
ip link add vc type veth peer name vc0 netns client
ip link add vs type veth peer name vs0 netns server
ip addr add 10.10.0.1/24 dev vc; ip link set vc up
ip addr add 203.0.113.1/24 dev vs; ip link set vs up
ip -n client addr add 10.10.0.2/24 dev vc0; ip -n client link set vc0 up; ip -n client link set lo up
ip -n client route add default via 10.10.0.1
ip -n server addr add 203.0.113.2/24 dev vs0; ip -n server link set vs0 up; ip -n server link set lo up
ip -n server route add default via 203.0.113.1
(ip netns exec server /lab/labserver 203.0.113.2:80 tls:203.0.113.2:443 203.0.113.2:8080 >/dev/null 2>&1 &)
# squid checks that an intercepted server name resolves to the address
# the client asked for; the lab's name resolves through /etc/hosts.
echo "203.0.113.2 lab.test" >>/etc/hosts
sleep 1
[ "$(client http://203.0.113.2/)" = "answered by 203.0.113.2:80" ] || fail "the lab network does not forward"
pass "the lab network forwards"

# The daemon, as a gateway would run it.
(/lab/flowsightd -log-level debug >/var/log/fsd.log 2>&1 &)
wait_for 30 curl -sf $API/api/system/info || fail "flowsightd did not come up"
pass "flowsightd is up"
wait_for 15 nft list table inet flowsight || fail "FlowSight's nftables table was not created"
pass "table inet flowsight exists"
save policy '{"enforce":true}'
save identity '{"local_networks":["10.10.0.0/24"]}'

# Interception on.
save web '{"intercept":true}'
apply
if ! wait_for 60 sh -c 'nft list chain inet flowsight fs_web | grep -q "redirect to"'; then
	fail "no redirects were loaded"
fi
pass "redirects loaded: $(nft list chain inet flowsight fs_web | grep -c 'redirect to') rule(s)"
grep -q 'http_port 10.10.0.1:3128 intercept' /etc/flowsight/squid/squid.conf || fail "squid does not listen on the LAN address"
pass "squid listens on the LAN address"
grep -q '203.0.113.1' /etc/flowsight/squid/squid.conf && fail "squid listens on the WAN address"
pass "squid does not listen on the WAN address"

# Traffic through the proxy.
got=$(client http://203.0.113.2/)
[ "$got" = "answered by 203.0.113.2:80" ] || fail "HTTP through the proxy: $got"
sleep 2
grep -q '10.10.0.2 .*203.0.113.2' /var/log/flowsight/squid/access.log || fail "the proxy did not log the HTTP request"
pass "HTTP went through the proxy"
got=$(client -k --resolve lab.test:443:203.0.113.2 https://lab.test/)
[ "$got" = "answered by tls:203.0.113.2:443" ] || fail "HTTPS through the proxy: $got"
sleep 2
grep -q 'lab.test' /var/log/flowsight/squid/access.log || fail "the proxy did not see the HTTPS server name"
pass "HTTPS was spliced through the proxy with its server name seen"
[ "$(client http://203.0.113.2:8080/)" = "answered by 203.0.113.2:8080" ] || fail "port 8080 was touched"
pass "other ports are left alone"
[ -z "$(client http://10.10.0.1:3128/)" ] || fail "a client reached the proxy directly"
pass "a client connecting to the proxy directly is turned away"

# Fail open: kill squid and hold it down; the redirects must go, and web
# access must work without the proxy.
chmod 000 /usr/sbin/squid
pkill -x squid
if ! wait_for 120 sh -c '! nft list chain inet flowsight fs_web | grep -q "redirect to"'; then
	chmod 755 /usr/sbin/squid; fail "the redirects stayed with the proxy dead"
fi
[ "$(client http://203.0.113.2/)" = "answered by 203.0.113.2:80" ] || fail "web access with the proxy dead"
pass "with the proxy dead the redirects are withdrawn and the web works"
chmod 755 /usr/sbin/squid
wait_for 120 sh -c 'nft list chain inet flowsight fs_web | grep -q "redirect to"' || fail "the redirects did not come back with the proxy"
[ "$(client http://203.0.113.2/)" = "answered by 203.0.113.2:80" ] || fail "HTTP after the proxy came back"
pass "the proxy came back and interception with it"

# A distribution firewall that drops incoming by default: health must say so.
nft add table inet distro
nft 'add chain inet distro input { type filter hook input priority filter; policy drop; }'
nft add rule inet distro input iifname lo accept
nft add rule inet distro input ct state established,related accept
wait_for 15 sh -c "curl -s $API/api/system/health | grep -q 'drop incoming connections by default'" ||
	fail "health did not warn about the distribution's input policy: $(health | head -c 600)"
pass "health warns that another table drops incoming connections"
nft delete table inet distro

# Interception off: the redirects go.
save web '{"intercept":false}'
apply
wait_for 60 sh -c '! nft list chain inet flowsight fs_web | grep -q "redirect to"' || fail "the redirects stayed with interception off"
pass "interception off withdraws the redirects"
echo "ALL PASS"

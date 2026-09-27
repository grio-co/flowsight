# How interception works, and what can go wrong

FlowSight owns a squid instance (`flowsight-proxy`) and two pf rules per
interface that send port 80 and 443 from the intercepted networks to it on
loopback. The proxy peeks at the TLS ClientHello for the server name and
splices the connection untouched unless a policy says terminate (denied) or
bump (inspect). Plain HTTP gets a block page for denied names.

## Ordering in pf

pf takes the *first* matching translation rule. NAT reflection, which lets a
client reach an internally hosted service by its public name, is itself an
`rdr`, so the interception rules must come after every port forward or that
traffic is sent to the proxy, which then tries to reach the firewall's own
WAN address and fails. FlowSight's `rdr-anchor "flowsight/*"` is registered
at the tail of the translation rules for exactly this reason. Do not "fix" a
reflection problem with a `no rdr` rule for the WAN address: it excludes the
traffic from reflection too and the failure looks innocent because a `no rdr`
never increments a counter.

## Safety rules the web module enforces

* Redirects are loaded only after squid has parsed its configuration and its
  listeners answer, and withdrawn as soon as they stop answering, so a proxy
  failure cannot take web access down.
* Squid runs with the group that may read `/dev/pf`; without it every
  intercepted connection fails with "NAT lookup failed".
* A domain list is pruned so no entry is a subdomain of another; squid refuses
  such lists.
* A plain forward-proxy port on loopback exists because squid needs one for
  its internal URLs.

## Who is decrypted, and who only has a certificate looked at

Inspection is scoped per policy. For each policy with `tls.inspect` the
proxy gets a source ACL of that policy's members and three rules: splice the
bypassed and pinned names, stare at step 2, bump at step 3. Every other
client meets `ssl_bump splice all` after peeking at the ClientHello, and pf
redirects everyone the same way; the scoping is entirely in squid. Two
switches widen it: *Stateful Packet Inspection › Inspect everything that
crosses the firewall* adds a `deep_all` policy covering every local network,
and nothing else does.

Squid checks a server's certificate whenever it reads one. With *Record
server certificates without inspecting* (`peek_server_cert`) on, it reads it
for every client, including the ones it will only splice. Had that check
refused a certificate squid could not verify, squid would not splice: it
bumps the client to show an error page under a certificate signed by the
FlowSight CA. A device that is not inspected, and does not trust the CA,
would then see a forged certificate for every server whose chain the
firewall cannot complete (a server that leaves out its intermediate is
enough), and its apps retry in a loop. So `sslproxy_cert_error` refuses bad
certificates only for the members of inspecting policies and allows them for
everyone else; a spliced client always receives the server's own
certificate and judges it itself, exactly as without the proxy.

To check which certificate a device receives, run from it (or from a device
in the same position):

```
openssl s_client -connect example.com:443 -servername example.com </dev/null | grep -E 'i:|Verify'
```

An issuer of *FlowSight Inspection CA* on a device no policy inspects is a
bug; the TLS page lists which clients were bumped (mode *bump*).

## On a Linux gateway (nftables)

nftables' `redirect` does not deliver to loopback: it rewrites the
destination to the address of the interface the connection came in on. So
on Linux FlowSight's proxy also listens on the LAN interfaces' own addresses
(each once, IPv4, and IPv6 other than link-local when IPv6 is intercepted),
and the fail-open check probes every one of them as well as loopback. A
proxy that answers on loopback but not on the LAN address has the redirects
withdrawn, exactly as a proxy that does not answer at all.

The interfaces are the ones in **Interfaces**, or, left empty, the ones
holding an address inside an intercepted network; the WAN is never chosen,
so the proxy never listens on a public address. Redirects are only rendered
for interfaces the proxy was told to listen on; if none can be found,
nothing is redirected. The addresses are read again at every probe, so a
LAN address that appears after the proxy was configured fails the probe and
withdraws interception until the next apply, rather than sending traffic to
an address nothing listens on.

Because the proxy's ports are now open on the LAN, FlowSight's `input` chain
(`fs_web_in`) turns away any connection to them that did not arrive through
a redirect: a client aiming at the proxy directly is reset. Loopback passes,
for the probe and for squid's own requests.

Redirected connections pass through the input hook, and nftables lets every
table judge them. If the distribution's firewall (ufw, firewalld, or an
`inet filter` table with `policy drop` on input) does not let the proxy's
ports in from the LAN, redirected web traffic is dropped there, while the
probe, made over loopback, still passes. FlowSight's table cannot accept on
another table's behalf, so the nftables module's health turns red and names
the table while interception is loaded and any other table's input chain
drops by default. Allow the proxy's ports (`http_port`, `https_port`, 3128
and 3129 unless changed) from the LAN in that firewall, for example
`ufw allow in on lan0 to any port 3128:3129 proto tcp`.

## IPv6

On a Linux gateway the proxy listens on the LAN's own IPv6 address (see
above), so the listener address only needs setting to turn IPv6
interception on. On pf:

pf cannot redirect LAN traffic to `[::1]`, so IPv6 interception needs an
address the firewall holds on the LAN. Set the web module's
**IPv6 listener address** (`ipv6_listener`) to one, typically a unique local
address (for example a `fd..::1` virtual IP on the LAN). The proxy then also
listens on that address and inet6 redirect rules are generated whose source
is the local-networks table, so clients with global addresses are covered.
Leave it empty and IPv6 web traffic is simply not intercepted (nothing
breaks; it is just not seen).

The local-networks table (`flowsight_local`) lives in the root pf ruleset and
is refreshed by the firewall module every minute; the anchors reference it by
name. Do not define a table of that name inside an anchor: pf would give the
anchor its own empty copy and "to ! <flowsight_local>" would match everything.

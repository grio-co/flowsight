# Give a device a DNS name

When you name a device in FlowSight, you can also give it a name on the
network, so other devices reach it as `nas.grio.co` instead of
`192.168.1.10`, and a lookup of its address answers with that name
(reverse DNS, which is what shows names in logs, `ping`, `traceroute` and
FlowSight's own pages).

## Name a device

1. Open the device's page (click it anywhere: Devices, IP Addresses, a
   session, a finding).
2. In *Identity*, click **rename** next to the name, or **add** next to
   *DNS name*.
3. Type the name FlowSight should show, such as *Kitchen iPad*.
4. Leave **Also add it to DNS** ticked. FlowSight turns the name into a DNS
   label (`kitchen-ipad`) and offers the local domain your network already
   uses most (from your OPNsense host overrides and your Pi-holes). Both can
   be edited. The preview shows both directions:

   ```
   kitchen-ipad.grio.co → 192.168.1.44
   192.168.1.44 → kitchen-ipad.grio.co
   ```

5. Choose the **addresses**. The device's IPv4 address is chosen by default.
   IPv6 addresses are listed too: one built from the hardware address is
   marked *stable*; a *privacy address* changes every day or so and is
   better left out.
6. Choose **where**: the gateway resolver, and each connected Pi-hole. All
   are ticked by default, because a device asks only one of them. A device
   that uses a Pi-hole directly never sees a name that only the gateway
   knows, since the Pi-hole forwards to its own upstream servers and not to
   the gateway.
7. Leave **Follow the device** ticked when the device gets its address by
   DHCP without a reservation. When its IPv4 address changes, FlowSight
   moves the name with it (checked every two minutes, by hardware address).
8. **Save**.

The device's *Identity* card then shows its DNS name. Renaming the device
again, with the box ticked, replaces the old name everywhere.

## Where the records go

- **Gateway resolver**: FlowSight's own include file, `flowsight-names.conf`,
  next to its other resolver files. The change is checked by
  `unbound-checkconf` and reverted if rejected, then loaded into the running
  resolver without flushing its cache. Your OPNsense host overrides are
  never changed. If the name you choose is already a host override, FlowSight
  refuses it. If an address's reverse name is already answered by a host
  override, FlowSight adds only the forward name on the gateway, so the
  address does not end up with two names.
- **Pi-hole**: a local DNS record (*Settings › Local DNS Records* on the
  Pi-hole), which Pi-hole answers both forward and reverse. FlowSight
  removes only the exact records it added. A Pi-hole must allow FlowSight to
  change its settings (see [Pi-hole](pihole.md)); one that does not is shown
  as read only. If a Pi-hole still answers a name with something else
  from its cache (a public wildcard such as `*.grio.co` looked up before the
  name existed; Pi-hole's cache optimizer keeps such answers alive), FlowSight
  restarts that Pi-hole's DNS service once to clear it, a second or two
  without answers.

## The DHCP server gets the name too

With *Settings › identity › Send device names to the DHCP server* on (the
default), every name given in FlowSight also goes to the DHCP server. On
OPNsense that is dnsmasq: FlowSight keeps its own host file
(`/usr/local/etc/flowsight/dnsmasq-names.hosts`, one `MAC,name` line per
device) named by one line in its own include
(`/usr/local/etc/dnsmasq.conf.d/flowsight-names.conf`). dnsmasq then gives
the device that name with its next lease, lists the lease under it, and
registers it in DNS under its DHCP domain. Only names are sent, never
addresses, so nothing about a device's address changes.

- The host name is the device's DNS label when it has one (`iphone`), so
  DHCP and DNS say the same thing; otherwise it is made from the name.
- A device you already describe to dnsmasq, with a static host in OPNsense
  (*Services › Dnsmasq › Hosts*) or through FlowSight's device placement,
  keeps that entry and is left out. *Settings › identity* lists what was sent
  and what was left alone, and why.
- Two devices given the same name get distinct host names (the second has
  the end of its hardware address appended).
- A rename reaches dnsmasq within a minute (at once from the device page) and
  is re-read without restarting it; turning the setting on the first time
  restarts dnsmasq once. The device picks the name up at its next lease
  renewal.
- Turning the setting off empties the host file.

## See and manage names

*Settings › dns › Device names* lists every name FlowSight put in DNS, its addresses,
whether it follows its device, and what each resolver answers for it right
now, forward and reverse. Hover a resolver's badge for the exact answers.
*Edit* opens the same dialog; *Remove* takes the name out of every resolver.

Every add, change, follow and removal is recorded under *Status › Changes*.

## Settings

*Settings › dns › Local domain for device names*: the domain offered first.
Empty picks the one your host overrides and Pi-holes use most.

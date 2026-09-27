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
  as read only.

## See and manage names

*Settings › dns › Device names* lists every name FlowSight put in DNS, its addresses,
whether it follows its device, and what each resolver answers for it right
now, forward and reverse. Hover a resolver's badge for the exact answers.
*Edit* opens the same dialog; *Remove* takes the name out of every resolver.

Every add, change, follow and removal is recorded under *Status › Changes*.

## Settings

*Settings › dns › Local domain for device names*: the domain offered first.
Empty picks the one your host overrides and Pi-holes use most.

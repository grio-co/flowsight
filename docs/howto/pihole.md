# Pi-hole with FlowSight

FlowSight works with Pi-hole in two ways:

1. **Reading.** It pulls each Pi-hole's query log into the DNS history, so
   every lookup a device makes through a Pi-hole shows up under that device,
   with the list that blocked it. Device advisories are built from it.
2. **Configuring.** On Pi-hole v6, the *Pi-hole* tab of the DNS page shows
   the settings that matter for what devices experience, with what each one
   does, what FlowSight recommends and why, each Pi-hole's current value,
   and a way to change it. It also pauses and resumes blocking, and edits
   the allow and deny lists.

The *Pi-hole* tab appears only while at least one Pi-hole v6 server is
connected. Without one, the DNS page has no tabs.

## Connect a Pi-hole

1. On the Pi-hole: *Settings › Web interface / API › Configure app
   password*, and copy the password it generates. Your web password is not
   changed.
2. In FlowSight: *Settings › pihole*. List each server as a URL
   (`https://192.168.1.53`, one per line) and paste the app password.
   A line starting with `#` keeps a server in the list without contacting it.
3. Wait half a minute. *Status* shows the pihole module importing; the DNS
   page's *Via* column shows `pi-hole 192.168.1.53` for its queries, and the
   *Pi-hole* tab appears.

## Let FlowSight change settings

Pi-hole lets an app password read its settings but not change them until you
allow it. On each Pi-hole, either turn on **Permit app password to modify
config** (*Settings › Web interface / API*, with Expert mode on), or run:

```
sudo pihole-FTL --config webserver.api.app_sudo true
```

Until then the *Pi-hole* tab marks that server *read only*, shows its values
and the guidance, and offers no *Apply* buttons. Pausing blocking and the
allow and deny lists work either way.

To take the permission back: `sudo pihole-FTL --config webserver.api.app_sudo false`.

## What can be changed from FlowSight

Only a curated set, grouped by what it affects:

- **Blocking**: on/off, what a blocked name is answered with (NULL, NX,
  NODATA, IP), how long devices keep a blocked answer, CNAME inspection,
  ESNI blocking.
- **Device-specific behaviour**: Pi-hole's built-in answers for iCloud
  Private Relay, Firefox's DNS-over-HTTPS canary, and automatic
  encrypted-DNS discovery. These decide whether Apple devices and browsers
  stay on your resolver.
- **Upstream and resolution**: upstream servers, DNSSEC, not forwarding
  plain names or private reverse lookups, client-subnet hints, cache size.
- **Local names**: conditional forwarding (so devices get names), local
  domain, local DNS records and aliases.
- **Limits and load**: the per-client rate limit (which a gateway forwarding
  for the whole network can trip), and what happens while blocklists
  update.
- **Logging and what FlowSight can see**: query logging and the privacy
  level. FlowSight warns at the top of the tab when either would hide
  queries from it.

The listening mode, interface and port are shown but cannot be changed
here: a wrong value stops the Pi-hole answering anyone, and the fix then
needs its console. DHCP, passwords and the web server are left to the
Pi-hole's own pages.

Every change asks for confirmation first. The dialog says when Pi-hole will
restart its DNS service to apply it (a second or two without answers) and
repeats any caution, such as turning on the Private Relay block. With more
than one Pi-hole, a change goes to all of them unless you pick one, and a
setting whose value differs between them is marked. Every change, pause
and list edit is recorded under *Status › Changes* with who made it.

## Allow and deny lists

*Allow* beats every blocklist: use it for a name a device needs. *Deny*
blocks a name no list has yet. Add several names at once, separated by
spaces or commas; choose *regex* for a pattern. Changes take effect at once,
within the blocked-answer lifetime. A device advisory caused by a Pi-hole
blocklist offers the allow entry as a button.

## Pause blocking

*Pause 5 min*, *15 min* or *1 hour* lets every name through and switches
blocking back on by itself. It is the quickest test of "is blocking what
breaks this?". *Resume now* ends a pause early.

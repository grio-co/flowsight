# Pi-hole with FlowSight

FlowSight works with Pi-hole in two ways:

1. **Reading.** It pulls each Pi-hole's query log into the DNS history, so
   every lookup a device makes through a Pi-hole shows up under that device,
   with the list that blocked it. Device advisories are built from it.
2. **Configuring.** On Pi-hole v6, *Settings › dns › Pi-hole* shows
   the settings that matter for what devices experience, with what each one
   does, what FlowSight recommends and why, each Pi-hole's current value,
   and a way to change it. It also pauses and resumes blocking, and edits
   the allow and deny lists.

The *Pi-hole* tab of *Settings › dns* appears only while at least one
Pi-hole v6 server is connected. *Settings › pihole* is where the
connection itself (servers, app password) is set.

## Connect a Pi-hole

1. On the Pi-hole: *Settings › Web interface / API › Configure app
   password*, and copy the password it generates. Your web password is not
   changed.
2. In FlowSight: *Settings › pihole*. List each server as a URL
   (`https://192.168.1.53`, one per line) and paste the app password.
   A line starting with `#` keeps a server in the list without contacting it.
3. Wait half a minute. *Status* shows the pihole module importing; the DNS
   page's *Via* column shows `pi-hole 192.168.1.53` for its queries, and the
   *Pi-hole* tab appears under *Settings › dns*.

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

**Why some changes restart DNS.** Pi-hole remembers what it decided for each
device and name. After a change to blocking or to the device-specific
answers, a device that already asked keeps getting the old answer until
Pi-hole's DNS service restarts, and that device is usually the one you are
trying to fix. FlowSight restarts it after applying those settings. If you
change them on the Pi-hole itself, run `pihole reloadlists` afterwards.

## Blocking

*Settings › dns › Pi-hole blocking* manages what the Pi-holes block and for
whom. A Pi-hole blocks from two things:

- **Lists**: subscriptions to blocklists and allowlists by URL. The Pi-hole
  downloads every list on each **gravity** rebuild.
- **Entries**: single names on its allow or deny list, exact or as a regular
  expression. Allow beats every blocklist; deny blocks a name no list has.

Every list and entry belongs to **groups**, and every **client** (a device,
by address, network, hardware address, host name or interface) is filtered
by the lists and entries of its groups. A client in no group is in
*Default*, and so is everything not given another group.

**Apply changes to** at the top picks where every change goes: all
connected Pi-holes (the default) or one. Groups are shown and chosen by
name. Each Pi-hole numbers its groups itself, so FlowSight translates the
name for each one, and creates the group on a Pi-hole that lacks it.
Something present on only some Pi-holes, or set differently on them, is
marked, with *Add to all* for a list that is missing somewhere.

- **Blocklists and allowlists**: add a list by URL with its groups, switch
  one on or off, change its groups, remove it. The domain count and last
  update show per Pi-hole. A change rebuilds gravity, in the background, on
  the Pi-holes it reached; the *Pi-holes* card shows progress and the output,
  and *Rebuild now* runs it by hand.
- **FlowSight categories as Pi-hole lists**: *Block with it* or *Allow with
  it* subscribes the Pi-holes to a FlowSight category. FlowSight serves the
  category as a feed, one domain per line, at
  `http://<gateway>:<port>/feeds/categories/<name>.txt?key=<feed key>`, and
  the Pi-hole fetches it on every gravity rebuild, so the Pi-hole follows the
  category as it changes. The key is a random secret of this installation;
  without it the feed answers "not found". FlowSight must listen on an
  address the Pi-hole can reach (*bind* is not 127.0.0.1).
- **Groups**: add, rename, switch off or remove a group. Removing a group
  sends its clients back to *Default*; *Default* cannot be removed.
- **Clients in groups**: put a device in groups (the address box suggests
  FlowSight's named devices). Groups apply to devices that ask the Pi-hole
  directly; a device that asks the gateway resolver reaches the Pi-hole, if
  at all, as the gateway.
- **Allow and deny entries**: add names (several at once), switch an entry
  on or off, change its groups, remove it.
- **Keep the Pi-holes the same**: *Sync now* makes every other Pi-hole (or
  one) match the one chosen: groups, lists, clients and entries are added
  where missing and corrected where different. Tick *also remove what they
  have beyond it* to make them identical.

Every change is recorded under *Status › Changes*, one line per Pi-hole it
reached. The same operations are in the API:

| Endpoint | Does |
|---|---|
| `GET /api/pihole/blocking` | Groups, lists, clients and entries merged across Pi-holes, with where each exists, gravity runs, and categories |
| `POST /api/pihole/lists` | Add, update or remove a list; rebuilds gravity unless `gravity: false` |
| `POST /api/pihole/domains` | Add, update or remove allow or deny entries |
| `POST /api/pihole/groups` | Add, update, rename or remove a group |
| `POST /api/pihole/clients` | Put a client in groups, or take it out |
| `POST /api/pihole/categories` | Subscribe the Pi-holes to a FlowSight category, or unsubscribe |
| `POST /api/pihole/gravity` | Rebuild gravity now |
| `POST /api/pihole/sync` | Make other Pi-holes match one |

Every write takes `server`: a Pi-hole's URL, host or address, or `all` (the
default). Groups are given by name. For example, to block a name for the
*Kids* group on every Pi-hole:

```
curl -X POST http://192.168.0.1:8080/api/pihole/domains \
  -H "X-Flowsight-Token: $TOKEN" -H "content-type: application/json" \
  -d '{"action":"add","type":"deny","domains":["games.example.com"],"groups":["Kids"],"server":"all"}'
```

## Pause blocking

*Pause 5 min*, *15 min* or *1 hour* lets every name through and switches
blocking back on by itself. It is the quickest test of "is blocking what
breaks this?". *Resume now* ends a pause early.

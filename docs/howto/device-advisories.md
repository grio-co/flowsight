# Device advisories: "my phone can't browse" and friends

Some of the most confusing problems on a filtered network are not blocks of
traffic at all. The firewall passes every packet, the proxy is healthy, apps
keep working, and yet Safari will not load a page, the phone says the Wi-Fi
has no internet, or notifications stop. The cause is a **DNS answer**: a
resolver (the gateway's, or a Pi-hole a device uses directly) answers
"no such name" or a block for something the device depends on.

FlowSight reads every DNS answer it can see (the gateway resolver and any
connected Pi-hole) and raises a **device advisory** when a device keeps
getting a failing answer for a name it cannot do without. An advisory says,
for that one device:

- **what the person sees**, in their words ("Safari can stall or refuse to
  load pages");
- **the cause**: which resolver answered, what it answered (NXDOMAIN, a
  block), from which list, for which names, how many times;
- **what to do**, specific to the resolver: for a Pi-hole, the exact setting
  or the allow-list entry.

When a connected Pi-hole caused it and FlowSight may change that Pi-hole's
settings, the fix is a button: *Let Private Relay work on this Pi-hole*, or
*Allow name on Pi-hole 192.168.1.53*. Every such change is recorded under
*Status › Changes*.

An advisory closes on its own once the failing answers stop (by default,
after 15 quiet minutes).

## Where they show up

- **Overview**: *Needs attention* lists open advisories with their fixes;
  *Devices needing attention* lists every device with an open finding of any
  kind, worst first.
- **A device's page** (click any device): *Needs attention on this device*
  at the top, covering every address the device has used (its IPv4 and IPv6
  addresses are one device), and the full *Findings* table further down.
- **Devices** and **IP Addresses**: a warning mark beside a device with open
  findings; hover it for the list, click it for the device.
- **DNS**: *Device advisories* above the charts; with a client filter, only
  that client's.
- **Pi-hole** tab of DNS: advisories a Pi-hole caused, next to the setting
  that causes them.
- **Findings**: every advisory with the *What to do* line.

## What is watched

| Advisory | Names | What the person sees |
|---|---|---|
| iCloud Private Relay is blocked (high) | mask.icloud.com, mask-h2.icloud.com | "Private Relay is not available"; Safari stalls or will not load pages while other apps work |
| Internet connectivity check is blocked (high) | captive.apple.com, connectivitycheck.gstatic.com, msftconnecttest.com, detectportal.firefox.com and similar | "No Internet" on the Wi-Fi, a sign-in sheet that never goes away, traffic moving to cellular |
| Network time is blocked (medium) | time.apple.com, time.windows.com, time.google.com, *.pool.ntp.org | The clock drifts; sign-ins and two-factor codes fail, sites show certificate errors |
| Certificate status checks are blocked (medium) | ocsp.apple.com, ocsp.digicert.com, *.o.lencr.org and similar | Slow app launches, installers and enterprise sign-ins that refuse to continue |
| Push notifications are blocked (medium) | *.push.apple.com, mtalk.google.com, *.notify.windows.com | Messages and alerts arrive late or not at all |
| Software update checks are blocked (low) | mesu.apple.com, gdmf.apple.com, *.windowsupdate.com and similar | The device cannot check for security updates |
| Sign-in and checkout protection is blocked (low) | *.siftscience.com, *.hcaptcha.com, challenges.cloudflare.com, Stripe and similar | Some apps and sites refuse to let you sign in, pay or verify an account |
| Name lookups are failing (medium) | 20% or more of at least 40 lookups answer SERVFAIL or REFUSED | Pages and apps fail at random, then work on retry |
| An app keeps retrying a blocked name (low) | any one blocked name asked for 120 times or more | A feature on the device is not working and keeps trying, costing battery and data |

The full list, with the exact names, is served by `GET /api/advisor/status`.

## The Private Relay case, worked through

This advisory exists because of a real evening. An iPhone had its DNS set by
hand to a Pi-hole. Pi-hole v6 answers NXDOMAIN for Apple's Private Relay
names by default (its `dns.specialDomains.iCloudPrivateRelay` setting). The
phone's apps, which do not use the relay, worked; Safari, which does, would
not load anything. Every packet was allowed and the proxy was fine, so the
network looked healthy. The DNS log held the answer: a hundred NXDOMAIN
answers an hour for mask.icloud.com, to that one phone.

There is no single right fix; pick one:

1. **Let the relay work.** Turn the Pi-hole setting off (the advisory's
   button, or the *Pi-hole* tab of DNS › *Device-specific behaviour*).
   Safari then goes through Apple's relay: it works, but neither the Pi-hole
   nor FlowSight can see which sites it visits.
   Changing the setting on the Pi-hole by hand is not enough on its own:
   Pi-hole keeps giving the old answer to a device that already asked until
   its cache is flushed, so run `pihole reloadlists` too. FlowSight's
   button does both.
2. **Keep the relay off on this network.** Leave the Pi-hole setting on, and
   on the device turn off *Limit IP Address Tracking* for this Wi-Fi
   (Settings › Wi-Fi › ⓘ) or Private Relay itself. Safari's traffic then
   stays visible and filtered.

## Settings

*Settings › advisor*:

- **Look-back window (minutes)**, default 15: how far back each scan looks,
  and so how long an advisory stays open after the last failing answer.
- **Ignore these clients**: addresses never advised on, such as a lab
  machine that is meant to be locked down.

Advisories need a DNS log. The gateway resolver's is read by the DNS module;
a Pi-hole's is pulled when it is connected under *Settings › pihole*
(see [Pi-hole](pihole.md)). A device whose lookups FlowSight cannot see (a
public resolver, DNS over HTTPS in a browser) cannot be advised on.

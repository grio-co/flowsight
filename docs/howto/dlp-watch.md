# HOWTO: watch data transfers and prevent them

Use the DLP (Data Loss Prevention) page to identify large file transfers, watch for repeated transfers to a destination, and stop them in flight.


![DLP: what is leaving now, by destination kind and by device, watched transfers, and the Leaving the country card.](img/dlp.png)

*DLP: what is leaving now, by destination kind and by device, watched transfers, and the Leaving the country card.*

## Prerequisites

- Traffic is being captured (at least 1 hour)
- You want to monitor a group of devices (e.g., `zone:iot`) or a specific application (e.g., Syncthing, S3)
- (Optional: watched groups enabled in *Protect › Groups & Schedules*)

## Steps

1. **Open the DLP page.**
   - FlowSight › DLP (under PROTECT)

2. **Understand the DLP cards.**
   The page shows several views:
   - **Transfers in progress**: active downloads and uploads right now
   - **Large downloads**: files being received (sorted by size)
   - **Large uploads**: files being sent (sorted by size)
   - **Leaving the country**: devices reaching servers abroad (if country enrichment is on)
   - **Repeated destinations**: devices connecting to the same destination multiple times (watching)

3. **Watch for large transfers.**
   Each large transfer shows:
   - **Device**: who is transferring
   - **Destination**: where it is going
   - **Size**: how much data
   - **Application**: what protocol (HTTP, FTP, S3, SMB, Syncthing, etc.)
   - **Bytes**: detailed breakdown
   - **Last seen**: when
   - **Stop** button (if enabled): kill the connection

4. **Set up watched groups (Pro).**
   To monitor specific devices or apps for repeated transfers:
   - FlowSight › Groups & Schedules (under PROTECT)
   - Click **New watched group**
   - Name it: `external-backup`, `cloud-sync`, etc.
   - Add the devices to watch: by MAC, zone, or address
   - (Or specify an application to watch: `app:Syncthing`, `app:S3`)
   - Click **Save**
   - The group now appears on the DLP page

5. **Understand the "Repeated destinations" card.**
   Once a watched group is set up, this card shows:
   - **Destination**: the server being accessed
   - **Sessions**: how many times in the window
   - **Bytes**: total data transferred
   - **Last seen**: when it was last active
   - **Block** button: write a policy denying this destination to the watched group
   - **Sessions** count: click to see all the sessions to this destination

6. **Stop a transfer (if enabled).**
   - In the *Transfers in progress* card, find the transfer
   - Click **Stop** to immediately cut the connection
   - (This requires the `stop_transfer` capability; check under *Administration › License*)

7. **Write a policy to block repeated transfers.**
   If you identify a destination you want to block:
   - Click **Block** on the destination's row
   - The policy editor opens with:
     - **Members**: the watched group pre-filled
     - **Destination**: the address or domain pre-filled
   - Set the **Action** to *block* (or *monitor* first)
   - Click **Save**

## What to expect

- **Large transfers** are typically:
  - Cloud backups (iCloud, Google Drive, OneDrive)
  - Media uploads (photos, videos)
  - Application updates
  - Database syncs (Syncthing, Resilio Sync)
  - Torrent or P2P uploads
- **Repeated destinations** from a watched group indicate:
  - Regular cloud sync (iCloud Photos, Syncthing)
  - Polling (apps checking for updates)
  - Telemetry (devices sending diagnostics)
- **The "Leaving the country" card** is useful for IoT devices that should not go abroad

## Limits

- The DLP page shows observed transfers; it cannot predict future ones
- Stopped transfers may reconnect immediately if the application retries
- Watched groups require the Pro tier
- Transfer monitoring is per-flow; a multi-threaded download may appear as several smaller transfers
- Encrypted transfers show the destination and size but not the file name

## Kinds of destination

Every connection on the DLP page is filed under one kind, by the name of the far end (or by its port for tunnels). The kind is what decides whether a large upload raises an event. Each pill on the page carries this text as its bubble, and *What the kinds mean* under **By destination** lists them all.

| Kind | What it covers | Watched |
|---|---|---|
| Cloud Storage | Sync and object storage: Dropbox, Drive, OneDrive, iCloud, S3 and the like. A large upload here is a copy of files leaving the network. | yes |
| File Transfer & Paste | One-shot drop sites and paste bins: WeTransfer, file.io, pastebin. They exist to move a file or a secret out in one request. | yes |
| Code Hosting | GitHub, GitLab, package registries. Source and credentials leave this way, deliberately or not. | yes |
| Personal Mail | Personal mail providers over the web. Attachments to a personal account bypass any company mail controls. | yes |
| Messaging | Chat services with file sharing: Discord, Telegram, WhatsApp, Slack. | yes |
| AI Assistants | Hosted language-model services. Pasted documents and code become someone else's logs. | yes |
| Remote Access | Remote desktop and tunnelling services: TeamViewer, AnyDesk, ngrok. They carry anything, in either direction. | yes |
| Backup | Backup services. Large uploads are expected, so they are measured but not flagged. | no |
| Media & Streaming | Video, music and game services. Mostly downloads. | no |
| Telemetry & Analytics | Update and analytics endpoints vendors call home to. Small and constant. | no |
| Content Delivery | Content networks fronting many sites. The name says who serves it, not what it is. | no |
| Encrypted Tunnel | A VPN or overlay recognised by port: WireGuard, OpenVPN, IPsec, Tailscale. Nothing inside can be seen; the volume, the far end and the timing are all that is knowable. | yes |
| Unnamed Destination | Nothing names the address: no DNS answer was seen for it, no server name in a TLS handshake, and no reverse lookup. Ordinary traffic almost always has a name, so a nameless far end is worth a look. | yes |
| Other | Matched none of the above. Split further by what is known about it, in this order: the application's category from the flow probe (*Other · Software Update*, *Other · Advertisement*), the web category of the name from the category feeds, the network that announces the address (*Other · Apple Inc.*), and failing all of those the port (*Other · HTTPS*, *Other · Traceroute*). | no |

Which kinds are watched is a setting under **Settings › egress**. A watched kind raises an event when a device uploads to it past the volume, rate or ratio thresholds, or reaches it for the first time.

## What a flagged transfer shows

Each flagged transfer is enriched from what the gateway already knows, so the row answers who, what and where without leaving the page:

- **When**: the moment it crossed the threshold, when the connection opened, and how long it had been open.
- **Who**: the device by name, with its maker, address and hardware address.
- **What**: a one-line reading of the payload (*Encrypted web (TLS, name seen)*, *Inspected: images, API calls*, *BitTorrent*, *Media stream*), the application the flow probe recognised, the name it was for, the content types seen when the session was inspected, and how much of it was readable (inspected, name seen, opaque).
- **Where**: the far end by name, address and port, its city and country, whether it is an anycast instance, and the network that announces it, with links to the route on the Map and to the sessions.
- **How much** and **why**: bytes sent and received, the rate at the time, and the threshold that tripped.

The same detail sits behind every row of **Moving now**, so a live connection can be read the same way before it is flagged.

## Related

- [See what your IoT devices send abroad, and block it](iot-abroad.md)
- [Block apps and categories on a schedule](policy-schedule.md)
- [Watch data leaving and stop a transfer](dlp-watch.md)
- *User guide › DLP*

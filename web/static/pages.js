/* FlowSight pages: visibility. Each page is {title, render(el, ctx)} */
'use strict';
(function () {
  const { esc, num, bytes, bps, dur, ago, when, pill, card, kpi, table, bars, chart, donut, hostLink, domainLink, get, post } = FS;

  // ------------------------------------------------------------- Overview
  // Activity, not volume: a bar is sessions, and its subtitle says which
  // hosts did it, with the bytes as an aside.
  const sessions = (n) => num(n) + ' sessions';
  const whoDid = (r) => {
    const who = (r.top_hosts || []).map(h => `<a href="#host/${encodeURIComponent(h.ip)}">${esc(h.name || h.ip)}</a>`).join(', ');
    const more = (r.hosts || 0) > (r.top_hosts || []).length ? ` +${num((r.hosts || 0) - (r.top_hosts || []).length)}` : '';
    return `${r.category ? esc(r.category) + ' · ' : ''}${who || (r.hosts ? num(r.hosts) + ' hosts' : '')}${more} · ${bytes((r.bytes_in || 0) + (r.bytes_out || 0))}`;
  };
  FS.registerPage('overview', {
    title: 'Overview', refresh: 15,
    async render(el) {
      const [sum, top, ts, health, findings, dns, setupState] = await Promise.all([
        get('/api/visibility/summary'), get(`/api/visibility/top?${FS.since()}&limit=8`),
        get(`/api/visibility/timeseries?${FS.since()}`), get('/api/system/health'),
        get('/api/system/findings'), get(`/api/dns/summary?${FS.since()}&limit=8`),
        get('/api/setup/state')]);
      if (sum.error && !sum.throughput_bps) { el.innerHTML = FS.err('Visibility unavailable: ' + sum.error); return; }
      const traffic = ts.traffic || [];
      const openF = (findings.findings || []).filter(f => !f.acked);
      const sev = { critical: 0, high: 0, medium: 0, low: 0 }; openF.forEach(f => sev[f.severity] = (sev[f.severity] || 0) + 1);

      // Banner for incomplete setup wizard
      let banner = '';
      if (setupState && !setupState.error && !setupState.completed) {
        banner = `<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:12px 16px;margin-bottom:14px;display:flex;gap:12px;align-items:center">
          <span style="font-size:20px">⚙</span>
          <div style="flex:1">
            <div style="font-weight:500">Setup wizard not completed</div>
            <div style="font-size:12px;color:#666;margin-top:4px">Run the setup wizard to configure traffic sources, DNS, security and more.</div>
          </div>
          <a href="#setup" class="btn small">Open setup</a>
          <button id="dismiss-banner" class="iconbtn small" style="font-size:16px;cursor:pointer;padding:4px 8px">×</button>
        </div>`;
      }

      el.innerHTML = banner + `
      <div class="grid cols-6">
        ${kpi('Throughput', bps(sum.throughput_bps), (sum.throughput_download_bps || sum.throughput_upload_bps) ? `↓ ${bps(sum.throughput_download_bps)} · ↑ ${bps(sum.throughput_upload_bps)} · ${num(sum.throughput_pps)} pps` : num(sum.throughput_pps) + ' pps')}
        ${kpi('Active flows', num(sum.active_flows), num(sum.flows_last_hour) + ' in the last hour')}
        ${kpi('Active hosts', num(sum.active_hosts), num(sum.hosts_last_hour) + ' local, last hour')}
        ${kpi('Blocked', num(sum.blocked_last_hour + (sum.dns_blocked_last_hour || 0)), 'last hour (web + DNS)', sum.blocked_last_hour ? 'warn' : '')}
        ${kpi('Threats', num(sum.alerts_last_hour), 'IDS alerts, last hour', sum.alerts_last_hour ? 'bad' : '')}
        ${kpi('Findings', num(openF.length), `${sev.critical + sev.high} high or critical`, sev.critical ? 'bad' : sev.high ? 'warn' : '')}
      </div>
      ${openF.some(f => f.module === 'advisor') || (FS.findingDevice && openF.some(f => FS.findingDevice(f))) ? `<div class="grid cols-2 attn" style="margin-top:14px">
        ${openF.some(f => f.module === 'advisor') ? card('Needs attention', FS.adviceHTML(openF.filter(f => f.module === 'advisor'), { max: 4 }), 'problems people notice on a device, with the fix') : ''}
        ${card('Devices needing attention', FS.devicesAttentionHTML(openF), `<a href="#findings">all findings</a>`)}
      </div>` : ''}
      <div class="grid cols-2" style="margin-top:14px">
        ${card('Traffic', chart([{ name: 'download', points: traffic.map(p => [p.t, p.bytes_in]) }, { name: 'upload', points: traffic.map(p => [p.t, p.bytes_out]) }], { fmt: bytes, area: true, tall: true }) + FS.legend(['download', 'upload']))}
        ${card('Throughput', chart(((ts.throughput_download_bps || []).length || (ts.throughput_upload_bps || []).length)
          ? [{ name: 'inbound (download)', points: (ts.throughput_download_bps || []).map(p => [p.t, p.v]) }, { name: 'outbound (upload)', points: (ts.throughput_upload_bps || []).map(p => [p.t, p.v]) }]
          : [{ name: 'bps', points: (ts.throughput_bps || []).map(p => [p.t, p.v]) }], { fmt: bps, area: true, tall: true }) + FS.legend(['inbound (download)', 'outbound (upload)']), 'inbound and outbound')}
      </div>
      <div class="grid cols-3" style="margin-top:14px">
        ${card('Top hosts', bars((top.hosts || []).map(h => ({ label: h.name || h.ip, sub: `${h.name ? h.ip + ((h.addresses || []).length > 1 ? ` +${h.addresses.length - 1}` : '') + ' · ' : ''}${num(h.apps || 0)} apps · ${bytes((h.bytes_in || 0) + (h.bytes_out || 0))}`, value: h.flows || 0, href: '#host/' + h.ip })), sessions), 'by sessions')}
        ${card('Top applications', bars((top.apps || []).map(a => ({ label: a.app, subHTML: whoDid(a), value: a.flows || 0, href: '#flows?app=' + encodeURIComponent(a.app) })), sessions), 'by sessions')}
        ${card('Top categories', donut((top.categories || []).map(c => ({ label: c.category, value: c.flows || 0 })), sessions), 'by sessions')}
      </div>
      <div class="grid cols-3" style="margin-top:14px">
        ${card('Top sites', bars((top.domains || []).map(d => ({ label: d.domain, subHTML: whoDid(d), value: d.flows || 0, href: '#flows?domain=' + encodeURIComponent(d.domain),
          // Where the site's traffic actually went, on the map: the endpoint
          // with a measured route when there is one, else the busiest.
          extra: d.dst_ip ? ` <a class="maplink${d.traced ? '' : ' untraced'}" href="#paths?dst=${encodeURIComponent(d.dst_ip)}" title="${d.traced ? 'Route to ' + FS.esc(d.dst_ip) + ' on the map' : FS.esc(d.dst_ip) + ' on the map \u2014 not traced yet; the map will trace it when it can'}">map</a>` : '' })), sessions), 'by sessions',
          'map: the route to the endpoint that served the site')}
        ${card('Blocked', bars((top.blocked || []).map(b => ({ label: (b.name || b.ip) + ' → ' + b.app, value: b.flows, href: '#host/' + b.ip }))) )}
        ${card('DNS', dns.error ? FS.err(dns.error) : `<div class="kv"><dt>Queries</dt><dd>${num((dns.totals || {}).queries)}</dd><dt>Blocked</dt><dd>${num((dns.totals || {}).blocked)} (${FS.pct((dns.totals || {}).blocked, (dns.totals || {}).queries)})</dd><dt>Clients</dt><dd>${num((dns.totals || {}).clients)}</dd><dt>Domains</dt><dd>${num((dns.totals || {}).domains)}</dd></div><div style="margin-top:8px">${bars((dns.blocked || []).slice(0, 5).map(d => ({ label: d.domain, value: d.queries, sub: d.list })))}</div>`)}
      </div>
      <div class="grid cols-2" style="margin-top:14px">
        ${card('Modules', Object.entries(health.modules || {}).map(([n, m]) => `<div class="barrow" style="grid-template-columns:auto 1fr auto"><span><i class="dot ${m.ok ? 'ok' : 'bad'}"></i><b>${esc(n)}</b></span><span class="muted small" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.detail || '')}</span><span class="small muted">${(m.capabilities || []).join(', ')}</span></div>`).join(''), `<a href="#system">details</a>`)}
        ${card('Open findings', openF.length ? table(openF.slice(0, 10), FS.findingCols()) : FS.empty('No open findings'), `who sent what, where, and why \u00b7 <a href="#findings">all ${num(openF.length)}</a>`)}
      </div>`;

      // Handle dismiss button for setup banner
      const dismissBtn = FS.$('#dismiss-banner', el);
      if (dismissBtn) {
        dismissBtn.onclick = (e) => {
          e.preventDefault();
          try { localStorage.setItem('fs.setupBannerDismissed', Date.now().toString()); } catch (e) {}
          FS.$('[id="dismiss-banner"]', el).closest('div').remove();
        };
      }
      if (FS.adviceWire) FS.adviceWire(el, () => FS.render());
    }
  });

  // ------------------------------------------------------------- IP Addresses
  FS.registerPage('hosts', {
    title: 'IP Addresses', refresh: 30,
    async render(el, ctx) {
      const [d] = await Promise.all([get(`/api/identity/hosts?${FS.since()}${ctx.params.all ? '&all=1' : ''}`), (FS.loadIssues ? FS.loadIssues() : null)]);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      let rows = d.hosts || [];
      const q = (ctx.params.q || '').toLowerCase();
      if (q) rows = rows.filter(h => JSON.stringify(h).toLowerCase().includes(q));
      // One row per device: every address behind the same hardware address
      // folds into one, traffic summed, the addresses listed under the name.
      // Addresses with no known device stay their own rows.
      let byDevice = false; try { byDevice = localStorage.getItem('fs.hostsByDevice') === '1'; } catch (e) {}
      const seen = rows.length;
      if (byDevice) {
        const dev = new Map(); const out = [];
        rows.forEach(r => {
          if (!r.mac) { out.push(r); return; }
          let g = dev.get(r.mac);
          if (!g) { g = Object.assign({}, r, { addrs: [], bytes_in: 0, bytes_out: 0, flows: 0, blocked: 0, alerts: 0, last_seen: 0 }); dev.set(r.mac, g); out.push(g); }
          g.addrs.push(r.ip);
          if (!g.name && r.name) g.name = r.name;
          if (g.ip.includes(':') && !r.ip.includes(':')) g.ip = r.ip; // prefer the IPv4 address as the row's link
          g.bytes_in += r.bytes_in || 0; g.bytes_out += r.bytes_out || 0; g.flows += r.flows || 0; g.blocked += r.blocked || 0; g.alerts += r.alerts || 0;
          if ((r.last_seen || 0) > g.last_seen) g.last_seen = r.last_seen;
        });
        rows = out;
      }
      el.innerHTML = `<div class="actions"><span class="muted">${byDevice ? `${rows.length} devices (${seen} addresses)` : `${rows.length} addresses`} seen in the last ${FS.state.hours}h</span><label class="small" style="margin-left:12px;display:inline-flex;align-items:center;gap:6px"><input type="checkbox" id="by-device" ${byDevice ? 'checked' : ''}> one row per device</label><span class="spacer" style="flex:1"></span><a class="btn" href="#hosts?all=1">Include inactive</a></div>` +
        card('IP Addresses', table(rows, [
          // The address is the row; the device it belongs to reads under it.
          { t: 'Address', f: r => `<a href="#host/${encodeURIComponent(r.ip)}" class="mono">${esc(r.ip)}</a>${FS.issueMark ? FS.issueMark(r.ip, r.mac, ...(r.addrs || [])) : ''}${r.name ? `<div class="muted small">${esc(r.name)}${FS.provenanceMark(r.name_source, r.name_confidence)}</div>` : ''}` + (r.addrs && r.addrs.length > 1 ? `<div class="muted small mono">${r.addrs.filter(a => a !== r.ip).map(a => `<a href="#host/${encodeURIComponent(a)}">${esc(a)}</a>`).join(' · ')}</div>` : ''), sort: 'ip' },
          { t: 'Device', f: r => esc(r.name || ''), sort: 'name' },
          { t: 'MAC', f: r => `<span class="mono">${esc(r.mac || '')}</span>${r.randomized ? ' ' + pill('private', '') : ''}`, sort: 'mac' },
          { t: 'Vendor', k: 'vendor' }, { t: 'Zone', f: r => r.zone ? pill(r.zone, 'info') : '', sort: 'zone' },
          { t: 'Down', f: r => bytes(r.bytes_in), num: true, sort: 'bytes_in' }, { t: 'Up', f: r => bytes(r.bytes_out), num: true, sort: 'bytes_out' },
          { t: 'Flows', f: r => num(r.flows), num: true, sort: 'flows' }, { t: 'Blocked', f: r => r.blocked ? `<span class="sev-high">${num(r.blocked)}</span>` : '0', num: true, sort: 'blocked' },
          { t: 'Alerts', f: r => r.alerts ? `<span class="sev-high">${num(r.alerts)}</span>` : '0', num: true, sort: 'alerts' },
          { t: 'Last seen', f: r => ago(r.last_seen), sort: 'last_seen' }]));
      const cb = FS.$('#by-device', el);
      if (cb) cb.onchange = () => { try { localStorage.setItem('fs.hostsByDevice', cb.checked ? '1' : '0'); } catch (e) {} FS.render(); };
    }
  });

  // ------------------------------------------------------------- Host detail
  FS.registerPage('host', {
    title: 'Host', refresh: 30,
    async render(el, ctx) {
      const ip = ctx.arg; if (!ip) { el.innerHTML = FS.err('no host given'); return; }
      const [d, scanData, visData, hf, dnsName] = await Promise.all([
        get(`/api/visibility/host?ip=${encodeURIComponent(ip)}&${FS.since()}`),
        get(`/api/scan/result?ip=${encodeURIComponent(ip)}`),
        get(`/api/visibility/visibility?ip=${encodeURIComponent(ip)}&${FS.since()}`),
        get(`/api/system/findings?host=${encodeURIComponent(ip)}`),
        get(`/api/dns/names/suggest?ip=${encodeURIComponent(ip)}`)
      ]);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      // Findings about this device from every module, across all its addresses.
      const devF = ((hf && hf.findings) || d.findings || []).filter(f => !f.acked);
      const h = d.host || {}, dev = d.device || {}, t = d.totals || {}, dt = d.dns_totals || {};
      const scan = scanData && !scanData.error ? scanData : null;
      FS.setTitle((h.name || ip) + (h.name ? ` · ${ip}` : ''));
      const identCard = `<dl class="kv"><dt>Address</dt><dd class="mono">${esc(ip)}${(d.addresses || []).length > 1 ? `<div class="small muted" style="margin-top:3px">also ${(d.addresses || []).filter(a => a !== ip).map(a => `<a href="#host/${encodeURIComponent(a)}" class="mono">${esc(a)}</a>`).join(', ')}</div>` : ''}</dd><dt>Name</dt><dd>${esc(h.name || '—')} <a href="#" id="rename" class="small">rename</a></dd>${FS.dnsNameRow ? FS.dnsNameRow(dnsName) : ''}<dt>MAC</dt><dd class="mono">${esc(h.mac || '—')}</dd><dt>Vendor</dt><dd>${esc(h.vendor || '—')}</dd><dt>Zone</dt><dd>${esc(dev.zone || h.zone || '—')}</dd><dt>Class</dt><dd>${esc(dev.class || dev.device_type || h.device_type || '—')}</dd>${dev.proxmox ? `<dt>Proxmox</dt><dd>${esc(dev.proxmox.name)} (${dev.proxmox.type} ${dev.proxmox.vmid} on ${esc(dev.proxmox.node)})</dd>` : ''}<dt>First seen</dt><dd>${h.first_seen ? when(h.first_seen) : '—'}</dd><dt>Last seen</dt><dd>${ago(h.last_seen)}</dd></dl><div class="actions"><button class="btn small" id="identify">Identify device</button></div>`;
      el.innerHTML = `
      ${devF.length && FS.adviceHTML ? `<div class="attn" style="margin-bottom:14px">${card(`Needs attention on this device`, FS.adviceHTML(devF, { hideDevice: true, max: 5 }), `${num(devF.length)} open \u00b7 details in Findings below`)}</div>` : ''}
      <div class="grid cols-4">
        ${card('Identity', identCard)}
        ${kpi('Traffic', bytes((t.bytes_in || 0) + (t.bytes_out || 0)), `${bytes(t.bytes_in)} down · ${bytes(t.bytes_out)} up`)}
        ${kpi('Flows', num(t.flows), `${num(t.blocked)} blocked`, t.blocked ? 'warn' : '')}
        ${kpi('DNS', num(dt.queries), `${num(dt.blocked)} blocked · ${num(dt.domains)} domains`, dt.blocked ? 'warn' : '')}
      </div>
      <div style="margin-top:14px">${card('Activity', chart([{ name: 'download', points: (d.timeline || []).map(p => [p.t, p.bytes_in]) }, { name: 'upload', points: (d.timeline || []).map(p => [p.t, p.bytes_out]) }, { name: 'blocked', points: (d.timeline || []).map(p => [p.t, p.blocked]) , color: '#dc2626'}], { fmt: bytes, area: true, tall: true }) + FS.legend(['download', 'upload', 'blocked flows']))}</div>
      ${scan ? `<div style="margin-top:14px">${card('Identification', `<div class="small muted">Scanned ${ago(scan.finished)}</div>` + (scan.os_guesses && scan.os_guesses.length ? `<div><b>OS:</b> ${scan.os_guesses.map(g => esc(g.os)).join(', ')}</div>` : '') + (scan.open_ports && scan.open_ports.length ? `<div><b>Ports:</b> ${scan.open_ports.map(p => p.port).join(', ')}</div>` : '') + (scan.nmap_enhanced ? '<div class="small muted">via nmap</div>' : ''))}</div>` : ''}
      <div class="grid cols-3" style="margin-top:14px">
        ${card('Applications', bars((d.apps || []).map(a => ({ label: a.app, sub: `${a.category || ''}${a.category ? ' · ' : ''}${bytes((a.bytes_in || 0) + (a.bytes_out || 0))}`, value: a.flows || 0 })), sessions), 'by sessions')}
        ${card('Sites', bars((d.domains || []).map(a => ({ label: a.domain, sub: `${a.category || ''}${a.category ? ' · ' : ''}${bytes((a.bytes_in || 0) + (a.bytes_out || 0))}`, value: a.flows || 0, href: '#flows?ip=' + ip + '&domain=' + encodeURIComponent(a.domain) })), sessions), 'by sessions')}
        ${card('Destinations', bars((d.destinations || []).map(a => ({ label: a.name || a.ip, sub: `${a.ip}:${a.port}/${a.proto}`, value: (a.bytes_in || 0) + (a.bytes_out || 0) })), bytes))}
      </div>
      <div class="grid cols-2" style="margin-top:14px">
        ${card('DNS', table(d.dns || [], [{ t: 'Domain', f: r => domainLink(r.domain) }, { t: 'Action', f: r => r.action === 'pass' ? pill('pass', 'ok') : pill(r.action + (r.list ? ' · ' + r.list : ''), 'bad'), sort: 'action' }, { t: 'Queries', k: 'queries', num: true }]))}
        ${card('Blocked queries', table(d.dns_blocked || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Domain', f: r => domainLink(r.domain) }, { t: 'Type', k: 'qtype' }, { t: 'List', f: r => pill(r.list || 'blocked', 'bad') }, { t: 'Via', f: r => `<span class="small muted">${esc((r.source || 'unbound').replace('pihole:', 'pi-hole '))}</span>` }]), `<a href="#dns?client=${encodeURIComponent(ip)}&blocked=1">all blocked for this host</a>`)}
        ${card('TLS', table(d.tls || [], [{ t: 'Server name', k: 'sni' }, { t: 'Version', k: 'version' }, { t: 'Mode', f: r => pill(r.mode || 'splice', r.mode === 'bump' ? 'warn' : r.mode === 'terminate' ? 'bad' : ''), sort: 'mode' }, { t: 'Sessions', k: 'sessions', num: true }]))}
      </div>
      ${visData && !visData.error ? `<div style="margin-top:14px">${card('What FlowSight can see for this device', (() => {
        const vis = visData.visibility || {}; const labels = { inspected: 'Inspected by FlowSight: content and names fully visible', sni: 'TLS with server name: names from ClientHello, content not inspected', http: 'Plain HTTP: names and content visible', quic: 'QUIC encrypted: names unknown, encryption end-to-end', ech: 'Encrypted Client Hello: names encrypted by design', opaque: 'Encrypted with no visible name: cannot steer traffic to these destinations', dns: 'DNS transactions: names and answers visible', plain: 'Other unencrypted traffic' };
        const entries = Object.entries(vis).filter(([_, count]) => count > 0).map(([k, count]) => `<div style="margin:8px 0"><b>${esc(k)}</b> (${count} sessions): ${esc(labels[k] || 'Unknown')}<br><a href="#flows?ip=${encodeURIComponent(ip)}&visibility=${esc(k)}" class="small">see these sessions →</a></div>`).join('');
        return entries || '<span class="muted">No visibility data</span>';
      })())}</div>` : ''}
      <div style="margin-top:14px">${card('Recent flows', table(d.flows || [], [{ t: 'When', f: r => when(r.end_ts || r.ts), sort: 'ts' }, { t: 'Destination', f: r => `${FS.ipTag(r.dst_ip, r.dst_name)}:${r.dst_port} <span class="muted small">${esc(r.proto)}</span>`, sort: 'dst_ip' }, { t: 'Application', f: r => `${esc(r.app || '')} <span class="muted small">${esc(r.category || '')}</span>`, sort: 'app' }, { t: 'Site', f: r => esc(r.domain || ''), sort: 'domain' }, { t: 'Down', f: r => bytes(r.bytes_in), num: true, sort: 'bytes_in' }, { t: 'Up', f: r => bytes(r.bytes_out), num: true, sort: 'bytes_out' }, { t: 'Verdict', f: r => FS.verdictPill(r.verdict) + (r.policy ? ` <span class="muted small">${esc(r.policy)}</span>` : ''), sort: 'verdict' }]))}</div>
      <div class="grid cols-2" style="margin-top:14px">
        ${card('Alerts', table(d.alerts || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Severity', f: r => FS.sevPill(r.severity), sort: 'severity' }, { t: 'Signature', k: 'signature' }, { t: 'Peer', f: r => r.src_ip === ip ? esc(r.dst_ip) : esc(r.src_ip) }]))}
      </div>
      <div style="margin-top:14px" id="host-findings">${card('Findings', devF.length ? table(devF, FS.findingCols().filter(c => c.t !== 'Who')) : FS.empty('No open findings for this device'), 'every address this device has used')}</div>`;
      if (FS.adviceWire) FS.adviceWire(el, () => FS.render());
      // A quick way to the question everyone asks about a gadget.
      const idc = FS.$('#rename', el); if (idc && idc.parentNode && !FS.$('#abroad-link', el)) { const a = document.createElement('a'); a.id = 'abroad-link'; a.className = 'btn small'; a.href = '#flows?ip=' + encodeURIComponent(ip) + '&abroad=1'; a.textContent = 'Sessions outside the country'; idc.parentNode.appendChild(a); }
      if (idc && idc.parentNode && !FS.$('#baseline-link', el)) { const b = document.createElement('a'); b.id = 'baseline-link'; b.className = 'btn small'; b.href = '#anomalies?ip=' + encodeURIComponent(ip); b.textContent = 'Baseline'; idc.parentNode.appendChild(b); }
      FS.$$('[data-nm-open]', el).forEach(a => a.onclick = (e) => { e.preventDefault(); FS.nameDevice(ip, h.name || '', () => FS.render()); });
      if (FS.nameDevice) FS.$('#rename', el).onclick = (e) => { e.preventDefault(); FS.nameDevice(ip, h.name || '', () => FS.render()); };
      else FS.$('#rename', el).onclick = async (e) => { e.preventDefault(); const name = prompt('Display name for ' + ip, h.name || ''); if (name === null) return; const r = await post('/api/identity/name', { ip, name }); if (r.error) FS.toast(r.error, true); else FS.render(); };
      const identBtn = FS.$('#identify', el);
      if (identBtn) identBtn.onclick = async () => { const scanResp = await post('/api/scan/start', { ip, profile: 'identify' }); if (scanResp.error) { FS.toast(scanResp.error.includes('disabled') ? 'Scanning disabled: Settings › Scan to enable it' : scanResp.error, true); return; } FS.toast('Identifying ' + ip + '...'); let result; for (let i = 0; i < 60; i++) { await new Promise(r => setTimeout(r, 3000)); result = await get(`/api/scan/result?ip=${encodeURIComponent(ip)}`); if (result && !result.error && result.finished) break; } if (result && !result.error) FS.render(); };
    }
  });

  // ------------------------------------------------------------- Flows / sessions
  FS.registerPage('flows', {
    title: 'Sessions', refresh: 10,
    async render(el, ctx) {
      const p = ctx.params; const qs = new URLSearchParams({ minutes: p.minutes || 30, limit: 500 });
      if (p.ip) qs.set('ip', p.ip); if (p.app) qs.set('app', p.app); if (p.blocked) qs.set('blocked', '1');
      if (p.country) qs.set('country', p.country); if (p.abroad) qs.set('abroad', '1'); if (p.anycast) qs.set('anycast', '1');
      if (p.source) qs.set('source', p.source);
      if (p.visibility) qs.set('visibility', p.visibility);
      const d = await get('/api/visibility/flows?' + qs);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      let rows = d.flows || [];
      if (p.domain) rows = rows.filter(f => (f.domain || '').includes(p.domain));
      if (p.visibility) rows = rows.filter(f => f.visibility === p.visibility);
      const filt = (k, v) => v ? `<span class="chip"${k === 'country' ? ` title="${esc(FS.countryName(v))}"` : ''}>${esc(k)}: ${esc(v)} <button data-k="${esc(k)}">×</button></span>` : '';
      const home = d.home_country || '';
      el.innerHTML = `<div class="actions"><div class="chips">${filt('ip', p.ip)}${filt('app', p.app)}${filt('domain', p.domain)}${filt('country', p.country)}${filt('source', p.source)}${filt('visibility', p.visibility)}${p.abroad ? filt('only', 'outside ' + (home || 'home')) : ''}${p.anycast ? filt('only', 'anycast') : ''}${p.blocked ? filt('only', 'blocked') : ''}</div><span style="flex:1"></span><div class="seg" id="win">${[15, 30, 60, 240, 1440].map(m => `<button data-m="${m}" class="${String(p.minutes || 30) === String(m) ? 'on' : ''}">${m < 60 ? m + 'm' : (m / 60) + 'h'}</button>`).join('')}</div><a class="btn" href="#flows?abroad=1${p.ip ? '&ip=' + p.ip : ''}" title="${home ? 'Sessions whose far end is outside ' + esc(home) : 'Sessions whose far end is outside this country (needs the country database under Settings › enrich)'}">Outside ${esc(home || 'the country')}${home ? ` <span class="muted small">(${esc(FS.countryName(home))})</span>` : ''}</a><a class="btn" href="#flows?blocked=1${p.ip ? '&ip=' + p.ip : ''}">Blocked only</a></div>` +
        card(`${rows.length} sessions`, table(rows, [
          { t: 'When', f: r => when(r.end_ts || r.ts), sort: 'ts' },
          { t: 'Client', f: r => hostLink(r.src_ip, r.src_name), sort: 'src_ip' },
          { t: 'Server', f: r => `${FS.ipTag(r.dst_ip, r.dst_name)}:${r.dst_port}${r.anycast ? ` <a class="pill" href="#flows?anycast=1${p.ip ? '&ip=' + p.ip : ''}" title="Anycast: this range answers from many sites at once. The country is where it is registered, not where it answered from.">anycast</a>` : ''}${r.country && r.country !== '-' ? ` <a class="pill ${home && !r.anycast && r.country.toUpperCase() !== home ? 'warn' : ''}" href="#flows?country=${esc(r.country)}${p.ip ? '&ip=' + p.ip : ''}" title="${esc(FS.countryName(r.country))} — Sessions to ${esc(r.country)}">${esc(r.country)}</a>` : ''}`, sort: 'dst_ip' },
          { t: 'App', f: r => `<a href="#flows?app=${encodeURIComponent(r.app || '')}">${esc(r.app || '')}</a> <span class="muted small">${esc(r.category || '')}</span>`, sort: 'app' },
          { t: 'Site', f: r => r.domain_source === 'probe_name' ? `<span class="muted" title="Name from the flow probe's cache: the last DNS answer it saw for this address, not something this client asked for">${domainLink(r.domain)}</span>` : (r.domain && r.domain_source ? `<span title="Name from ${esc({ sni: 'the TLS ClientHello (SNI)', http_host: 'the HTTP Host header', dns_query: 'the DNS query' }[r.domain_source] || r.domain_source)}">${domainLink(r.domain)}</span>` : domainLink(r.domain)), sort: 'domain' },
          { t: 'Proto', f: r => `${esc(r.proto || '')}${r.tls_version ? ' <span class="muted small">' + esc(r.tls_version) + '</span>' : ''}`, sort: 'proto' },
          { t: 'Down', f: r => bytes(r.bytes_in), num: true, sort: 'bytes_in' }, { t: 'Up', f: r => bytes(r.bytes_out), num: true, sort: 'bytes_out' },
          { t: 'Duration', f: r => dur(r.duration), num: true, sort: 'duration' },
          { t: 'Verdict', f: r => FS.verdictPill(r.verdict) + (r.policy ? ` <span class="muted small">${esc(r.policy)}</span>` : ''), sort: 'verdict' },
          { t: 'Source', k: 'source' },
          { t: 'Readable', f: r => {
            const v = r.visibility || ''; const titles = { inspected: 'Inspected by FlowSight', sni: 'TLS with server name visible', http: 'Plain HTTP', quic: 'QUIC encrypted', ech: 'Encrypted Client Hello', opaque: 'Encrypted, name unknown', dns: 'DNS transaction', plain: 'Unencrypted' };
            return v ? `<span class="muted small" title="${esc(titles[v] || v)}">${esc(v)}</span>` : '';
          }, sort: 'visibility' },
          // The path this session takes: the map narrowed to this client and
          // this destination, one traceroute, nothing else. Local-to-local
          // sessions have no path across the internet to show.
          { t: '', f: r => FS.isPrivateIP(r.dst_ip) || !r.dst_ip ? '' : `<a class="btn small" href="#paths?dst=${encodeURIComponent(r.dst_ip)}&device=${encodeURIComponent(r.src_ip || '')}" title="Show this session's path on the map: ${esc(r.src_name || r.src_ip)} to ${esc(r.dst_name || r.dst_ip)}">Map</a>` }]));
      FS.$$('#win button', el).forEach(b => b.onclick = () => { p.minutes = b.dataset.m; FS.go('#flows?' + new URLSearchParams(p)); });
      FS.$$('.chip button', el).forEach(b => b.onclick = () => { if (b.dataset.k === 'only') { delete p.blocked; delete p.abroad; } else delete p[b.dataset.k]; FS.go('#flows?' + new URLSearchParams(p)); });
    }
  });

  // ------------------------------------------------------------- Applications
  FS.registerPage('apps', {
    title: 'Applications', refresh: 30,
    async render(el) {
      const d = await get(`/api/visibility/apps?${FS.since()}`);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const rows = d.apps || [];
      const byCat = {}; rows.forEach(a => { const c = a.category || 'Unknown'; byCat[c] = (byCat[c] || 0) + (a.flows || 0); });
      const breedPill = b => b ? pill(b, { Safe: 'ok', Acceptable: 'ok', Fun: 'info', Unsafe: 'warn', Dangerous: 'bad', Potentially_Dangerous: 'warn' }[b] || '') : '';
      el.innerHTML = `<div class="help" style="margin-bottom:10px">Applications and their categories are identified by nDPI from each flow's own packets; the breed is its risk grade. These are not the web-content categories under Protect \u203a Categories; <a href="https://github.com/grio-co/flowsight/blob/main/docs/howto/categories-and-apps.md" target="_blank" rel="noopener">how each is identified</a>.</div><div class="two">${card('Applications', table(rows, [
        { t: 'Application', f: r => (!r.app || r.app === 'Unknown') ? `<a href="#unknown" title="What nDPI could not name, taken apart by what else is known"><b>Unknown</b></a> <span class="muted small">catalogue</span>` : `<a href="#app/${encodeURIComponent(r.app)}" title="What it is, who uses it, where it goes">${esc(r.app)}</a> <a class="muted small" href="#flows?app=${encodeURIComponent(r.app)}">sessions</a>`, sort: 'app' },
        { t: 'Category', f: r => r.category ? `<a href="#appcat/${encodeURIComponent(r.category)}" title="Everything in this category">${esc(r.category)}</a>` : '', sort: 'category' }, { t: 'Breed', f: r => breedPill(r.breed), sort: 'breed' },
        { t: 'Sessions', f: r => num(r.flows), num: true, sort: 'flows' },
        { t: 'Who', f: r => `${num(r.hosts || 0)} host${r.hosts === 1 ? '' : 's'}${(r.top_hosts || []).length ? `<div class="small">${(r.top_hosts || []).map(h => `<a href="#flows?app=${encodeURIComponent(r.app)}&ip=${encodeURIComponent(h.ip)}" title="${num(h.flows)} sessions">${esc(h.name || h.ip)}</a>`).join(', ')}</div>` : ''}`, sort: 'hosts' },
        { t: 'Last seen', f: r => r.last_seen ? ago(r.last_seen) : '', sort: 'last_seen' },
        { t: 'Blocked', f: r => r.blocked ? `<span class="sev-high">${num(r.blocked)}</span>` : '0', num: true, sort: 'blocked' },
        { t: 'Down', f: r => bytes(r.bytes_in), num: true, sort: 'bytes_in' }, { t: 'Up', f: r => bytes(r.bytes_out), num: true, sort: 'bytes_out' },
        { t: 'Block', f: r => `<button class="btn small" data-app="${esc(r.app)}">policy…</button>` }]))}
      <div class="stack">${card('By category', donut(Object.entries(byCat).map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value), sessions), 'by sessions')}${card('About', `<p class="small muted">Applications are identified by nDPI on the first packets of each flow. Breed is nDPI's own risk grouping. Use <b>policy…</b> to deny an application for a group of devices; enforcement is at the firewall and needs no inline engine.</p>`)}</div></div>`;
      FS.$$('button[data-app]', el).forEach(b => b.onclick = () => FS.quickPolicy({ apps: [b.dataset.app] }));
    }
  });

  // ------------------------------------------------------------- Web
  FS.registerPage('web', {
    title: 'Web', refresh: 30,
    async render(el, ctx) {
      const [s, l, st] = await Promise.all([get(`/api/web/summary?${FS.since()}&limit=12`), get('/api/web/log?limit=300' + (ctx.params.blocked ? '&blocked=1' : '') + (ctx.params.decrypted ? '&decrypted=1' : '') + (ctx.params.client ? '&client=' + encodeURIComponent(ctx.params.client) : '')), get('/api/web/status')]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const t = s.totals || {};
      const state = !st.intercepting ? pill('interception off', 'warn') : st.running ? pill('intercepting', 'ok') : pill('proxy down', 'bad');
      el.innerHTML = `<div class="grid cols-4">${kpi('Requests', num(t.requests), `${num(t.domains)} sites · ${num(t.clients)} clients`)}${kpi('Blocked', num(t.blocked), FS.pct(t.blocked, t.requests) + ' of requests', t.blocked ? 'warn' : '')}${kpi('TLS handling', (s.tls_modes || []).map(m => `${esc(m.mode || 'splice')} ${num(m.sessions)}`).join(' · ') || '—', 'splice = untouched, bump = inspected')}${card('Proxy', `<div>${state}</div><div class="small muted" style="margin-top:6px">${esc(st.error || (st.intercepting ? 'Port 80 and 443 from local networks pass through the FlowSight proxy.' : 'Enable interception in the web module settings to see server names and block sites.'))}</div><div class="actions"><a class="btn" href="#modules/web">Settings</a></div>`)}</div>
      <div class="grid cols-3" style="margin-top:14px">${card('Top sites', bars((s.sites || []).map(d => ({ label: d.domain, sub: d.category || '', value: d.requests, href: '#flows?domain=' + encodeURIComponent(d.domain) }))))}${card('Categories', donut((s.categories || []).map(c => ({ label: c.category, value: c.requests }))))}${card('Blocked sites', bars((s.blocked || []).map(d => ({ label: d.domain, value: d.requests }))))}</div>
      <div style="margin-top:14px">${card('Requests', table(l.requests || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Client', f: r => hostLink(r.src_ip, r.src_name), sort: 'src_ip' }, { t: 'Site', f: r => domainLink(r.domain), sort: 'domain' }, { t: 'Request', f: r => r.url ? `<span class="mono small" title="${esc(r.url)}">${esc(r.method || 'GET')} ${esc((r.url || '').replace(/^https?:\/\/[^/]+/, '') || '/')}</span>${r.status ? ` <span class="muted small">${esc(r.status)}</span>` : ''}` : (r.proto === 'tls' ? '<span class="muted small">encrypted (not inspected)</span>' : '') }, { t: 'Category', k: 'category' }, { t: 'Proto', f: r => esc(r.proto) + (r.tls_version ? ' <span class="muted small">' + esc(r.tls_version) + '</span>' : '') + (r.url && r.proto === 'tls' ? ' ' + pill('decrypted', 'warn') : '') }, { t: 'Bytes', f: r => bytes(r.bytes_in), num: true, sort: 'bytes_in' }, { t: 'Verdict', f: r => FS.verdictPill(r.verdict), sort: 'verdict' }]), `<a href="#web?decrypted=1">decrypted only</a> · <a href="#web?blocked=1">blocked only</a> · <a href="#web">all</a>`)}</div>`;
    }
  });

  // ------------------------------------------------------------- DNS
  FS.registerPage('dns', {
    title: 'DNS', refresh: 30,
    async render(el, ctx) {
      const p = ctx.params; const lq = new URLSearchParams({ limit: 300 }); if (p.client) lq.set('client', p.client); if (p.domain) lq.set('domain', p.domain); if (p.blocked) lq.set('blocked', '1');
      const [s, l, ts, tabs, adv] = await Promise.all([get(`/api/dns/summary?${FS.since()}&limit=12`), get('/api/dns/log?' + lq), get(`/api/dns/timeseries?${FS.since()}`), (FS.dnsTabs ? FS.dnsTabs('dns') : ''), get('/api/system/findings?module=advisor' + (p.client ? '&host=' + encodeURIComponent(p.client) : ''))]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const t = s.totals || {}, live = s.live || {};
      const advF = ((adv && adv.findings) || []).filter(f => !f.acked);
      el.innerHTML = tabs + (advF.length && FS.adviceHTML ? `<div class="attn" style="margin-bottom:14px">${card('Device advisories', FS.adviceHTML(advF, { max: 5 }), 'DNS answers that are breaking something on a device')}</div>` : '') + `<div class="grid cols-5" style="grid-template-columns:repeat(5,minmax(0,1fr))">${kpi('Queries', num(t.queries), `${num(t.clients)} clients · ${num(t.domains)} domains`)}${kpi('Blocked', num(t.blocked), FS.pct(t.blocked, t.queries), t.blocked ? 'warn' : '')}${kpi('Cache hits', FS.pct(live.cached, live.queries), 'of answers (raw window)')}${kpi('Failures', num((live.nxdomain || 0) + (live.servfail || 0)), `${num(live.nxdomain)} NXDOMAIN · ${num(live.servfail)} SERVFAIL`)}${kpi('Latency', (live.avg_ms || 0).toFixed(1) + ' ms', 'average resolution')}</div>
      <div style="margin-top:14px">${card('Queries over time', chart([{ name: 'queries', points: (ts.series || []).map(x => [x.t, x.queries]) }, { name: 'blocked', points: (ts.series || []).map(x => [x.t, x.blocked]), color: '#dc2626' }], { area: true, tall: true }) + FS.legend(['queries', 'blocked']))}</div>
      <div class="grid cols-4" style="margin-top:14px">${card('Top domains', bars((s.top || []).map(d => ({ label: d.domain, value: d.queries, href: '#dns?domain=' + encodeURIComponent(d.domain) }))))}${card('Most blocked', bars((s.blocked || []).map(d => ({ label: d.domain, sub: d.list, value: d.queries }))))}${card('Clients', bars((s.clients || []).map(c => ({ label: c.name || c.ip, sub: `${num(c.blocked)} blocked`, value: c.queries, href: '#dns?client=' + c.ip }))))}${card('Blocked by', donut((s.lists || []).map(x => ({ label: x.list, value: x.queries }))))}</div>
      <div style="margin-top:14px">${card('Query log', `<div class="chips" style="margin-bottom:8px">${p.client ? `<span class="chip">client: ${esc(p.client)} <a href="#dns">×</a></span>` : ''}${p.domain ? `<span class="chip">domain: ${esc(p.domain)} <a href="#dns">×</a></span>` : ''}</div>` + table(l.queries || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Client', f: r => hostLink(r.client, r.client_name), sort: 'client' }, { t: 'Domain', f: r => `<a href="#dns?domain=${encodeURIComponent(r.domain)}">${esc(r.domain)}</a>`, sort: 'domain' }, { t: 'Via', f: r => `<span class="small muted">${esc((r.source || 'unbound').replace('pihole:', 'pi-hole ').replace('doh:', 'DoH '))}</span>`, sort: 'source' }, { t: 'Type', k: 'qtype' }, { t: 'Result', f: r => r.action === 'pass' ? pill(r.rcode || 'ok', r.rcode === 'NOERROR' ? 'ok' : '') : pill('blocked' + (r.list ? ' · ' + r.list : ''), 'bad'), sort: 'action' }, { t: 'Source', k: 'answer_source' }, { t: 'ms', f: r => (r.ms || 0).toFixed(0), num: true, sort: 'ms' }]), `<a href="#dns?blocked=1">blocked only</a>`)}</div>`;
      if (FS.adviceWire) FS.adviceWire(el, () => FS.render());
    }
  });

  // ------------------------------------------------------------- Threats
  FS.registerPage('threats', {
    title: 'Threats', refresh: 30,
    async render(el, ctx) {
      const [s, a] = await Promise.all([get(`/api/ids/summary?${FS.since()}`), get(`/api/ids/alerts?${FS.since()}&limit=300${ctx.params.severity ? '&severity=' + ctx.params.severity : ''}`)]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const sev = {}; (s.by_severity || []).forEach(x => sev[x.severity] = x.alerts);
      el.innerHTML = `<div class="grid cols-4">${kpi('Alerts', num(s.total), `${num(s.blocked)} dropped by IPS`, s.total ? 'warn' : '')}${kpi('Critical / high', num((sev.critical || 0) + (sev.high || 0)), `${num(sev.medium)} medium · ${num(sev.low)} low`, sev.critical ? 'bad' : sev.high ? 'warn' : '')}${kpi('Sources', num((s.by_source || []).length), 'distinct attacking addresses')}${card('Engine', s.source_error ? `<div>${pill('not reading', 'bad')}</div><div class="small muted" style="margin-top:6px">${esc(s.source_error)}</div>` : `<div>${pill('Suricata', 'ok')}</div><div class="small muted" style="margin-top:6px">Alerts are read from the EVE log; Suricata's own rules and mode are managed in its service settings.</div>`)}</div>
      <div class="grid cols-3" style="margin-top:14px">${card('Top signatures', bars((s.by_signature || []).slice(0, 10).map(x => ({ label: x.signature, sub: `sid ${x.sig_id}`, value: x.alerts }))))}${card('Categories', donut((s.by_category || []).map(x => ({ label: x.category || 'uncategorised', value: x.alerts }))))}${card('Sources', bars((s.by_source || []).map(x => ({ label: x.name || x.ip, sub: x.local ? 'local' : '', value: x.alerts, href: x.local ? '#host/' + x.ip : '' }))))}</div>
      <div style="margin-top:14px">${card('Alerts', table(a.alerts || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Severity', f: r => FS.sevPill(r.severity), sort: 'severity' }, { t: 'Signature', f: r => `<b>${esc(r.signature)}</b><div class="muted small">${esc(r.category || '')} · sid ${esc(r.sig_id)}</div>`, sort: 'signature' }, { t: 'Source', f: r => hostLink(r.src_ip, r.src_ip_name) + ':' + r.src_port, sort: 'src_ip' }, { t: 'Destination', f: r => hostLink(r.dst_ip, r.dst_ip_name) + ':' + r.dst_port, sort: 'dst_ip' }, { t: 'Proto', k: 'proto' }, { t: 'Action', f: r => FS.verdictPill(r.verdict), sort: 'verdict' }]))}</div>`;
    }
  });

  // One certificate, in full. Everything the inventory holds about it:
  // the two distinguished names unabbreviated, every alternative name, the
  // serial, the key, the validity and the fingerprint to compare by hand.
  const certModal = (r) => {
    const dn = (v) => esc(v || '—');
    const date = (t) => t ? new Date(t * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '—';
    let sans = []; try { sans = JSON.parse(r.sans || '[]'); } catch (e) {}
    let snis = []; try { snis = JSON.parse(r.snis || '[]'); } catch (e) {}
    let attrs = {}; try { attrs = JSON.parse(r.attrs || '{}'); } catch (e) {}
    const days = r.not_after ? Math.round((r.not_after - Date.now() / 1000) / 86400) : null;
    const flags = [
      r.self_signed ? pill('self-signed', 'warn') : '',
      r.trusted === 1 ? pill('chain trusted', 'ok') : r.trusted === 0 ? pill('chain not trusted', 'bad') : '',
      days != null && days < 0 ? pill('expired', 'bad') : days != null && days < 30 ? pill('expires soon', 'warn') : '',
    ].filter(Boolean).join(' ') || '<span class="muted small">nothing of note</span>';
    const row = (k, v) => `<dt>${esc(k)}</dt><dd>${v}</dd>`;
    return `<h2>${esc((r.subject || '').replace(/^.*CN=/, '') || 'Certificate')}</h2>
      <div style="margin-bottom:12px">${flags}</div>
      <dl class="kv small certdetail">
        ${row('Subject', `<span class="mono">${dn(r.subject)}</span>`)}
        ${row('Issuer', `<span class="mono">${dn(r.issuer)}</span>`)}
        ${row('Serial', `<span class="mono">${dn(r.serial)}</span>`)}
        ${row('Valid from', date(r.not_before))}
        ${row('Valid until', date(r.not_after) + (days != null ? ` <span class="muted">(${days < 0 ? (-days) + ' days ago' : 'in ' + days + ' days'})</span>` : ''))}
        ${row('Key', r.key_type ? esc(r.key_type) + (r.key_bits ? ' ' + r.key_bits + '-bit' : '') : '<span class="muted">not read</span>')}
        ${row('Signature', dn(r.sig_alg))}
        ${attrs.tls_version ? row('Negotiated', esc(attrs.tls_version)) : ''}
        ${row('SHA-256', `<span class="mono">${dn(r.fingerprint)}</span>`)}
        ${row('Subject alternative names', sans.length ? sans.map(n => `<span class="mono">${esc(n)}</span>`).join('<br>') : '<span class="muted">none recorded</span>')}
        ${row('Server names seen', snis.length ? snis.map(n => `<a href="#flows?domain=${encodeURIComponent(n)}">${esc(n)}</a>`).join(', ') : '<span class="muted">none</span>')}
        ${row('Seen', `${num(r.seen)} times, first ${ago(r.first_seen)}, last ${ago(r.last_seen)}`)}
        ${row('Recorded by', esc(r.source || 'unknown') + (r.source === 'probe' ? ' <span class="muted">(FlowSight opened a connection and read it)</span>' : r.source === 'squid' ? ' <span class="muted">(seen in a handshake through the proxy)</span>' : ''))}
      </dl>
      <div class="actions"><button class="btn" data-close>Close</button></div>`;
  };

  // ------------------------------------------------------------- TLS
  FS.registerPage('tls', {
    title: 'TLS', refresh: 60,
    async render(el, ctx) {
      const [s, c, sess] = await Promise.all([get(`/api/tls/summary?${FS.since()}`), get(`/api/tls/certs?${FS.since()}&limit=200${ctx.params.problem ? '&problem=1' : ''}${ctx.params.q ? '&q=' + encodeURIComponent(ctx.params.q) : ''}`), get('/api/tls/sessions?limit=200')]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const t = s.totals || {}, ca = s.ca || {};
      const caCard = ca.exists ? `<div>${pill('CA ready', 'ok')}</div><dl class="kv small" style="margin-top:8px"><dt>Subject</dt><dd>${esc(ca.subject)}</dd><dt>Valid until</dt><dd>${new Date(ca.not_after * 1000).toISOString().slice(0, 10)}</dd><dt>SHA-256</dt><dd class="mono" style="word-break:break-all">${esc(ca.fingerprint_sha256)}</dd></dl><div class="actions"><a class="btn" href="${FS.base ? FS.base + encodeURIComponent('/api/tls/ca/download') : '/api/tls/ca/download'}">Download certificate</a><button class="btn danger" id="ca-del">Delete CA</button></div><div class="help">Install this certificate as a trusted root on every device whose policy has TLS inspection turned on. Devices without it will see certificate warnings for inspected sites.</div>`
        : `<div>${pill('no CA', 'warn')}</div><div class="small muted" style="margin:8px 0">Without a CA the proxy only peeks at handshakes: server names and, optionally, certificates are recorded but nothing is decrypted. Create a CA to allow policies to inspect selected devices.</div><div class="actions"><button class="btn primary" id="ca-create">Create inspection CA</button></div>`;
      el.innerHTML = `<div class="grid cols-4">${kpi('TLS sessions', num(t.sessions), `${num(t.names)} server names · ${num(t.clients)} clients`)}${kpi('Inspected', num(t.inspected), FS.pct(t.inspected, t.sessions) + ' of sessions decrypted', t.inspected ? 'warn' : '')}${kpi('Problem certificates', num(s.problem_certificates), 'expired or self-signed, seen this window', s.problem_certificates ? 'warn' : '')}${card('Inspection CA', caCard)}</div>
      <div class="grid cols-2" style="margin-top:14px">${card('Versions and handling', `<div class="small muted" style="margin-bottom:6px">Protocol version</div>${FS.strip((s.versions || []).map(v => ({ label: v.version, value: v.sessions })))}<div class="small muted" style="margin:14px 0 6px">What FlowSight did with the session</div>${FS.strip((s.modes || []).map(v => ({ label: v.mode, value: v.sessions })))}`)}${card('Issuers', bars((s.issuers || []).map(i => ({ label: FS.issuerName(i.issuer), title: i.issuer, value: i.seen }))))}</div>
      <div style="margin-top:14px" id="certs-card">${card('Certificates', table(c.certificates || [], [{ t: 'Subject', f: r => `<b>${esc((r.subject || '').replace(/^.*CN=/, ''))}</b><div class="muted small">${esc(r.subject || '')}</div>`, sort: 'subject' }, { t: 'Issuer', f: r => `<span title="${esc(r.issuer || '')}">${esc(FS.issuerName(r.issuer))}</span>`, sort: 'issuer' }, { t: 'Names', f: r => esc((JSON.parse(r.snis || '[]')).slice(0, 3).join(', ')) }, { t: 'Key', f: r => r.key_type ? `<span class="small">${esc(r.key_type)}${r.key_bits ? ' ' + r.key_bits : ''}</span>` : '', sort: 'key_bits' }, { t: 'Expires', f: r => { if (!r.not_after) return '<span class="muted small">not read yet</span>'; const d = new Date(r.not_after * 1000), days = Math.round((r.not_after - Date.now() / 1000) / 86400); return `<span class="${days < 0 ? 'sev-high' : days < 30 ? 'sev-medium' : ''}">${d.toISOString().slice(0, 10)}</span><div class="muted small">${days < 0 ? 'expired ' + (-days) + 'd ago' : 'in ' + days + 'd'}</div>`; }, sort: 'not_after' }, { t: 'Flags', f: r => [r.self_signed ? pill('self-signed', 'warn') : '', r.trusted === 0 ? pill('chain not trusted', 'bad') : r.trusted === 1 ? pill('trusted', 'ok') : ''].filter(Boolean).join(' ') }, { t: 'Seen', f: r => num(r.seen), num: true, sort: 'seen' }, { t: 'Last', f: r => ago(r.last_seen), sort: 'last_seen' }, { t: 'Via', k: 'source' }], { rowAttr: r => `class="clickable" data-cert="${esc(r.fingerprint || '')}"` }), `<a href="#tls?problem=1">problems only</a> · <span class="muted">click a row for the whole certificate</span>`)}</div>
      <div style="margin-top:14px" id="pinned-card"></div>
      <div style="margin-top:14px">${card('Recent sessions', table(sess.sessions || [], [
        { t: 'When', f: r => when(r.ts), sort: 'ts' },
        { t: 'Client', f: r => FS.addrCell(r.src_ip, r.src_name), sort: 'src_ip' },
        { t: 'Server name', f: r => r.sni ? `<a href="#flows?domain=${encodeURIComponent(r.sni)}">${esc(r.sni)}</a>` : '<span class="muted">—</span>', sort: 'sni' },
        { t: 'Server', f: r => `${FS.addrCell(r.dst_ip, r.dst_name)}${r.dst_port ? `<span class="muted small">:${r.dst_port}</span>` : ''}`, sort: 'dst_ip' },
        { t: 'Version', k: 'version' },
        { t: 'Mode', f: r => r.mode === 'bump'
            ? `<a href="#web?decrypted=1&client=${encodeURIComponent(r.src_ip || '')}" title="What was decrypted for this client">${pill('bump', 'warn')}</a>`
            : pill(r.mode || 'splice', r.mode === 'terminate' ? 'bad' : ''), sort: 'mode' },
        { t: 'JA3', f: r => `<span class="mono small">${esc((r.ja3 || '').slice(0, 12))}</span>` },
        { t: 'Via', k: 'source' }]))}</div>`;
      // The table shows what fits; the certificate itself is one click away.
      const certs = {}; (c.certificates || []).forEach(r => { if (r.fingerprint) certs[r.fingerprint] = r; });
      const certBox = FS.$('#certs-card', el);
      if (certBox) certBox.addEventListener('click', (ev) => {
        const tr = ev.target.closest('tr[data-cert]'); if (!tr) return;
        const r = certs[tr.getAttribute('data-cert')]; if (!r) return;
        FS.modal(certModal(r));
      });
      get('/api/web/pinned').then(p => {
        const list = (p && p.pinned) || []; const box = FS.$('#pinned-card', el); if (!box) return;
        box.innerHTML = card(`Pinned sites (${list.length})`, (list.length ? table(list, [
          { t: 'Name', f: r => `<b>${esc(r.name)}</b>`, sort: 'name' },
          { t: 'How', f: r => r.manual ? pill('by hand', '') : pill('detected', 'warn'), sort: 'manual' },
          { t: 'Refusals', f: r => num(r.failures), num: true, sort: 'failures' },
          { t: 'Clients', f: r => num(r.clients || 0), num: true },
          { t: 'Last', f: r => ago(r.last), sort: 'last' },
          { t: '', f: r => `<button class="btn small" data-unpin="${esc(r.name)}">Inspect again</button>` },
        ]) : '<div class="empty">Nothing is pinned</div>') +
          `<form class="f" id="pinf" style="display:flex;gap:8px;align-items:end;margin-top:8px"><div style="flex:1"><label>Add a name to relay without inspecting</label><input type="text" name="name" placeholder="app.example.com"></div><button class="btn">Add</button></form>` +
          `<div class="help">${esc((p && p.note) || '')}</div>`);
        FS.$$('[data-unpin]', box).forEach(b => b.onclick = async () => { const r = await post('/api/web/pinned', { name: b.dataset.unpin, remove: true }); FS.toast(r.error || 'Will be inspected again', !!r.error); FS.render(); });
        FS.$('#pinf', box).onsubmit = async (e) => { e.preventDefault(); const r = await post('/api/web/pinned', { name: e.target.name.value }); FS.toast(r.error || 'Added', !!r.error); FS.render(); };
      });
      const cr = FS.$('#ca-create', el); if (cr) cr.onclick = async () => { const name = prompt('Common name for the CA', 'FlowSight Inspection CA'); if (!name) return; const r = await post('/api/tls/ca/create', { name }); if (r.error) FS.toast(r.error, true); else { FS.toast('CA created'); FS.render(); } };
      const dl = FS.$('#ca-del', el); if (dl) dl.onclick = async () => { if (!await FS.confirm('Delete the inspection CA? Every policy with TLS inspection stops decrypting, and a new CA would have to be installed on devices again.')) return; const r = await post('/api/tls/ca/delete', {}); if (r.error) FS.toast(r.error, true); else FS.render(); };
    }
  });

  // ------------------------------------------------------------- Anomalies
  FS.registerPage('anomalies', {
    title: 'Anomalies', refresh: 30,
    async render(el, ctx) {
      const ip = ctx.params.ip;
      // If viewing device profile
      if (ip) {
        const p = await get(`/api/baseline/profile?ip=${encodeURIComponent(ip)}`);
        if (p.error) { el.innerHTML = FS.err(p.error); return; }
        const profile = p.profile;
        if (!profile) { el.innerHTML = FS.err('Device not found'); return; }
        const countries = profile.countries || {};
        const ports = profile.ports || {};
        const dests = profile.destinations || {};
        const countryEntries = Object.entries(countries).map(([c, r]) => ({ country: c, ...r }));
        const portEntries = Object.entries(ports).map(([p, r]) => ({ port: p, ...r }));
        const destEntries = Object.entries(dests).map(([d, r]) => ({ dest: d, ...r }));
        el.innerHTML = `
          ${card('Device profile', `<b>${esc(profile.mac)}</b><div class="small muted">First seen ${new Date(profile.first_seen * 1000).toISOString().slice(0, 10)}</div>`)}
          ${card('Countries', countryEntries.length ? table(countryEntries, [
            { t: 'Country', k: 'country' },
            { t: 'First seen', f: r => new Date(r.first_seen * 1000).toISOString().slice(0, 10) },
            { t: 'Last seen', f: r => ago(r.last_seen), sort: 'last_seen' },
            { t: 'Flows', f: r => num(r.count), num: true, sort: 'count' },
            { t: 'Bytes', f: r => bytes(r.bytes), num: true, sort: 'bytes' }
          ]) : FS.empty('No countries'))}
          ${card('Ports', portEntries.length ? table(portEntries, [
            { t: 'Port', k: 'port' },
            { t: 'First seen', f: r => new Date(r.first_seen * 1000).toISOString().slice(0, 10) },
            { t: 'Last seen', f: r => ago(r.last_seen), sort: 'last_seen' },
            { t: 'Flows', f: r => num(r.count), num: true, sort: 'count' },
            { t: 'Bytes', f: r => bytes(r.bytes), num: true, sort: 'bytes' }
          ]) : FS.empty('No ports'))}
          ${card('Destinations', destEntries.length ? table(destEntries, [
            { t: 'Destination', k: 'dest' },
            { t: 'First seen', f: r => new Date(r.first_seen * 1000).toISOString().slice(0, 10) },
            { t: 'Last seen', f: r => ago(r.last_seen), sort: 'last_seen' },
            { t: 'Flows', f: r => num(r.count), num: true, sort: 'count' },
            { t: 'Bytes', f: r => bytes(r.bytes), num: true, sort: 'bytes' }
          ]) : FS.empty('No destinations'))}
        `;
        return;
      }
      // Show anomalies list
      const d = await get('/api/baseline/anomalies');
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const anomalies = d.anomalies || [];
      const openAnomalies = anomalies.filter(a => !a.acked);
      el.innerHTML = card('Open Anomalies', openAnomalies.length ? table(openAnomalies, [
        { t: 'Device', f: r => `<a href="#anomalies?ip=${encodeURIComponent(r.device)}"><b>${esc(r.device)}</b></a><div class="muted small mono">${esc(r.mac)}</div>` },
        { t: 'Kind', f: r => pill(r.kind), sort: 'kind' },
        { t: 'Finding', f: r => `<b>${esc(r.title)}</b><div class="muted small">${esc((r.detail || '').slice(0, 100))}</div>` },
        { t: 'Severity', f: r => FS.sevPill(r.severity), sort: 'severity' },
        { t: 'Since', f: r => ago(r.ts), sort: 'ts' },
        { t: '', f: r => `<button class="btn small" data-ack="${r.id}">Ack</button>` }
      ]) : FS.empty('No open anomalies'));
      FS.$$('[data-ack]', el).forEach(b => b.onclick = async () => { await post('/api/baseline/ack', { id: Number(b.dataset.ack) }); FS.render(); });
    }
  });

  // Flow sources - NetFlow, IPFIX, sFlow exporters
  FS.registerPage('flowsources', {
    title: 'Flow sources', refresh: 10,
    async render(el) {
      const st = await get('/api/netflow/status');
      if (st.error) { el.innerHTML = FS.err('Flow sources unavailable: ' + st.error); return; }
      const exporters = st.exporters || [];
      const cols = [
        { t: 'Address', k: 'address' },
        { t: 'Protocol', k: 'protocol' },
        { t: 'Records', f: r => num(r.records_total), num: true },
        { t: 'Flows', f: r => num(r.flows_total), num: true },
        { t: 'Dropped', f: r => num(r.drops_total), num: true },
        { t: 'Templates', f: r => num(r.templates) },
        { t: 'Last seen', f: r => ago(r.last_seen) }
      ];
      el.innerHTML = exporters.length
        ? card('Connected exporters', table(exporters, cols))
        : card('Connected exporters', '<div class="empty">No exporters connected</div>');
    }
  });
})();

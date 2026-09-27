// Device advisories, and the DNS settings tabs (device names, Pi-hole).
//
// An advisory is a finding about something a person notices on a device
// ("Safari won't load", "notifications stopped") whose cause is a resolver
// answer, not a threat. They are shown where a person looks when a device
// misbehaves: at the top of the Overview, at the top of that device's page,
// beside the device in the Devices and IP Addresses lists, and on the DNS
// page. Each says what the person sees, what answered and why, and how to
// fix it, with the fix one click away when a connected Pi-hole can apply it.
(function () {
  const esc = (s) => FS.esc(s);
  const DOCS = 'https://github.com/grio-co/flowsight/blob/main/docs/howto/';
  const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const A = (f) => (f && f.attrs && typeof f.attrs === 'object') ? f.attrs : {};
  const isIP = (s) => /^\d+\.\d+\.\d+\.\d+$/.test(s || '') || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(s || '');

  // The device a finding is about, as {key, ip, name, mac}.
  FS.findingDevice = (f) => {
    const w = A(f).who || {};
    const ip = w.ip || (isIP(f.subject) ? f.subject : '');
    const mac = (w.mac || '').toLowerCase();
    if (!ip && !mac) return null;
    return { key: mac || ip, ip, name: w.name || '', mac, addresses: w.addresses || [] };
  };

  // --------------------------------------------------------------- index
  // One fetch of the open findings serves every list on a page: a map from
  // each address and MAC to the findings about that device.
  let idx = null, idxAt = 0;
  FS.loadIssues = async () => {
    if (idx && Date.now() - idxAt < 20000) return idx;
    const d = await FS.get('/api/system/findings');
    const by = new Map();
    ((d && d.findings) || []).filter(f => !f.acked).forEach(f => {
      const dev = FS.findingDevice(f); if (!dev) return;
      const keys = new Set([dev.ip, dev.mac, ...(dev.addresses || [])].filter(Boolean).map(x => String(x).toLowerCase()));
      keys.forEach(k => { if (!by.has(k)) by.set(k, []); if (!by.get(k).includes(f)) by.get(k).push(f); });
    });
    idx = by; idxAt = Date.now();
    return idx;
  };
  FS.issuesFor = (...ids) => {
    if (!idx) return [];
    const seen = new Set(); const out = [];
    ids.filter(Boolean).forEach(i => (idx.get(String(i).toLowerCase()) || []).forEach(f => { if (!seen.has(f.id)) { seen.add(f.id); out.push(f); } }));
    return out.sort((a, b) => (SEV[a.severity] ?? 5) - (SEV[b.severity] ?? 5));
  };
  // A small marker for a device row: "⚠ Private Relay blocked" or "3 issues".
  FS.issueMark = (ip, ...more) => {
    const list = FS.issuesFor(ip, ...more); if (!list.length) return '';
    const worst = list[0].severity;
    const cls = worst === 'critical' || worst === 'high' ? 'bad' : worst === 'medium' ? 'warn' : '';
    const text = list.length === 1 ? list[0].title : `${list.length} issues`;
    const tip = list.map(f => `${f.severity}: ${f.title}`).join('\n');
    return ` <a class="pill ${cls} issue-mark" href="#host/${encodeURIComponent(ip || '')}" title="${esc(tip)}">⚠ ${esc(text)}</a>`;
  };

  // --------------------------------------------------------------- advice
  const effectOf = (f) => (A(f).why || {}).effect || '';
  const fixOf = (f) => (A(f).why || {}).fix || '';

  function oneAdvice(f, opts) {
    const a = A(f), why = a.why || {}, what = a.what || {}, where = a.where || {};
    const dev = FS.findingDevice(f);
    const sevCls = f.severity === 'critical' || f.severity === 'high' ? 'bad' : f.severity === 'medium' ? 'warn' : '';
    const names = (what.domains || (what.domain ? [what.domain] : [])).slice(0, 4);
    const cause = [];
    if (where.name) cause.push(`${esc(where.name)} answered ${esc(why.answer || 'a block')}${why.list ? ` <span class="muted">(${esc(why.list)})</span>` : ''}`);
    if (names.length) cause.push(`for ${names.map(n => `<span class="mono">${esc(n)}</span>`).join(', ')}`);
    if (why.count) cause.push(`${FS.num(why.count)} times in ${FS.num(why.window_min || 15)} minutes`);
    if (why.percent != null && f.kind === 'dns_failing') cause.push(`${why.percent}% of ${FS.num(what.queries)} lookups failed`);
    const evid = dev && dev.ip ? `#dns?client=${encodeURIComponent(dev.ip)}${what.domain ? '&domain=' + encodeURIComponent(what.domain) : ''}` : '#dns';
    const btns = [];
    if (why.switch) btns.push(`<button class="btn small primary" data-adv-switch='${esc(JSON.stringify(why.switch))}'>${esc(why.switch.label || 'Change on the Pi-hole')}</button>`);
    if (why.allow) btns.push(`<button class="btn small" data-adv-allow='${esc(JSON.stringify(why.allow))}'>Allow ${why.allow.domains.length === 1 ? esc(why.allow.domains[0]) : why.allow.domains.length + ' names'} on Pi-hole ${esc(why.allow.server)}</button>`);
    btns.push(`<a class="btn small" href="${evid}">See the lookups</a>`);
    if (f.module === 'advisor') btns.push(`<a class="small" href="${DOCS}device-advisories.md" target="_blank" rel="noopener">about device advisories</a>`);
    return `<div class="advice ${sevCls}">
      <div class="advice-head">${FS.pill(f.severity, sevCls)} <b>${esc(f.title)}</b>${dev && !opts.hideDevice ? ` <span class="muted">on</span> ${FS.hostLink(dev.ip, dev.name)}` : ''} <span class="muted small">since ${FS.ago(f.ts)}</span></div>
      ${effectOf(f) ? `<div class="advice-effect">${esc(effectOf(f))}</div>` : `<div class="advice-effect">${esc(f.detail || '')}</div>`}
      ${cause.length ? `<div class="small advice-cause"><span class="muted">Cause:</span> ${cause.join(' ')}</div>` : ''}
      ${fixOf(f) ? `<div class="advice-fix"><b>What to do.</b> ${esc(fixOf(f))}</div>` : ''}
      <div class="actions">${btns.join('')}</div></div>`;
  }

  // Advisories first (they carry a fix), then the rest by severity.
  FS.adviceHTML = (findings, opts) => {
    opts = opts || {};
    const list = (findings || []).filter(f => !f.acked).sort((a, b) => ((a.module === 'advisor') ? 0 : 1) - ((b.module === 'advisor') ? 0 : 1) || (SEV[a.severity] ?? 5) - (SEV[b.severity] ?? 5));
    const max = opts.max || 6;
    return list.slice(0, max).map(f => f.module === 'advisor' || fixOf(f) ? oneAdvice(f, opts)
      : `<div class="advice ${f.severity === 'high' || f.severity === 'critical' ? 'bad' : f.severity === 'medium' ? 'warn' : ''}"><div class="advice-head">${FS.sevPill(f.severity)} <b>${esc(f.title)}</b> <span class="muted small">${esc(f.module)} · since ${FS.ago(f.ts)}</span></div><div class="advice-effect small">${esc(f.detail || '')}</div></div>`).join('')
      + (list.length > max ? `<div class="small muted" style="margin-top:6px">${list.length - max} more · <a href="#findings">all findings</a></div>` : '');
  };

  // Wires the one-click fixes; onDone re-renders.
  FS.adviceWire = (el, onDone) => {
    FS.$$('[data-adv-switch]', el).forEach(b => b.onclick = async () => {
      const t = JSON.parse(b.dataset.advSwitch);
      if (!await FS.confirm(`Set ${t.key} to ${JSON.stringify(t.value)} on Pi-hole ${t.server}?\n\nThe Pi-hole restarts its DNS service so devices that already asked get the new answer (a second or two without answers).`)) return;
      b.disabled = true;
      const r = await FS.post('/api/pihole/config', { server: t.server, key: t.key, value: t.value });
      const res = ((r && r.results) || [])[0] || {};
      FS.toast(r.error || res.error || 'Changed on the Pi-hole. The device retries on its own; toggling its Wi-Fi makes it immediate.', !!(r.error || res.error));
      b.disabled = false; if (!r.error && !res.error && onDone) onDone();
    });
    FS.$$('[data-adv-allow]', el).forEach(b => b.onclick = async () => {
      const t = JSON.parse(b.dataset.advAllow);
      if (!await FS.confirm(`Add ${t.domains.join(', ')} to the allow list on Pi-hole ${t.server}?`)) return;
      b.disabled = true;
      const r = await FS.post('/api/pihole/domains', { server: t.server, action: 'add', type: 'allow', kind: 'exact', domains: t.domains, comment: 'Allowed from a FlowSight device advisory' });
      const res = ((r && r.results) || [])[0] || {};
      FS.toast(r.error || res.error || 'Allowed on the Pi-hole', !!(r.error || res.error));
      b.disabled = false; if (!r.error && !res.error && onDone) onDone();
    });
  };

  // Devices with open findings, worst first: for the Overview.
  FS.devicesAttentionHTML = (findings) => {
    const groups = new Map();
    (findings || []).filter(f => !f.acked).forEach(f => {
      const d = FS.findingDevice(f); if (!d) return;
      if (!groups.has(d.key)) groups.set(d.key, { dev: d, list: [] });
      const g = groups.get(d.key); g.list.push(f); if (!g.dev.name && d.name) g.dev.name = d.name;
    });
    const rows = [...groups.values()].map(g => { g.list.sort((a, b) => (SEV[a.severity] ?? 5) - (SEV[b.severity] ?? 5)); g.worst = g.list[0].severity; return g; })
      .sort((a, b) => (SEV[a.worst] ?? 5) - (SEV[b.worst] ?? 5) || b.list.length - a.list.length).slice(0, 8);
    if (!rows.length) return FS.empty('No device has an open finding');
    return rows.map(g => `<div class="attn-row">${FS.sevPill(g.worst)} <span>${FS.hostLink(g.dev.ip, g.dev.name)}</span><div class="small">${[...new Set(g.list.map(f => f.title))].slice(0, 3).map(esc).join(' · ')}${g.list.length > 3 ? ` <span class="muted">+${g.list.length - 3}</span>` : ''}</div></div>`).join('');
  };

  // --------------------------------------------------------------- DNS tabs
  // The Pi-hole tab of Settings › dns exists only while a Pi-hole v6 server is connected.
  let phAt = 0, phConnected = 0;
  FS.piholeConnected = async () => {
    if (Date.now() - phAt < 30000) return phConnected;
    const s = await FS.get('/api/pihole/status');
    phConnected = (s && !s.error && s.connected) || 0; phAt = Date.now();
    return phConnected;
  };
  // DNS configuration lives on Settings › dns, in tabs: the resolver's own
  // settings, device names, and (while one is connected) the Pi-hole.
  // Monitor › DNS only watches.
  FS.dnsTabs = async (active) => {
    const ph = await FS.piholeConnected();
    const t = (id, label) => `<a href="#modules/dns${id === 'resolver' ? '' : '?tab=' + id}" class="${active === id ? 'on' : ''}">${label}</a>`;
    return `<div class="tabs dns-tabs">${t('resolver', 'Resolver')}${t('names', 'Device names')}${ph ? t('pihole', 'Pi-hole') + t('phblock', 'Pi-hole blocking') : ''}</div>`;
  };
  FS.dnsSettings = async (el, ctx) => {
    const tab = (ctx.params && ctx.params.tab) || 'resolver';
    const left = FS.$('.two > div', el) || el;
    const strip = await FS.dnsTabs(tab);
    if (tab === 'resolver') { left.insertAdjacentHTML('afterbegin', strip); return; }
    left.innerHTML = strip + '<div class="dns-set"></div>';
    const host = FS.$('.dns-set', left);
    if (tab === 'pihole') await FS.renderPihole(host);
    else if (tab === 'phblock' && FS.renderPiholeBlocking) await FS.renderPiholeBlocking(host);
    else if (FS.renderLocalNames) await FS.renderLocalNames(host);
  };


  // --------------------------------------------------------------- Pi-hole
  const fmtVal = (v) => Array.isArray(v) ? (v.length ? v.map(x => `<div class="mono small">${esc(x)}</div>`).join('') : '<span class="muted small">none</span>')
    : typeof v === 'boolean' ? FS.pill(v ? 'on' : 'off', v ? 'ok' : '') : `<span class="mono">${esc(v)}</span>`;
  const allowedList = (a) => Array.isArray(a) ? a.filter(x => x && typeof x === 'object' && 'item' in x) : [];

  function editor(s, servers, anyWritable) {
    const vals = s.values || {}; const urls = Object.keys(vals); const cur = vals[urls[0]];
    const t = String(s.type || '').toLowerCase();
    if (s.read_only) return `<div class="small muted">${esc(s.read_only)}</div>`;
    if (!anyWritable) return '';
    let input;
    const choices = allowedList(s.allowed);
    if (t === 'boolean') input = `<select name="value"><option value="true" ${cur === true ? 'selected' : ''}>on</option><option value="false" ${cur === false ? 'selected' : ''}>off</option></select>`;
    else if (choices.length) input = `<select name="value">${choices.map(c => `<option value="${esc(c.item)}" ${String(c.item) === String(cur) ? 'selected' : ''}>${esc(c.item)}</option>`).join('')}</select>`;
    else if (t.includes('array')) input = `<textarea name="value" rows="${Math.min(8, Math.max(2, (cur || []).length + 1))}" placeholder="one per line">${esc((cur || []).join('\n'))}</textarea>`;
    else input = `<input name="value" value="${esc(cur ?? '')}" ${t.includes('integer') ? 'inputmode="numeric"' : ''}>`;
    const target = servers.length > 1 ? `<select name="server"><option value="all">all Pi-holes</option>${servers.map(x => `<option value="${esc(x.url)}">${esc(x.host)}</option>`).join('')}</select>` : `<input type="hidden" name="server" value="all">`;
    return `<form class="ph-set" data-key="${esc(s.key)}" data-caution="${esc(s.caution || '')}" data-restarts="${s.restarts_dns ? 1 : 0}">${input}${target}<button class="btn small">Apply</button></form>`;
  }

  // Pi-hole configuration lives on Settings › dns (tab Pi-hole); the old
  // route sends people there.
  FS.registerPage('pihole', { title: 'Pi-hole', refresh: 0, async render() { FS.go('#modules/dns?tab=pihole'); } });

  FS.renderPihole = async (el) => {
    {
      const tabs = '';
      const [cfg, doms, adv] = await Promise.all([FS.get('/api/pihole/config'), FS.get('/api/pihole/domains'), FS.get('/api/system/findings?module=advisor')]);
      if (!await FS.piholeConnected()) { el.innerHTML = FS.empty('No Pi-hole is connected. Add one under Settings › pihole: its URL and an app password.') + `<div class="actions" style="margin-top:10px"><a class="btn" href="#modules/pihole">Pi-hole connection</a></div>`; return; }
      if (cfg.error) { el.innerHTML = FS.err(cfg.error); return; }
      const servers = cfg.servers || []; const writable = servers.filter(s => s.writable);
      const anyWritable = writable.length > 0;
      const srvCard = FS.table(servers, [
        { t: 'Pi-hole', f: s => `<b>${esc(s.host)}</b><div class="muted small mono">${esc(s.url)}</div>` },
        { t: 'Version', f: s => esc(s.version || '') },
        { t: 'Blocking', f: s => s.error ? FS.pill('unreachable', 'bad') : s.blocking === 'enabled' ? FS.pill('on', 'ok') : FS.pill(s.blocking_timer ? `paused ${Math.ceil(s.blocking_timer / 60)} min` : String(s.blocking || 'off'), 'warn') },
        { t: 'From FlowSight', f: s => s.error ? `<span class="small">${esc(s.error)}</span>` : s.writable ? FS.pill('can change settings', 'ok') : `${FS.pill('read only', 'warn')}<div class="small muted" style="max-width:420px">${esc(s.read_only_reason || '')}</div>` }]);
      const pause = `<div class="actions"><span class="muted small">Blocking on every Pi-hole:</span>${[5, 15, 60].map(m => `<button class="btn small" data-pause="${m}">Pause ${m < 60 ? m + ' min' : '1 hour'}</button>`).join('')}<button class="btn small" data-resume>Resume now</button></div><div class="help small">Pausing lets every name through for a while and switches blocking back on by itself. Use it to test whether a problem is caused by blocking.</div>`;
      const warn = (cfg.warnings || []).map(w => `<div class="advice warn"><div class="advice-effect">${esc(w)}</div></div>`).join('');
      const advOpen = (adv.findings || []).filter(f => (A(f).why || {}).resolver && String(A(f).why.resolver).startsWith('pihole:'));
      const sections = (cfg.sections || []).map(sec => FS.card(sec.title, `<div class="help" style="margin-bottom:10px">${esc(sec.intro)}</div>` + (sec.settings || []).map(s => {
        const vals = s.values || {};
        const valCells = Object.keys(vals).map(u => `<div class="ph-val">${servers.length > 1 ? `<span class="muted small">${esc((servers.find(x => x.url === u) || {}).host || u)}</span> ` : ''}${fmtVal(vals[u])}</div>`).join('');
        const rec = s.recommend !== undefined && s.recommend !== null ? (Object.values(vals).every(v => JSON.stringify(v) === JSON.stringify(s.recommend) || String(v) === String(s.recommend)) ? FS.pill('as recommended', 'ok') : FS.pill('recommended: ' + (typeof s.recommend === 'boolean' ? (s.recommend ? 'on' : 'off') : s.recommend), 'warn')) : '';
        return `<div class="ph-row"><div class="ph-main"><div><b>${esc(s.label)}</b> <span class="muted small mono">${esc(s.key)}</span> ${s.differs ? FS.pill('differs between Pi-holes', 'warn') : ''} ${rec} ${s.restarts_dns ? `<span class="muted small" title="Pi-hole restarts its DNS service to apply this: a second or two without answers">restarts DNS</span>` : ''}</div>
          <div class="small">${esc(s.guide || '')}</div>${s.why ? `<div class="small muted">${esc(s.why)}</div>` : ''}${s.pihole_description ? `<details class="small muted"><summary>Pi-hole's description</summary><div style="white-space:pre-wrap">${esc(s.pihole_description)}</div></details>` : ''}</div>
          <div class="ph-side"><div>${valCells}</div>${editor(s, servers, anyWritable)}</div></div>`;
      }).join(''))).join('<div style="height:14px"></div>');
      const domRows = (doms.domains || []);

      el.innerHTML = tabs + warn
        + (advOpen.length ? FS.card('Device advisories caused by a Pi-hole', FS.adviceHTML(advOpen, { max: 4 })) + '<div style="height:14px"></div>' : '')
        + `<div class="grid cols-2">${FS.card('Connected Pi-holes', srvCard + pause)}${FS.card('Blocking', `<div class="small">Blocklists, allow and deny entries, groups, clients, FlowSight categories as Pi-hole lists, gravity, and keeping several Pi-holes the same are on <a href="#modules/dns?tab=phblock">Settings › dns › Pi-hole blocking</a>. There are ${FS.num(domRows.length)} allow and deny entries now.</div>`)}</div>
        <div style="height:14px"></div>${sections}
        <div class="help" style="margin-top:12px">Only the settings above can be changed from FlowSight, and each change is recorded under <a href="#system">Status</a> › Changes with who made it. Everything else (DHCP, passwords, the web server) stays on the Pi-hole's own pages. <a href="${DOCS}pihole.md" target="_blank" rel="noopener">How FlowSight works with Pi-hole</a>.</div>`;
      FS.adviceWire(el, () => FS.render());
      FS.$$('[data-pause]', el).forEach(b => b.onclick = async () => { const r = await FS.post('/api/pihole/blocking', { blocking: false, minutes: Number(b.dataset.pause) }); FS.toast(r.error || `Blocking paused for ${b.dataset.pause} minutes`, !!r.error); FS.render(); });
      const res = FS.$('[data-resume]', el); if (res) res.onclick = async () => { const r = await FS.post('/api/pihole/blocking', { blocking: true }); FS.toast(r.error || 'Blocking on', !!r.error); FS.render(); };
      FS.$$('form.ph-set', el).forEach(f => f.onsubmit = async (e) => {
        e.preventDefault();
        const key = f.dataset.key; const fd = new FormData(f);
        let value = fd.get('value'); if (value === 'true') value = true; else if (value === 'false') value = false;
        const msg = [`Change ${key} on ${fd.get('server') === 'all' ? 'every connected Pi-hole' : fd.get('server')}?`, f.dataset.caution, f.dataset.restarts === '1' ? 'The Pi-hole restarts its DNS service to apply it, so devices that already asked get the new answer too (a second or two without answers).' : ''].filter(Boolean).join('\n\n');
        if (!await FS.confirm(msg)) return;
        const r = await FS.post('/api/pihole/config', { key, value, server: fd.get('server') });
        const bad = ((r && r.results) || []).filter(x => x.error);
        const notes = ((r && r.results) || []).filter(x => x.note).map(x => x.host + ': ' + x.note);
        FS.toast(r.error || (bad.length ? bad.map(x => x.host + ': ' + x.error).join('; ') : notes.length ? notes.join('; ') : 'Applied'), !!(r.error || bad.length || notes.length));
        if (!r.error) FS.render();
      });
    }
  };
})();

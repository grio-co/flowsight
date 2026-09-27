/* FlowSight pages: one application, one application category, the unknown, and application control. */
(function () {
  'use strict';
  const { esc, num, bytes, ago, when, pill, card, kpi, table, bars, chart, get, post, hostLink } = window.FS;
  const FS = window.FS;
  const DOC = 'https://github.com/grio-co/flowsight/blob/main/docs/howto/categories-and-apps.md';
  const breedTone = { Safe: 'ok', Acceptable: 'ok', Fun: 'info', Unsafe: 'warn', Dangerous: 'bad', Potentially_Dangerous: 'warn' };
  const breedPill = (b) => b ? pill(b.replace('_', ' '), breedTone[b] || '') : '';
  const catLink = (c) => c ? `<a href="#appcat/${encodeURIComponent(c)}" title="Everything in this category">${esc(c)}</a>` : '';
  const appLink = (a) => `<a href="#app/${encodeURIComponent(a)}">${esc(a)}</a>`;

  // The write-up: what it is for, the risk, what goes wrong, what to look for.
  const noteCard = (n, who) => {
    n = n || {};
    const list = (arr) => (arr || []).length ? `<ul class="small" style="margin:4px 0 0 18px">${arr.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : '<span class="muted small">nothing specific</span>';
    return `<div class="note-grid">
      <div><div class="hg">What it is for</div><div class="small">${esc(n.purpose || '')}</div></div>
      <div><div class="hg">Risk</div><div class="small">${esc(n.risk || '')}</div></div>
      <div><div class="hg">Common issues</div>${list(n.issues)}</div>
      <div><div class="hg">What to look for</div>${list(n.look_for)}</div>
    </div><div class="muted small" style="margin-top:8px">${n.source === 'curated' ? 'Written for this application.' : 'No write-up for this application yet; this is the note for its category.'} nDPI identifies ${esc(who)} from the flow's own packets; <a href="${DOC}" target="_blank" rel="noopener">how applications and categories are identified</a>.</div>`;
  };
  const policiesCard = (pols) => table(pols || [], [
    { t: 'Policy', f: p => `<a href="#policies?edit=${encodeURIComponent(p.name)}"><b>${esc(p.name)}</b></a>` },
    { t: 'State', f: p => p.enabled ? pill('enabled', 'ok') : pill('disabled', '') },
    { t: 'Action', f: p => p.allowed ? pill('allowed', 'ok') : pill(p.action || 'block', 'bad') },
    { t: 'By', f: p => p.allowed ? 'allow list' : (p.by === 'app_category' ? 'its category' : 'the application') },
    { t: 'Members', f: p => num(p.members || 0), num: true },
    { t: 'Schedule', f: p => esc(p.schedule || 'always') }], { empty: 'No policy names it. Application control does nothing to it.' });

  // ------------------------------------------------------------- one application
  FS.registerPage('app', {
    title: 'Application', refresh: 60,
    async render(el, ctx) {
      const name = ctx.arg; if (!name) { el.innerHTML = FS.err('no application given'); return; }
      const d = await get(`/api/visibility/app?name=${encodeURIComponent(name)}&${FS.since()}`);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const t = d.totals || {}, vis = d.visibility || {};
      if (FS.setTitle) FS.setTitle(name);
      const visRow = Object.entries(vis).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${pill(k, k === 'inspected' ? 'ok' : (k === 'opaque' || k === 'ech') ? 'warn' : '')} ${num(v)}`).join(' ');
      el.innerHTML = `<div class="grid cols-4">
        ${card('Identity', `<dl class="kv"><dt>Application</dt><dd><b>${esc(name)}</b></dd><dt>Category</dt><dd>${catLink(d.category) || '<span class="muted">none</span>'}</dd><dt>Breed</dt><dd>${breedPill(d.breed) || '<span class="muted">unrated</span>'}</dd><dt>Seen</dt><dd>${t.first_seen ? ago(t.first_seen) + ' to ' + ago(t.last_seen) : 'not in this window'}</dd></dl>`)}
        ${kpi('Sessions', num(t.flows || 0), `${num(t.hosts || 0)} device${t.hosts === 1 ? '' : 's'} · ${num(t.blocked || 0)} blocked`, t.blocked ? 'warn' : '')}
        ${kpi('Traffic', bytes((t.bytes_in || 0) + (t.bytes_out || 0)), `${bytes(t.bytes_in || 0)} down · ${bytes(t.bytes_out || 0)} up`)}
        ${card('Actions', `<div class="actions"><button class="btn" id="app-block">Block for…</button><a class="btn" href="#flows?app=${encodeURIComponent(name)}">Sessions</a>${d.category ? `<a class="btn" href="#appcat/${encodeURIComponent(d.category)}">Category</a>` : ''}</div><div class="help" style="margin-top:6px">Block opens a policy denying this application for the devices you pick; application control cuts matching flows off at the firewall.</div>`)}
      </div>
      <div style="margin-top:14px">${card('About ' + esc(name), noteCard(d.note, 'it'))}</div>
      <div style="margin-top:14px">${card('Activity', chart([{ name: 'download', points: (d.timeline || []).map(p => [p.t, p.bytes_in]) }, { name: 'upload', points: (d.timeline || []).map(p => [p.t, p.bytes_out]) }], bytes), `${visRow || 'no sessions in this window'}`)}</div>
      <div class="grid cols-3" style="margin-top:14px">
        ${card('Who uses it', bars((d.devices || []).map(x => ({ label: x.name || x.ip, sub: `${x.name ? x.ip + ' · ' : ''}${bytes((x.bytes_in || 0) + (x.bytes_out || 0))}`, value: x.flows || 0, href: '#host/' + encodeURIComponent(x.ip) })), num), 'by sessions')}
        ${card('Names it talks to', bars((d.domains || []).map(x => ({ label: x.domain, sub: bytes((x.bytes_in || 0) + (x.bytes_out || 0)), value: x.flows || 0, href: '#flows?domain=' + encodeURIComponent(x.domain) })), num), 'by sessions')}
        ${card('Where it goes', table(d.destinations || [], [
          { t: 'Far end', f: x => `<b>${esc(x.name || x.ip)}</b>${x.name ? `<div class="muted small mono">${esc(x.ip)}</div>` : ''}` },
          { t: 'Port', f: x => `${x.port}/${esc(x.proto || '')}` },
          { t: 'Country', f: x => x.country ? FS.cc(x.country, { cls: 'pill' }) : '' },
          { t: 'AS', f: x => x.asn ? 'AS' + esc(x.asn) : '' },
          { t: 'Sessions', f: x => num(x.flows), num: true },
          { t: 'Bytes', f: x => bytes(x.bytes), num: true },
          { t: '', f: x => `<a href="#paths?dst=${encodeURIComponent(x.ip)}" title="The route to it on the map">map</a>` }]))}
      </div>
      <div class="grid cols-2" style="margin-top:14px">
        ${card('Ports and countries', `<div class="two"><div>${bars((d.ports || []).map(x => ({ label: `${x.port}/${x.proto}`, value: x.flows })), num)}</div><div>${bars((d.countries || []).map(x => ({ label: FS.countryName(x.country) + ' (' + x.country + ')', value: x.flows })), num)}</div></div>`)}
        ${card('What policy says', policiesCard(d.policies))}
      </div>`;
      FS.$('#app-block', el).onclick = () => FS.quickPolicy({ apps: [name] });
    }
  });

  // ------------------------------------------------------------- one category
  FS.registerPage('appcat', {
    title: 'Application category', refresh: 60,
    async render(el, ctx) {
      const name = ctx.arg; if (!name) { el.innerHTML = FS.err('no category given'); return; }
      const d = await get(`/api/visibility/app-category?name=${encodeURIComponent(name)}&${FS.since()}`);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const t = d.totals || {};
      if (FS.setTitle) FS.setTitle(name + ' \u00b7 category');
      el.innerHTML = `<div class="grid cols-4">
        ${card('Category', `<dl class="kv"><dt>Name</dt><dd><b>${esc(name)}</b></dd><dt>Defined by</dt><dd>nDPI</dd><dt>Applications seen</dt><dd>${num((d.apps || []).length)}</dd></dl>`)}
        ${kpi('Sessions', num(t.flows || 0), `${num(t.hosts || 0)} device${t.hosts === 1 ? '' : 's'}`)}
        ${kpi('Traffic', bytes((t.bytes_in || 0) + (t.bytes_out || 0)), `${bytes(t.bytes_in || 0)} down · ${bytes(t.bytes_out || 0)} up`)}
        ${card('Actions', `<div class="actions"><button class="btn" id="cat-block">Block the category for…</button><a class="btn" href="#apps">Applications</a></div>`)}
      </div>
      <div style="margin-top:14px">${card('About this category', noteCard(d.note, 'the category'))}</div>
      <div class="grid cols-2" style="margin-top:14px">
        ${card('Applications in it', table(d.apps || [], [
          { t: 'Application', f: x => appLink(x.app), sort: 'app' },
          { t: 'Breed', f: x => breedPill(x.breed), sort: 'breed' },
          { t: 'Sessions', f: x => num(x.flows), num: true, sort: 'flows' },
          { t: 'Devices', f: x => num(x.hosts), num: true, sort: 'hosts' },
          { t: 'Down', f: x => bytes(x.bytes_in), num: true, sort: 'bytes_in' },
          { t: 'Up', f: x => bytes(x.bytes_out), num: true, sort: 'bytes_out' },
          { t: 'Blocked', f: x => x.blocked ? `<span class="sev-high">${num(x.blocked)}</span>` : '0', num: true, sort: 'blocked' },
          { t: 'Last seen', f: x => x.last_seen ? ago(x.last_seen) : '', sort: 'last_seen' }]))}
        <div>${card('Who uses it', bars((d.devices || []).map(x => ({ label: x.name || x.ip, sub: bytes((x.bytes_in || 0) + (x.bytes_out || 0)), value: x.flows || 0, href: '#host/' + encodeURIComponent(x.ip) })), num), 'by sessions')}
        <div style="margin-top:14px">${card('What policy says', policiesCard(d.policies))}</div></div>
      </div>`;
      FS.$('#cat-block', el).onclick = () => FS.quickPolicy({ app_categories: [name] });
    }
  });

  // ------------------------------------------------------------- the unknown
  FS.registerPage('unknown', {
    title: 'Unknown applications', refresh: 60,
    async render(el) {
      const d = await get(`/api/visibility/unknown?${FS.since()}&limit=200`);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const rows = d.signatures || [];
      const named = rows.filter(r => r.name).length;
      el.innerHTML = `<div class="grid cols-4">
        ${kpi('Unnamed sessions', num(d.total_flows || 0), `in the last ${FS.state.hours} h`)}
        ${kpi('Signatures', num(rows.length), `${num(named)} named by you`)}
        ${card('What this is', `<div class="small">${esc(d.note || '')}</div>`)}
        ${card('Where names come from', `<div class="small">The name a device asked for (DNS or TLS server name), the network that announces the far end, and the port. <a href="${DOC}" target="_blank" rel="noopener">How applications are identified</a>.</div>`)}
      </div>
      <div style="margin-top:14px">${card('Catalogue', table(rows, [
        { t: 'Signature', f: r => `<b>${esc(r.name || r.label)}</b>${r.name ? `<div class="muted small">${esc(r.label)}</div>` : ''}<div class="muted small mono">${esc(r.signature)}</div>`, sort: 'signature' },
        { t: 'Sample far end', f: r => `<span class="mono small">${esc(r.sample_ip)}</span>${r.asn ? `<div class="muted small">AS${esc(r.asn)}</div>` : ''} <a href="#paths?dst=${encodeURIComponent(r.sample_ip)}" class="small">map</a>` },
        { t: 'Devices', f: r => `${num(r.hosts)}<div class="small">${(r.devices || []).map(x => hostLink(x.ip, x.name)).join(', ')}</div>`, num: true, sort: 'hosts' },
        { t: 'Sessions', f: r => num(r.flows), num: true, sort: 'flows' },
        { t: 'Down / up', f: r => `${bytes(r.bytes_in)} / ${bytes(r.bytes_out)}`, num: true, sort: 'bytes_out' },
        { t: 'Seen', f: r => `${ago(r.first_seen)} to ${ago(r.last_seen)}`, sort: 'last_seen' },
        { t: '', f: r => `<button class="btn small" data-name-sig="${esc(r.signature)}" data-cur="${esc(r.name || '')}">${r.name ? 'Rename' : 'Name'}</button> <a class="btn small" href="#flows?dst=${encodeURIComponent(r.sample_ip)}">sessions</a>` }],
        { empty: 'Nothing unnamed in this window.' }), 'busiest first; a name you give a signature is remembered and shown wherever the signature appears')}</div>`;
      FS.$$('[data-name-sig]', el).forEach(b => b.onclick = () => {
        const sig = b.dataset.nameSig;
        FS.modal(`<h2>Name this traffic</h2><p class="small muted mono">${esc(sig)}</p><form class="f"><label>Name</label><input type="text" name="name" value="${esc(b.dataset.cur)}" maxlength="80" placeholder="Echo keepalive"><div class="actions"><button class="btn primary">Save</button><button type="button" class="btn" data-close>Cancel</button>${b.dataset.cur ? '<button type="button" class="btn danger" id="un-forget">Forget</button>' : ''}</div></form>`, (box) => {
          FS.$('form', box).onsubmit = async (e) => { e.preventDefault(); const r = await post('/api/visibility/unknown/name', { signature: sig, name: e.target.name.value.trim() }); FS.toast(r.error || 'Named', !!r.error); if (!r.error) { FS.closeModal(); FS.render(); } };
          const f = FS.$('#un-forget', box); if (f) f.onclick = async () => { const r = await post('/api/visibility/unknown/name', { signature: sig, name: '' }); FS.toast(r.error || 'Forgotten', !!r.error); FS.closeModal(); FS.render(); };
        });
      });
    }
  });

  // ------------------------------------------------------------- application control (Protect)
  FS.registerPage('appcontrol', {
    title: 'Applications (L7)', refresh: 30,
    async render(el) {
      const [st, bl, pol, apps] = await Promise.all([get('/api/appcontrol/status'), get(`/api/appcontrol/blocked?${FS.since()}&limit=200`), get('/api/policy'), get(`/api/visibility/apps?${FS.since()}`)]);
      if (st.error && !st.rules) { el.innerHTML = FS.err(st.error); return; }
      const doc = (pol && pol.document) || {};
      const policies = (doc.policies || []).filter(p => (p.deny && ((p.deny.apps || []).length || (p.deny.app_categories || []).length)) || (p.allow && (p.allow.apps || []).length));
      const rules = st.rules || [];
      const appRows = apps.apps || [];
      el.innerHTML = `<div class="grid cols-4">
        ${card('State', `<div>${st.enforcing ? pill('enforcing', 'ok') : pill('recording only', 'warn')}</div><div class="small muted" style="margin-top:6px">${st.enforcing ? 'Denied applications are cut off at the firewall.' : 'Policy enforcement is off or pf is unavailable: denials are recorded, not enforced.'}</div>`)}
        ${kpi('Policies naming applications', num(policies.length), `${num(rules.length)} active rule set${rules.length === 1 ? '' : 's'}`)}
        ${kpi('Addresses held', num(rules.reduce((a, r) => a + (r.blocked_addresses || 0), 0)), 'learned from denied flows, expiring by the table TTL')}
        ${kpi('Blocks', num((bl.blocks || []).length), `in the last ${FS.state.hours} h`, (bl.blocks || []).length ? 'warn' : '')}
      </div>
      <div class="help" style="margin-top:10px">This is where application control is configured: which applications and nDPI categories are denied, for whom, and when. <a href="#apps">Monitor › Applications</a> only watches. A policy's <em>Apps</em> and <em>App categories</em> deny by identity, on the flow itself, whatever name or address it uses; <a href="${DOC}" target="_blank" rel="noopener">how applications are identified</a>.</div>
      <div style="margin-top:14px">${card('What is denied, and for whom', `<div class="actions" style="margin-bottom:8px"><button class="btn primary" id="ac-new">Block an application…</button><a class="btn" href="#policies">All policies</a></div>` + table(policies, [
        { t: 'Policy', f: p => `<a href="#policies?edit=${encodeURIComponent(p.name)}"><b>${esc(p.name)}</b></a>${p.description ? `<div class="muted small">${esc(p.description)}</div>` : ''}` },
        { t: 'State', f: p => p.enabled ? pill('enabled', 'ok') : pill('disabled', '') },
        { t: 'Denies', f: p => `${(p.deny.apps || []).map(a => appLink(a)).join(', ')}${(p.deny.apps || []).length && (p.deny.app_categories || []).length ? '<br>' : ''}${(p.deny.app_categories || []).map(c => `category ${catLink(c)}`).join(', ')}` },
        { t: 'Allows', f: p => (p.allow && p.allow.apps || []).map(a => appLink(a)).join(', ') || '<span class="muted">—</span>' },
        { t: 'For', f: p => (p.match && (p.match.members || p.match.hosts) || p.members || []).slice(0, 6).map(x => esc(x)).join(', ') || '<span class="muted">everyone</span>' },
        { t: 'When', f: p => esc(p.schedule || 'always') }],
        { empty: 'No policy denies an application yet. Block an application… starts one.' }))}</div>
      <div class="grid cols-2" style="margin-top:14px">
        ${card('Active rule sets', table(rules, [
          { t: 'Policy', f: r => esc(r.policy) }, { t: 'Table', f: r => `<span class="mono small">${esc(r.table)}</span>` },
          { t: 'Applications', f: r => (r.apps || []).map(a => appLink(a)).join(', ') },
          { t: 'Addresses held', f: r => num(r.blocked_addresses || 0), num: true }], { empty: 'Nothing compiled: no enabled policy names an application.' }))}
        ${card('Recent blocks', table((bl.blocks || []).slice(0, 50), [
          { t: 'When', f: b => when(b.ts), sort: 'ts' },
          { t: 'Device', f: b => hostLink(b.src_ip || b.local, b.src_name) },
          { t: 'Application', f: b => appLink(b.app || '') },
          { t: 'Far end', f: b => b.dst_ip ? `<span class="mono small">${esc(b.dst_ip)}</span>` : '' },
          { t: 'Policy', f: b => esc(b.policy || '') }], { empty: 'No blocks in this window.' }))}
      </div>
      <div style="margin-top:14px">${card('Applications seen, busiest first', table(appRows.slice(0, 60), [
        { t: 'Application', f: r => appLink(r.app), sort: 'app' }, { t: 'Category', f: r => catLink(r.category), sort: 'category' }, { t: 'Breed', f: r => breedPill(r.breed), sort: 'breed' },
        { t: 'Sessions', f: r => num(r.flows), num: true, sort: 'flows' }, { t: 'Devices', f: r => num(r.hosts || 0), num: true, sort: 'hosts' },
        { t: 'Blocked', f: r => r.blocked ? `<span class="sev-high">${num(r.blocked)}</span>` : '0', num: true, sort: 'blocked' },
        { t: '', f: r => `<button class="btn small" data-block-app="${esc(r.app)}">Block for…</button>` }]), 'from Monitor › Applications; the button opens a policy for that application')}</div>`;
      FS.$('#ac-new', el).onclick = () => FS.quickPolicy({ apps: [] });
      FS.$$('[data-block-app]', el).forEach(b => b.onclick = () => FS.quickPolicy({ apps: [b.dataset.blockApp] }));
    }
  });
})();

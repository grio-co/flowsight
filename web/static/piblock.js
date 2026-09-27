// Settings › dns › Pi-hole blocking: what the Pi-holes block, and for whom.
//
// Pi-hole blocks from lists (blocklist and allowlist subscriptions by URL)
// and from single entries (allow or deny, exact or regex). Each list, entry
// and client belongs to groups, and a client is filtered by its groups'
// lists and entries. Every change here goes to the Pi-hole chosen at the top,
// or to all of them; groups are named, and a group a Pi-hole lacks is made.
(function () {
  const esc = (s) => FS.esc(s);
  const DOC = 'https://github.com/grio-co/flowsight/blob/main/docs/howto/pihole.md#blocking';
  const KEY = 'fs.phblock.target';
  let target = 'all';
  try { target = localStorage.getItem(KEY) || 'all'; } catch (e) { /* private window */ }

  const hostOf = (servers, u) => ((servers || []).find(s => s.url === u) || {}).host || u;
  const where = (row, servers) => {
    const on = Object.keys(row.servers || {});
    if (servers.length < 2) return '';
    const pills = [];
    if (row.missing > 0) pills.push(FS.pill(`only on ${on.map(u => hostOf(servers, u)).join(', ')}`, 'warn'));
    if (row.differs) pills.push(FS.pill('differs between Pi-holes', 'warn'));
    return pills.join(' ');
  };
  const groupPills = (gs) => (gs || []).length ? gs.map(g => FS.pill(g, g === 'Default' ? '' : 'info')).join(' ') : FS.pill('Default', '');

  async function send(path, body, what) {
    body = Object.assign({ server: target }, body);
    const r = await FS.post(path, body);
    const bad = ((r && r.results) || []).filter(x => x.error).map(x => `${x.host}: ${x.error}`);
    const grav = (r && r.gravity && r.gravity.length) ? ` Gravity is rebuilding on ${r.gravity.join(', ')}.` : '';
    FS.toast(r.error || (bad.length ? bad.join('; ') : (what || 'Done') + '.' + grav), !!(r.error || bad.length));
    return r;
  }

  // Choosing groups: every group any Pi-hole has, plus a new one.
  function pickGroups(all, current, title) {
    return new Promise(res => {
      FS.modal(`<h2>${esc(title)}</h2><form class="f pg-form"><div class="pg-list">${all.map(g => `<label><input type="checkbox" name="g" value="${esc(g)}" ${(current || []).includes(g) || (!(current || []).length && g === 'Default') ? 'checked' : ''}> ${esc(g)}</label>`).join('')}</div>
        <label>New group<input name="new" placeholder="Kids" autocomplete="off"></label>
        <div class="help small">A client is filtered by the lists and entries of the groups it is in. A group a Pi-hole does not have yet is created on it.</div>
        <div class="actions"><button class="btn primary">Use these groups</button><button type="button" class="btn" data-x>Cancel</button></div></form>`, (b) => {
        const f = FS.$('form', b);
        FS.$('[data-x]', b).onclick = () => { FS.closeModal(); res(null); };
        f.onsubmit = (e) => { e.preventDefault(); const gs = FS.$$('input[name=g]:checked', f).map(x => x.value); const n = f.new.value.trim(); if (n && !gs.includes(n)) gs.push(n); FS.closeModal(); res(gs); };
      });
    });
  }

  FS.renderPiholeBlocking = async (el) => {
    const d = await FS.get('/api/pihole/blocking');
    if (d.error) { el.innerHTML = FS.err(d.error); return; }
    const servers = d.servers || [];
    if (target !== 'all' && !servers.some(s => s.url === target)) target = 'all';
    const groupNames = Array.from(new Set((d.groups || []).map(g => g.name))).sort((a, b) => a === 'Default' ? -1 : b === 'Default' ? 1 : a.localeCompare(b));
    const running = servers.some(s => s.gravity && s.gravity.running);

    const targetSel = `<label class="pb-target">Apply changes to <select id="pb-target"><option value="all" ${target === 'all' ? 'selected' : ''}>all ${servers.length} Pi-holes</option>${servers.map(s => `<option value="${esc(s.url)}" ${target === s.url ? 'selected' : ''}>${esc(s.host)} only</option>`).join('')}</select></label>`;
    const srvTable = FS.table(servers, [
      { t: 'Pi-hole', f: s => `<b>${esc(s.host)}</b>${s.error ? `<div class="small sev-high">${esc(s.error)}</div>` : ''}` },
      { t: 'Changes', f: s => s.writable ? FS.pill('allowed', 'ok') : FS.pill('read only', 'warn') },
      { t: 'Gravity', f: s => { const g = s.gravity; if (!g) return '<span class="muted small">not run from FlowSight</span>'; return (g.running ? FS.pill('rebuilding…', 'info') : g.ok ? FS.pill('rebuilt ' + FS.ago(g.finished), 'ok') : FS.pill('problems ' + FS.ago(g.finished), 'bad')) + ((g.tail || []).length ? `<details class="small"><summary>output</summary><pre class="code small">${esc(g.tail.join('\n'))}</pre></details>` : ''); } },
      { t: '', f: s => `<button class="btn small" data-grav="${esc(s.url)}" ${s.gravity && s.gravity.running ? 'disabled' : ''}>Rebuild now</button>` }]);
    const syncCard = servers.length > 1 ? FS.card('Keep the Pi-holes the same', `<form class="f pb-sync"><div class="row">Make <select name="to"><option value="all">every other Pi-hole</option>${servers.map(s => `<option value="${esc(s.url)}">${esc(s.host)}</option>`).join('')}</select> match <select name="from">${servers.map(s => `<option value="${esc(s.url)}">${esc(s.host)}</option>`).join('')}</select></div>
      <div class="row small">${['groups', 'lists', 'clients', 'domains'].map(p => `<label><input type="checkbox" name="part" value="${p}" checked> ${p}</label>`).join(' ')}</div>
      <label class="small"><input type="checkbox" name="extra"> also remove what they have beyond it</label>
      <div class="actions"><button class="btn">Sync now</button></div></form><div class="help small">Adds what is missing and corrects what differs. Removing extras is off unless ticked.</div>`) : '';

    const groupsCard = FS.card('Groups', FS.table(d.groups || [], [
      { t: 'Group', f: g => `<b>${esc(g.name)}</b>${g.default ? ' <span class="muted small">every client not in another group</span>' : ''}${g.comment ? `<div class="muted small">${esc(g.comment)}</div>` : ''}` },
      { t: 'On', f: g => `<label class="switch"><input type="checkbox" data-gon="${esc(g.name)}" ${g.enabled ? 'checked' : ''}> ${g.enabled ? 'on' : 'off'}</label>` },
      { t: '', f: g => where(g, servers) },
      { t: '', f: g => g.default ? '' : `<button class="btn small" data-gren="${esc(g.name)}">Rename</button> <button class="btn small" data-grm="${esc(g.name)}">Remove</button>` }])
      + `<form class="f pb-addgroup row"><input name="name" placeholder="New group, e.g. Kids" required><input name="comment" placeholder="Note (optional)"><button class="btn small primary">Add group</button></form>`, `${FS.num((d.groups || []).length)}`);

    const listsCard = FS.card('Blocklists and allowlists', FS.table(d.lists || [], [
      { t: 'List', f: l => `<span class="mono small" style="word-break:break-all">${esc(l.address)}</span>${l.category ? ` ${FS.pill('FlowSight category ' + l.category, 'info')}` : ''}${l.comment ? `<div class="muted small">${esc(l.comment)}</div>` : ''}` },
      { t: 'Type', f: l => FS.pill(l.type, l.type === 'allow' ? 'ok' : 'bad') },
      { t: 'On', f: l => `<input type="checkbox" data-lon='${esc(JSON.stringify({ a: l.address, t: l.type }))}' ${l.enabled ? 'checked' : ''}>` },
      { t: 'Groups', f: l => `${groupPills(l.groups)} <a href="#" class="small" data-lgrp='${esc(JSON.stringify({ a: l.address, t: l.type, g: l.groups }))}'>edit</a>` },
      { t: 'Domains', f: l => Object.entries(l.servers || {}).map(([u, v]) => `<div class="small">${servers.length > 1 ? esc(hostOf(servers, u)) + ': ' : ''}${FS.num(v.number || 0)}${v.date_updated ? ` <span class="muted">${FS.ago(v.date_updated)}</span>` : ''}</div>`).join('') },
      { t: '', f: l => where(l, servers) + (l.missing > 0 ? ` <button class="btn small" data-lall='${esc(JSON.stringify({ a: l.address, t: l.type, g: l.groups, c: l.comment || '' }))}'>Add to all</button>` : '') },
      { t: '', f: l => `<button class="btn small" data-lrm='${esc(JSON.stringify({ a: l.address, t: l.type }))}'>Remove</button>` }])
      + `<form class="f pb-addlist"><div class="row"><input name="address" placeholder="https://… list URL" required style="flex:2"><select name="type"><option value="block">block</option><option value="allow">allow</option></select><input name="comment" placeholder="Note (optional)"></div>
        <div class="row small">Groups: ${groupNames.map(g => `<label><input type="checkbox" name="g" value="${esc(g)}" ${g === 'Default' ? 'checked' : ''}> ${esc(g)}</label>`).join(' ')}</div>
        <div class="actions"><button class="btn small primary">Add list</button></div></form>
        <div class="help small">A list is a URL the Pi-hole downloads on every gravity rebuild. Adding, removing or switching a list rebuilds gravity on the Pi-holes it changed, in the background.</div>`, `${FS.num((d.lists || []).length)}`);

    const cats = d.categories || [];
    const catsCard = cats.length ? FS.card('FlowSight categories as Pi-hole lists', FS.table(cats, [
      { t: 'Category', f: c => `<a href="#categories"><b>${esc(c.name)}</b></a><div class="muted small">${FS.num(c.domains)} domains</div>` },
      { t: 'On the Pi-holes', f: c => { const sub = c.subscribed || {}; const on = Object.keys(sub); return on.length ? on.map(u => FS.pill(`${hostOf(servers, u)}: ${sub[u]}`, sub[u] === 'allow' ? 'ok' : 'bad')).join(' ') : '<span class="muted small">not subscribed</span>'; } },
      { t: '', f: c => { const on = Object.keys(c.subscribed || {}); const typ = on.length ? c.subscribed[on[0]] : ''; return on.length ? `<button class="btn small" data-cun='${esc(JSON.stringify({ c: c.name, t: typ }))}'>Unsubscribe</button>` : `<button class="btn small" data-csub='${esc(JSON.stringify({ c: c.name, t: 'block' }))}'>Block with it</button> <button class="btn small" data-csub='${esc(JSON.stringify({ c: c.name, t: 'allow' }))}'>Allow with it</button>`; } }]),
      `<a href="${DOC}" target="_blank" rel="noopener">how</a>`)
      + '' : '';

    const clientsCard = FS.card('Clients in groups', FS.table(d.clients || [], [
      { t: 'Client', f: c => `<span class="mono">${esc(c.client)}</span>${c.flowsight_name || c.name ? `<div class="small">${esc(c.flowsight_name || c.name)}</div>` : ''}${c.comment ? `<div class="muted small">${esc(c.comment)}</div>` : ''}` },
      { t: 'Groups', f: c => `${groupPills(c.groups)} <a href="#" class="small" data-cgrp='${esc(JSON.stringify({ c: c.client, g: c.groups }))}'>edit</a>` },
      { t: '', f: c => where(c, servers) },
      { t: '', f: c => `<button class="btn small" data-crm="${esc(c.client)}">Remove</button>` }], { empty: 'Every client is in the Default group.' })
      + `<form class="f pb-addclient"><div class="row"><input name="client" list="pb-devices" placeholder="192.168.1.68, a MAC, a network or a host name" required style="flex:2"><datalist id="pb-devices"></datalist><input name="comment" placeholder="Note (optional)"></div>
        <div class="row small">Groups: ${groupNames.map(g => `<label><input type="checkbox" name="g" value="${esc(g)}" ${g === 'Default' ? 'checked' : ''}> ${esc(g)}</label>`).join(' ')}</div>
        <div class="actions"><button class="btn small primary">Add client</button></div></form>
        <div class="help small">Groups apply to devices that ask the Pi-hole directly. A device that asks the gateway resolver reaches the Pi-hole, if at all, as the gateway.</div>`, `${FS.num((d.clients || []).length)}`);

    const domainsCard = FS.card('Allow and deny entries', FS.table(d.domains || [], [
      { t: 'Name', f: x => `<span class="mono">${esc(x.domain)}</span>${x.kind === 'regex' ? ' ' + FS.pill('regex', '') : ''}${x.comment ? `<div class="muted small">${esc(x.comment)}</div>` : ''}` },
      { t: 'List', f: x => FS.pill(x.type, x.type === 'allow' ? 'ok' : 'bad') },
      { t: 'On', f: x => `<input type="checkbox" data-don='${esc(JSON.stringify({ d: x.domain, t: x.type, k: x.kind }))}' ${x.enabled ? 'checked' : ''}>` },
      { t: 'Groups', f: x => `${groupPills(x.groups)} <a href="#" class="small" data-dgrp='${esc(JSON.stringify({ d: x.domain, t: x.type, k: x.kind, g: x.groups }))}'>edit</a>` },
      { t: '', f: x => where(x, servers) },
      { t: '', f: x => `<button class="btn small" data-drm='${esc(JSON.stringify({ d: x.domain, t: x.type, k: x.kind }))}'>Remove</button>` }])
      + `<form class="f pb-adddom"><div class="row"><input name="domains" placeholder="name.example.com (several: space or comma separated)" required style="flex:2"><select name="type"><option value="deny">deny</option><option value="allow">allow</option></select><select name="kind"><option value="exact">exact</option><option value="regex">regex</option></select></div>
        <div class="row small">Groups: ${groupNames.map(g => `<label><input type="checkbox" name="g" value="${esc(g)}" ${g === 'Default' ? 'checked' : ''}> ${esc(g)}</label>`).join(' ')}</div>
        <div class="actions"><button class="btn small primary">Add</button></div></form>
        <div class="help small">Allow beats every blocklist; deny blocks a name no list has. Changes take effect at once.</div>`, `${FS.num((d.domains || []).length)}`);

    el.innerHTML = `<div class="help" style="margin-bottom:12px">A Pi-hole blocks from <b>lists</b> (subscriptions to blocklists and allowlists) and from single <b>entries</b>. Each belongs to <b>groups</b>, and a <b>client</b> is filtered by its groups; a client in no group is in <i>Default</i>. <a href="${DOC}" target="_blank" rel="noopener">How Pi-hole blocking works with FlowSight</a>.</div>
      <div class="pb-bar">${targetSel}</div>
      <div class="grid cols-2">${FS.card('Pi-holes', srvTable)}${syncCard || FS.card('Groups by name', '<div class="small">Groups are named here; each Pi-hole numbers its own. A group a Pi-hole lacks is created on it when something is put in it.</div>')}</div>
      <div style="height:14px"></div>${listsCard}<div style="height:14px"></div>${catsCard}${cats.length ? '<div style="height:14px"></div>' : ''}
      <div class="grid cols-2">${groupsCard}${clientsCard}</div><div style="height:14px"></div>${domainsCard}`;

    const $ = (s) => FS.$(s, el), $$ = (s) => FS.$$(s, el), J = (x) => JSON.parse(x);
    const redo = () => FS.render();
    const sel = $('#pb-target'); if (sel) sel.onchange = () => { target = sel.value; try { localStorage.setItem(KEY, target); } catch (e) { /* ignore */ } };
    $$('[data-grav]').forEach(b => b.onclick = async () => { const r = await FS.post('/api/pihole/gravity', { server: b.dataset.grav }); FS.toast(r.error || 'Gravity rebuilding', !!r.error); redo(); });
    const sync = $('form.pb-sync'); if (sync) sync.onsubmit = async (e) => {
      e.preventDefault(); const f = sync;
      const parts = FS.$$('input[name=part]:checked', f).map(x => x.value);
      if (!await FS.confirm(`Make ${f.to.value === 'all' ? 'every other Pi-hole' : hostOf(servers, f.to.value)} match ${hostOf(servers, f.from.value)} (${parts.join(', ')})?${f.extra.checked ? '\n\nWhat they have beyond it is removed.' : ''}`)) return;
      const r = await FS.post('/api/pihole/sync', { from: f.from.value, to: f.to.value, parts, remove_extra: f.extra.checked });
      const lines = ((r && r.results) || []).map(x => `${x.host}: ${x.error || ((x.changes || []).length ? x.changes.length + ' changes' : 'already the same')}`);
      FS.toast(r.error || lines.join('; '), !!(r.error || ((r && r.results) || []).some(x => x.error))); redo();
    };
    $$('[data-gon]').forEach(c => c.onchange = async () => { await send('/api/pihole/groups', { action: 'update', name: c.dataset.gon, enabled: c.checked }, `Group ${c.dataset.gon} ${c.checked ? 'on' : 'off'}`); redo(); });
    $$('[data-grm]').forEach(b => b.onclick = async () => { if (!await FS.confirm(`Remove the group ${b.dataset.grm}?\n\nIts clients fall back to Default.`)) return; await send('/api/pihole/groups', { action: 'remove', name: b.dataset.grm }, 'Removed'); redo(); });
    $$('[data-gren]').forEach(b => b.onclick = () => {
      FS.modal(`<h2>Rename ${esc(b.dataset.gren)}</h2><form class="f"><input name="n" value="${esc(b.dataset.gren)}" required><div class="actions"><button class="btn primary">Rename</button><button type="button" class="btn" data-x>Cancel</button></div></form>`, (m) => {
        FS.$('[data-x]', m).onclick = () => FS.closeModal();
        FS.$('form', m).onsubmit = async (e) => { e.preventDefault(); const n = e.target.n.value.trim(); FS.closeModal(); if (n && n !== b.dataset.gren) { await send('/api/pihole/groups', { action: 'update', name: b.dataset.gren, new_name: n }, 'Renamed'); redo(); } };
      });
    });
    const ag = $('form.pb-addgroup'); if (ag) ag.onsubmit = async (e) => { e.preventDefault(); await send('/api/pihole/groups', { action: 'add', name: ag.name.value.trim(), comment: ag.comment.value.trim() }, 'Group added'); redo(); };
    const checked = (f) => FS.$$('input[name=g]:checked', f).map(x => x.value);
    const al = $('form.pb-addlist'); if (al) al.onsubmit = async (e) => { e.preventDefault(); await send('/api/pihole/lists', { action: 'add', address: al.address.value.trim(), type: al.type.value, comment: al.comment.value.trim(), groups: checked(al) }, 'List added'); redo(); };
    $$('[data-lon]').forEach(c => c.onchange = async () => { const v = J(c.dataset.lon); await send('/api/pihole/lists', { action: 'update', address: v.a, type: v.t, enabled: c.checked }, `List ${c.checked ? 'on' : 'off'}`); redo(); });
    $$('[data-lrm]').forEach(b => b.onclick = async () => { const v = J(b.dataset.lrm); if (!await FS.confirm(`Remove this ${v.t}list?\n\n${v.a}`)) return; await send('/api/pihole/lists', { action: 'remove', address: v.a, type: v.t }, 'List removed'); redo(); });
    $$('[data-lall]').forEach(b => b.onclick = async () => { const v = J(b.dataset.lall); const r = await FS.post('/api/pihole/lists', { action: 'update', address: v.a, type: v.t, groups: v.g, comment: v.c, server: 'all' }); FS.toast(r.error || 'Added to every Pi-hole', !!r.error); redo(); });
    $$('[data-lgrp]').forEach(a => a.onclick = async (e) => { e.preventDefault(); const v = J(a.dataset.lgrp); const gs = await pickGroups(groupNames, v.g, 'Groups for this list'); if (gs) { await send('/api/pihole/lists', { action: 'update', address: v.a, type: v.t, groups: gs }, 'Groups set'); redo(); } });
    $$('[data-csub]').forEach(b => b.onclick = async () => { const v = J(b.dataset.csub); await send('/api/pihole/categories', { action: 'subscribe', category: v.c, type: v.t }, `Category ${v.c} is now a ${v.t}list`); redo(); });
    $$('[data-cun]').forEach(b => b.onclick = async () => { const v = J(b.dataset.cun); if (!await FS.confirm(`Stop using the FlowSight category ${v.c} as a Pi-hole ${v.t}list?`)) return; await send('/api/pihole/categories', { action: 'unsubscribe', category: v.c, type: v.t }, 'Unsubscribed'); redo(); });
    const ac = $('form.pb-addclient'); if (ac) ac.onsubmit = async (e) => { e.preventDefault(); await send('/api/pihole/clients', { action: 'add', client: ac.client.value.trim(), comment: ac.comment.value.trim(), groups: checked(ac) }, 'Client added'); redo(); };
    $$('[data-cgrp]').forEach(a => a.onclick = async (e) => { e.preventDefault(); const v = J(a.dataset.cgrp); const gs = await pickGroups(groupNames, v.g, 'Groups for ' + v.c); if (gs) { await send('/api/pihole/clients', { action: 'update', client: v.c, groups: gs }, 'Groups set'); redo(); } });
    $$('[data-crm]').forEach(b => b.onclick = async () => { if (!await FS.confirm(`Take ${b.dataset.crm} out of its groups? It goes back to Default.`)) return; await send('/api/pihole/clients', { action: 'remove', client: b.dataset.crm }, 'Removed'); redo(); });
    const ad = $('form.pb-adddom'); if (ad) ad.onsubmit = async (e) => { e.preventDefault(); await send('/api/pihole/domains', { action: 'add', type: ad.type.value, kind: ad.kind.value, domains: String(ad.domains.value).split(/[\s,]+/).filter(Boolean), groups: checked(ad) }, 'Added'); redo(); };
    $$('[data-don]').forEach(c => c.onchange = async () => { const v = J(c.dataset.don); await send('/api/pihole/domains', { action: 'update', type: v.t, kind: v.k, domains: [v.d], enabled: c.checked }, `Entry ${c.checked ? 'on' : 'off'}`); redo(); });
    $$('[data-dgrp]').forEach(a => a.onclick = async (e) => { e.preventDefault(); const v = J(a.dataset.dgrp); const gs = await pickGroups(groupNames, v.g, 'Groups for ' + v.d); if (gs) { await send('/api/pihole/domains', { action: 'update', type: v.t, kind: v.k, domains: [v.d], groups: gs }, 'Groups set'); redo(); } });
    $$('[data-drm]').forEach(b => b.onclick = async () => { const v = J(b.dataset.drm); if (!await FS.confirm(`Remove ${v.d} from the ${v.t} list?`)) return; await send('/api/pihole/domains', { action: 'remove', type: v.t, kind: v.k, domains: [v.d] }, 'Removed'); redo(); });
    // FlowSight's devices, for naming a client by what it is.
    FS.get('/api/identity/hosts?hours=168').then(h => {
      const dl = FS.$('#pb-devices', el); if (!dl || !h || h.error) return;
      dl.innerHTML = (h.hosts || []).filter(x => x.name && x.is_local && !String(x.ip).includes(':')).slice(0, 300).map(x => `<option value="${esc(x.ip)}">${esc(x.name)}</option>`).join('');
    });
    if (running) setTimeout(() => { if (FS.parseHash().params.tab === 'phblock' && document.body.contains(el)) FS.render(); }, 4000);
  };
})();

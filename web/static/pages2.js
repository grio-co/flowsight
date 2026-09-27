/* FlowSight pages: policy, categories, findings, system. */
'use strict';
(function () {
  const { esc, num, bytes, ago, when, pill, card, kpi, table, bars, hostLink, domainLink, get, post } = FS;

  // ------------------------------------------------------------- Policy list
  FS.registerPage('policy', {
    title: 'Policies', refresh: 60,
    async render(el) {
      const [d, caps] = await Promise.all([get('/api/policy'), get('/api/policy/capabilities')]);
      if (d.error && !d.document) { el.innerHTML = FS.err(d.error); return; }
      const doc = Object.assign({ policies: [], groups: {}, schedules: {}, exclusions: {}, options: {} }, d.document || {}); doc.policies = doc.policies || []; doc.groups = doc.groups || {}; doc.schedules = doc.schedules || {};
      const plan = d.plan || {}; const status = {}; (plan.policies || []).forEach(p => status[p.name] = p);
      const provs = (caps.providers || []).map(p => `${esc(p.name)} <span class="muted small">${(p.capabilities || []).join(', ')}</span>`).join(' · ');
      const enforce = d.enforce;
      const banner = enforce ? `<div class="card" style="border-color:var(--ok)"><b>Enforcing.</b> Every provider is reconciled with this document about once a minute. ${plan.errors && plan.errors.length ? `<span class="sev-high">Last plan had errors: ${esc(plan.errors.join('; '))}</span>` : ''}${plan.warnings && plan.warnings.length ? `<div class="sev-medium small" style="margin-top:6px">${esc(plan.warnings.join(' · '))}</div>` : ''}</div>`
        : `<div class="card" style="border-color:var(--warn)"><b>Monitor mode.</b> Policies are compiled and planned but nothing is written to a backend until you turn on <a href="#modules/policy">Enforce policy</a>. ${d.error ? `<span class="sev-high">Document error: ${esc(d.error)}</span>` : ''}</div>`;
      const summary = (p) => {
        const bits = [];
        const dd = p.deny || {};
        if (dd.apps && dd.apps.length) bits.push(`apps: ${dd.apps.join(', ')}`);
        if (dd.app_categories && dd.app_categories.length) bits.push(`app categories: ${dd.app_categories.join(', ')}`);
        if (dd.categories && dd.categories.length) bits.push(`categories: ${dd.categories.join(', ')}`);
        if (dd.domains && dd.domains.length) bits.push(`domains: ${dd.domains.slice(0, 4).join(', ')}${dd.domains.length > 4 ? ` +${dd.domains.length - 4}` : ''}`);
        if (dd.tlds && dd.tlds.length) bits.push(`TLDs: .${dd.tlds.join(', .')}`);
        if (dd.ports && dd.ports.length) bits.push(`ports: ${dd.ports.join(', ')}`);
        if (dd.countries && dd.countries.length) bits.push(`countries: ${dd.countries.join(', ')}`);
        if (dd.countries_except && dd.countries_except.length) bits.push(`every country except ${dd.countries_except.join(', ')}`);
        const named = (dd.countries || []).concat(dd.countries_except || []).map(c => `${c} = ${FS.countryName(c)}`).join(', ');
        if (named) return `<span title="${esc(named)}">${esc(bits.join(' · '))}</span>`;
        if (dd.internet) bits.push('no internet');
        if (p.safe_search) bits.push('safe search');
        if (p.youtube) bits.push('YouTube ' + p.youtube);
        if (p.tls && p.tls.inspect) bits.push('TLS inspection');
        return esc(bits.join(' · ')) || '<span class="muted">nothing denied</span>';
      };
      const who = (p) => p.match.all ? 'everyone' : [...(p.match.groups || []).map(g => 'group ' + g), ...(p.match.members || [])].join(', ');
      el.innerHTML = banner + `<div class="actions" style="margin-top:14px"><button class="btn primary" id="new">New policy</button><button class="btn" id="plan">Show plan</button>${enforce ? '<button class="btn" id="apply">Apply now</button>' : ''}<button class="btn" id="export">Export YAML</button><button class="btn" id="import">Import…</button><span style="flex:1"></span><span class="small muted">Providers: ${provs || 'none'}</span></div>` +
        card(`${doc.policies.length} policies (evaluated in order)`, table(doc.policies, [
          { t: '', f: (p, i) => `<button class="btn small" data-move="up" data-name="${esc(p.name)}">↑</button> <button class="btn small" data-move="down" data-name="${esc(p.name)}">↓</button>`, w: '80px' },
          { t: 'Policy', f: p => `<b>${esc(p.name)}</b>${p.description ? `<div class="muted small">${esc(p.description)}</div>` : ''}`, sort: 'name' },
          { t: 'State', f: p => { const s = status[p.name] || {}; return (p.enabled ? (s.active === false ? pill('scheduled off', '') : pill('on', 'ok')) : pill('disabled', 'warn')) + (p.action === 'monitor' ? ' ' + pill('monitor', 'info') : '') + ((s.unmet || []).length ? ' ' + pill('unmet: ' + s.unmet.join(', '), 'bad') : '') + (s.warning ? ` <span class="pill bad" title="${esc(s.warning)}">all members excluded</span>` : ''); } },
          { t: 'Applies to', f: p => esc(who(p)) + (p.schedule ? ` <span class="muted small">· ${esc(p.schedule)}</span>` : '') },
          { t: 'Denies', f: summary },
          { t: '', f: p => `${((p.deny || {}).countries || []).length || ((p.deny || {}).countries_except || []).length ? `<a class="btn small" href="#policy-matches?name=${encodeURIComponent(p.name)}" title="Which devices are talking to denied countries, and where">Matches</a> ` : ''}<button class="btn small" data-edit="${esc(p.name)}">Edit</button> <button class="btn small danger" data-del="${esc(p.name)}">Delete</button>` }]), '') +
        (plan.providers ? card('Last plan', `<div class="small muted">${when(plan.at)} · ${plan.changes} provider(s) would change</div>` + (plan.providers || []).map(pp => `<div style="margin-top:8px"><b>${esc(pp.name)}</b> ${pp.error ? pill('error', 'bad') : pp.changed ? pill('changes', 'warn') : pill('in sync', 'ok')} <span class="muted small">${esc(pp.note || '')}</span>${pp.error ? `<div class="sev-high small">${esc(pp.error)}</div>` : ''}${pp.diff ? `<details><summary class="small">diff</summary><pre class="code">${FS.diffHtml(pp.diff.slice(0, 20000))}</pre></details>` : ''}</div>`).join('')) : '');
      // Country tables and the anchor's live counters: the proof that a
      // country rule exists in pf, what it holds, and whether it has matched.
      (async () => {
        const fw = await get('/api/firewall/status');
        if (!fw || fw.available === false) return;
        const gt = fw.geo_tables || [];
        const pc = (fw.counters && fw.counters.policy) ? fw.counters.policy.filter(r => r.label) : [];
        if (!gt.length && !pc.length) return;
        const box = document.createElement('div');
        box.style.marginTop = '14px';
        box.innerHTML = card(`Firewall tables and rules${fw.geo_filling ? ' · <span class="pill info">filling…</span>' : ''}`,
          (gt.length ? table(gt, [
            { t: 'Table', f: t => `<span class="mono">${esc(t.name)}</span>` },
            { t: 'Holds', f: t => (t.invert ? 'every country except ' : '') + (t.countries || []).map(c => FS.cc(c, { cls: 'pill' })).join(' ') },
            { t: 'Prefixes', f: t => num(t.prefixes), num: true },
            { t: 'In kernel', f: t => `<span class="${t.kernel_addresses === t.prefixes ? '' : 'sev-medium'}">${num(t.kernel_addresses)}</span>`, num: true },
            { t: 'Anycast left out', f: t => num(t.skipped_anycast), num: true },
            { t: 'Database', f: t => t.epoch ? new Date(t.epoch * 1000).toISOString().slice(0, 10) : '' },
            { t: 'Filled', f: t => t.updated ? ago(t.updated) : '' }]) : '') +
          (pc.length ? `<div style="margin-top:10px">${table(pc, [
            { t: 'Rule', f: r => `<span class="mono small">${esc(r.rule)}</span>${/^flowsight:(.+):[^:]+$/.test(r.label) ? ` <a class="small" href="#policy-matches?name=${encodeURIComponent(r.label.replace(/^flowsight:(.+):[^:]+$/, '$1'))}">matches</a>` : ''}` },
            { t: 'Evaluated', f: r => num(r.evaluations), num: true },
            { t: 'Matched packets', f: r => `<b>${num(r.packets)}</b>`, num: true },
            { t: 'Bytes', f: r => bytes(r.bytes), num: true },
            { t: 'States', f: r => num(r.states), num: true }])}</div>` : '') +
          `<form class="f" id="tbltest" style="margin-top:10px;display:flex;gap:8px;align-items:end"><div><label>Is an address in a table?</label><input type="text" name="ip" placeholder="34.249.231.250" style="width:200px"></div><div><label>Table</label><select name="name">${gt.map(t => `<option>${esc(t.name)}</option>`).join('')}</select></div><button class="btn">Test</button><span class="small muted" id="tblres"></span></form>
          <div class="help">Monitor-mode rules use <span class="mono">match</span> and count without dropping; the packet count rises on the first new connection to an address in the table. Anycast ranges are left out of every table on purpose.</div>`);
        el.appendChild(box);
        const f = FS.$('#tbltest', box);
        if (f) f.onsubmit = async (e) => {
          e.preventDefault();
          const r = await get(`/api/firewall/table?name=${encodeURIComponent(f.name.value)}&ip=${encodeURIComponent(f.ip.value.trim())}`);
          FS.$('#tblres', box).textContent = r.error ? r.error : (r.in_table ? `${r.ip} is in ${r.name}` : `${r.ip} is not in ${r.name}`) + ` (kernel holds ${num(r.kernel_addresses)})`;
        };
      })();
      FS.$('#new', el).onclick = () => FS.policyEditor(null, doc, caps);
      FS.$$('[data-edit]', el).forEach(b => b.onclick = () => FS.policyEditor(doc.policies.find(p => p.name === b.dataset.edit), doc, caps));
      FS.$$('[data-del]', el).forEach(b => b.onclick = async () => { if (!await FS.confirm(`Delete policy "${b.dataset.del}"?`)) return; const r = await post('/api/policy/policy/delete', { name: b.dataset.del }); if (r.error) FS.toast(r.error, true); else FS.render(); });
      FS.$$('[data-move]', el).forEach(b => b.onclick = async () => { const r = await post('/api/policy/policy/move', { name: b.dataset.name, direction: b.dataset.move }); if (r.error) FS.toast(r.error, true); else FS.render(); });
      FS.$('#plan', el).onclick = async () => { FS.toast('Planning…'); const r = await get('/api/policy/plan'); if (r.error) FS.toast(r.error, true); FS.render(); };
      const ap = FS.$('#apply', el); if (ap) ap.onclick = async () => { FS.toast('Applying…'); const r = await post('/api/policy/apply', {}); if (r.error) FS.toast(r.error, true); else FS.toast(r.ok ? 'Applied' : 'Apply had errors: ' + (r.error || ''), !r.ok); FS.render(); };
      FS.$('#export', el).onclick = () => { location.href = FS.base ? FS.base + encodeURIComponent('/api/policy/export') : '/api/policy/export'; };
      FS.$('#import', el).onclick = () => FS.modal(`<h2>Import policy document</h2><form class="f"><label>YAML or JSON</label><textarea name="text" style="min-height:260px"></textarea><div class="actions"><button class="btn primary">Replace document</button><button type="button" class="btn" data-close>Cancel</button></div></form>`, (b) => { FS.$('form', b).onsubmit = async (e) => { e.preventDefault(); const r = await post('/api/policy/import', { text: e.target.text.value }); if (r.error) FS.toast(r.error, true); else { FS.closeModal(); FS.toast(`Imported ${r.policies} policies`); FS.render(); } }; });
    }
  });

  // Policy editor modal. Works for new and existing policies.
  FS.policyEditor = function (pol, doc, caps) {
    const isNew = !pol;
    pol = pol ? JSON.parse(JSON.stringify(pol)) : { name: '', enabled: true, action: 'block', match: { groups: [] }, deny: {}, allow: {}, tls: {} };
    const groups = Object.keys(doc.groups || {}), schedules = Object.keys(doc.schedules || {});
    const webCats = (caps.categories || []).map(c => c.name), appCats = caps.app_categories || [];
    const list = (a) => (a || []).join('\n');
    const opts = (arr, sel) => arr.map(x => `<option ${sel && sel.includes(x) ? 'selected' : ''}>${esc(x)}</option>`).join('');
    FS.modal(`<h2>${isNew ? 'New policy' : 'Edit policy'}</h2><form class="f">
      <div class="row"><div><label>Name</label><input type="text" name="name" value="${esc(pol.name)}" required></div><div><label>Action</label><select name="action"><option ${pol.action === 'block' ? 'selected' : ''} value="block">block</option><option ${pol.action === 'monitor' ? 'selected' : ''} value="monitor">monitor (log only)</option></select></div></div>
      <label>Description</label><input type="text" name="description" value="${esc(pol.description || '')}">
      <div class="check"><input type="checkbox" name="enabled" ${pol.enabled ? 'checked' : ''}><span>Enabled</span></div>
      <div class="tabs"><button type="button" class="on" data-tab="who">Who</button><button type="button" data-tab="what">What to deny</button><button type="button" data-tab="countries">Countries</button><button type="button" data-tab="web">Web & DNS</button><button type="button" data-tab="tls">TLS</button></div>
      <div data-pane="who">
        <div class="check"><input type="checkbox" name="all" ${pol.match.all ? 'checked' : ''}><span>Everyone on the local networks</span></div>
        <label>Groups</label><select name="groups" multiple size="${Math.min(6, Math.max(2, groups.length))}">${opts(groups, pol.match.groups)}</select><div class="help">Manage groups under Groups &amp; Schedules.</div>
        <label>Extra members</label><textarea name="members" placeholder="10.0.0.5&#10;10.0.1.0/24&#10;mac:aa:bb:cc:dd:ee:ff&#10;device:kids-ipad&#10;user:alice&#10;usergroup:admins">${esc(list(pol.match.members))}</textarea>
        <div class="check"><input type="checkbox" name="even_excluded" ${pol.match.even_excluded ? 'checked' : ''}><span>Apply even to hosts in the exclusions list (firewall and DNS rules only; excluded hosts are still never intercepted). Needed when a whole subnet is excluded from interception but should still be subject to a port, internet or country rule.</span></div>
        <label>Schedule</label><select name="schedule"><option value="">always</option>${opts(schedules, [pol.schedule])}</select>
      </div>
      <div data-pane="what" hidden>
        <label>Applications (nDPI names)</label><textarea name="apps" placeholder="TikTok&#10;BitTorrent&#10;Discord" list="apps">${esc(list(pol.deny.apps))}</textarea><div class="help">Exact nDPI application names; see the Applications page. Matched flows are cut at the firewall.</div>
        <label>Application categories</label><select name="app_categories" multiple size="6">${opts(appCats, pol.deny.app_categories)}</select>
        <label>Ports</label><textarea name="ports" placeholder="tcp/25&#10;udp/1000-2000&#10;any/6881-6889">${esc(list(pol.deny.ports))}</textarea>
        <div class="check"><input type="checkbox" name="internet" ${pol.deny.internet ? 'checked' : ''}><span>No internet access at all (local networks stay reachable)</span></div>
        <label>Allowed applications (exceptions)</label><textarea name="allow_apps">${esc(list(pol.allow.apps))}</textarea>
      </div>
      <div data-pane="countries" hidden>
        <div id="countries-loading" class="small muted">Loading country list…</div>
        <div id="countries-list" hidden>
          <div class="check"><input type="checkbox" name="countries_except" ${(pol.deny.countries_except || []).length ? 'checked' : ''}><span>Block every country <b>except</b> the ones selected (your own country is always allowed)</span></div>
          <label>Countries</label>
          <input type="text" id="countries-search" name="countries-search" placeholder="Search countries…" style="margin-bottom:8px">
          <select name="countries" multiple size="8" id="countries-select">${opts((pol.deny.countries || []), pol.deny.countries)}</select>
          <div class="help">Two-letter codes come from the local country database (Settings › enrich › Country lookup). Deny mode blocks the selected countries; except mode blocks everything else. Sessions › Outside shows what each device reached.</div>
        </div>
        <div id="countries-error" hidden class="sev-high small"></div>
      </div>
      <div data-pane="web" hidden>
        <label>Web categories</label><select name="categories" multiple size="8">${opts(webCats, pol.deny.categories)}</select>
        <label>Domains (with subdomains)</label><textarea name="domains" placeholder="tiktok.com&#10;example.net">${esc(list(pol.deny.domains))}</textarea>
        <label>Top-level domains</label><input type="text" name="tlds" value="${esc((pol.deny.tlds || []).join(', '))}" placeholder="zip, mov, xyz">
        <label>Allowed domains (exceptions)</label><textarea name="allow_domains">${esc(list(pol.allow.domains))}</textarea>
        <div class="check"><input type="checkbox" name="safe_search" ${pol.safe_search ? 'checked' : ''}><span>Force safe search (Google, Bing, DuckDuckGo)</span></div>
        <label>YouTube restricted mode</label><select name="youtube"><option value="">off</option><option ${pol.youtube === 'moderate' ? 'selected' : ''} value="moderate">moderate</option><option ${pol.youtube === 'strict' ? 'selected' : ''} value="strict">strict</option></select>
      </div>
      <div data-pane="tls" hidden>
        <div class="check"><input type="checkbox" name="inspect" ${pol.tls && pol.tls.inspect ? 'checked' : ''}><span>Inspect TLS for these devices (decrypt with the FlowSight CA)</span></div>
        <div class="help">Needs the inspection CA created under TLS and installed on the devices. Banking, pinned apps and OS updates should be bypassed.</div>
        <label>Bypass (never inspected)</label><textarea name="bypass" placeholder="apple.com&#10;icloud.com&#10;bankofamerica.com">${esc(list(pol.tls && pol.tls.bypass))}</textarea>
      </div>
      <div class="actions"><button class="btn primary">Save</button><button type="button" class="btn" data-close>Cancel</button></div></form>`, (b) => {
      FS.$$('.tabs button', b).forEach(t => t.onclick = () => { FS.$$('.tabs button', b).forEach(x => x.classList.remove('on')); t.classList.add('on'); FS.$$('[data-pane]', b).forEach(p => p.hidden = p.dataset.pane !== t.dataset.tab); });
      // Load countries list asynchronously for the countries select.
      (async () => {
        const r = await get('/api/enrich/countries');
        const loading = FS.$('#countries-loading', b);
        const list = FS.$('#countries-list', b);
        const err = FS.$('#countries-error', b);
        const select = FS.$('#countries-select', b);
        const search = FS.$('#countries-search', b);
        if (r.error) {
          if (loading) loading.hidden = true;
          if (err) { err.hidden = false; err.textContent = r.error; }
          return;
        }
        const countries = r.countries || [];
        const opts = countries.map(c => `<option value="${esc(c.code)}" ${(((pol.deny && pol.deny.countries) || []).concat((pol.deny && pol.deny.countries_except) || [])).includes(c.code) ? 'selected' : ''}>${esc(c.code)} – ${esc(c.name)} (${c.prefixes} network(s))</option>`).join('');
        select.innerHTML = opts;
        if (loading) loading.hidden = true;
        if (list) list.hidden = false;
        // Live search in countries list
        if (search) {
          search.oninput = () => {
            const q = search.value.toLowerCase();
            FS.$$('option', select).forEach(opt => {
              opt.hidden = !opt.textContent.toLowerCase().includes(q);
            });
          };
        }
      })();
      FS.$('form', b).onsubmit = async (e) => {
        e.preventDefault(); const f = e.target;
        const lines = (n) => f[n].value.split(/\n|,/).map(x => x.trim()).filter(Boolean);
        const multi = (n) => Array.from(f[n].selectedOptions).map(o => o.value);
        const out = { name: f.name.value.trim(), description: f.description.value.trim(), enabled: f.enabled.checked, action: f.action.value,
          match: { all: f.all.checked, groups: multi('groups'), members: lines('members'), even_excluded: f.even_excluded.checked }, schedule: f.schedule.value,
          deny: { apps: lines('apps'), app_categories: multi('app_categories'), ports: lines('ports'), internet: f.internet.checked, categories: multi('categories'), domains: lines('domains'), tlds: lines('tlds'), countries: f.countries_except.checked ? [] : multi('countries'), countries_except: f.countries_except.checked ? multi('countries') : [] },
          allow: { apps: lines('allow_apps'), domains: lines('allow_domains') }, tls: { inspect: f.inspect.checked, bypass: lines('bypass') },
          safe_search: f.safe_search.checked, youtube: f.youtube.value };
        const r = await post('/api/policy/policy', { original: isNew ? '' : pol.name, policy: out });
        if (r.error) { FS.toast(r.error, true); return; }
        FS.closeModal(); FS.toast('Saved'); FS.render();
      };
    });
  };
  // Quick "block this app for a group" entry from the Applications page.
  FS.quickPolicy = async function (deny) {
    const [d, caps] = await Promise.all([get('/api/policy'), get('/api/policy/capabilities')]);
    const doc = Object.assign({ groups: {}, schedules: {}, policies: [] }, d.document || {}); doc.policies = doc.policies || []; doc.groups = doc.groups || {}; doc.schedules = doc.schedules || {};
    FS.policyEditor(null, doc, caps);
    setTimeout(() => {
      const f = FS.$('#modal form'); if (!f) return;
      if (deny.apps) {
        f.apps.value = deny.apps.join('\n');
        if (deny.apps.length) f.name.value = 'block-' + deny.apps[0].toLowerCase().replace(/[^a-z0-9]+/g, '-');
        FS.$$('.tabs button', f)[1].click();
      }
      if (deny.app_categories && deny.app_categories.length && f.app_categories) {
        Array.from(f.app_categories.options).forEach(o => { o.selected = deny.app_categories.includes(o.value); });
        if (!f.name.value) f.name.value = 'block-' + deny.app_categories[0].toLowerCase().replace(/[^a-z0-9]+/g, '-');
        FS.$$('.tabs button', f)[1].click();
      }
      if (deny.members && f.members) { f.members.value = deny.members.join('\n'); }
      if (deny.countries && deny.countries.length) {
        if (!f.name.value) f.name.value = 'block-' + deny.countries.join('-').toLowerCase();
        // The country list loads after the form opens; select once it is there.
        let tries = 0;
        const pick = () => {
          const sel = f['countries-select'];
          if (sel && sel.options.length) { Array.from(sel.options).forEach(o => { o.selected = deny.countries.includes(o.value); }); return; }
          if (++tries < 40) setTimeout(pick, 150);
        };
        pick();
        FS.$$('.tabs button', f)[2].click();
      }
    }, 50);
  };

  // ------------------------------------------------------------- Policy matches
  // Where a policy's country rule is matching: per device, the far ends in
  // denied countries with names and bytes (from the session table, computed
  // the way the rule is compiled), and beside it the packets the firewall
  // itself logged for the rule.
  FS.registerPage('policy-matches', {
    title: 'Policy matches', refresh: 30,
    async render(el, ctx) {
      const name = ctx.params.name || '';
      if (!name) { el.innerHTML = FS.err('Open this page from a policy\'s Matches button.'); return; }
      const d = await get(`/api/policy/matches?name=${encodeURIComponent(name)}&${FS.since()}`);
      if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const devices = d.devices || [];
      const logged = d.logged || {};
      const ldevs = logged.devices || [];
      const ccs = (list) => (list || []).map(c => FS.cc(c, { cls: 'pill' })).join(' ');
      const rule = d.countries_except && d.countries_except.length ? `every country except ${ccs(d.countries_except)}${d.home_country && !d.countries_except.includes(d.home_country) ? ` (and ${FS.cc(d.home_country, { cls: 'pill', title: 'home' })})` : ''}` : (d.countries || []).length ? `countries ${ccs(d.countries)}` : 'no country rule';
      const total = devices.reduce((a, x) => a + x.sessions, 0);
      const destRows = (x) => table(x.destinations || [], [
        { t: 'Destination', f: r => `<b>${esc(r.domain || r.name || r.ip)}</b>${(r.domain || r.name) ? `<div class="muted small mono">${esc(r.ip)}</div>` : ''}` },
        { t: 'Country', f: r => FS.cc(r.country, { cls: 'pill warn', href: `#flows?ip=${encodeURIComponent(x.ip)}&country=${esc(r.country)}` }), sort: 'country' },
        { t: 'Port / app', f: r => `${r.port || ''}${r.app ? ' · ' + esc(r.app) : ''}` },
        { t: 'Sessions', f: r => num(r.sessions), num: true, sort: 'sessions' },
        { t: 'Sent', f: r => bytes(r.bytes_out), num: true, sort: 'bytes_out' },
        { t: 'Received', f: r => bytes(r.bytes_in), num: true, sort: 'bytes_in' },
        { t: 'Last', f: r => ago(r.last_seen), sort: 'last_seen' },
        { t: '', f: r => `<a class="btn small" href="#paths?dst=${encodeURIComponent(r.ip)}" title="The route to this far end on the map">Map</a>` }]);
      el.innerHTML = `<div class="actions"><a class="btn" href="#policy">← Policies</a><span class="muted small">Policy <b>${esc(d.policy)}</b> · ${esc(d.action)} · ${rule} · ${num(d.members)} member network(s) · window ${FS.state.hours}h</span></div>
        <div class="grid cols-3" style="margin-top:14px">
          ${kpi('Devices', num(devices.length), 'talked to a denied country')}
          ${kpi('Sessions', num(total), d.action === 'monitor' ? 'would be blocked' : 'blocked or attempted')}
          ${kpi('Packets logged by the rule', num(logged.packets || 0), (logged.log && logged.log.error) ? 'log not readable: ' + esc(logged.log.error) : `from ${esc((logged.log || {}).path || 'the filter log')}`, (logged.log && logged.log.error) ? 'warn' : '')}
        </div>
        <div style="margin-top:14px">${card('By device: where the traffic went', devices.length ? devices.map(x => `<details ${devices.length <= 3 ? 'open' : ''} style="margin-bottom:8px"><summary style="cursor:pointer">${FS.hostLink(x.ip, x.name)} ${x.mac ? `<span class="muted small mono">${esc(x.mac)}</span>` : ''} · <b>${num(x.sessions)}</b> sessions · ${bytes(x.bytes_out)} sent · ${x.countries.map(c => FS.cc(c, { cls: 'pill warn' })).join(' ')}</summary><div style="margin-top:8px">${destRows(x)}</div></details>`).join('') : `<div class="empty">No session from this policy's members reached a denied country in the last ${FS.state.hours}h${d.country_rule ? '' : ' (the policy has no country rule)'}. Anycast far ends are left out on purpose.</div>`,
          'from the session table; anycast far ends left out, as in the rule')}</div>
        <div style="margin-top:14px">${card('Logged by the firewall rule', ldevs.length ? ldevs.map(x => `<details style="margin-bottom:8px"><summary style="cursor:pointer">${FS.hostLink(x.ip, x.name)} · <b>${num(x.packets)}</b> packets</summary><div style="margin-top:8px">${table(x.destinations || [], [
            { t: 'Destination', f: r => `<b>${esc(r.domain || r.name || r.ip)}</b>${(r.domain || r.name) ? `<div class="muted small mono">${esc(r.ip)}</div>` : ''}` },
            { t: 'Country', f: r => FS.cc(r.country, { cls: 'pill warn' }) },
            { t: 'Port', f: r => `${r.port || ''}${r.proto ? '/' + esc(r.proto) : ''}` },
            { t: 'Packets', f: r => num(r.packets), num: true, sort: 'packets' },
            { t: 'Last', f: r => ago(r.last), sort: 'last' },
            { t: '', f: r => `<a class="btn small" href="#paths?dst=${encodeURIComponent(r.ip)}">Map</a>` }])}</div></details>`).join('') : `<div class="empty">${(logged.log && logged.log.error) ? 'The filter log could not be read: ' + esc(logged.log.error) : `Nothing logged for this rule yet. The rule counts a packet when a new connection to an address in the table starts; ${num((logged.log || {}).lines_read || 0)} log lines read so far.`}</div>`,
          'exact, per packet, from pflog via the filter log; bare addresses, names filled in from the session table')}</div>
        <div class="help" style="margin-top:12px">The first card is computed the way the rule is compiled: the policy's members after exclusions, the denied countries, anycast ranges left out. The second is what pf itself wrote to its log for the rule. They should agree in shape; the log lags by a few seconds and only shows packets, not names.</div>`;
    }
  });

  // ------------------------------------------------------------- Groups & Schedules
  FS.registerPage('groups', {
    title: 'Groups & Schedules', refresh: 0,
    async render(el) {
      const d = await get('/api/policy'); const doc = d.document || { groups: {}, schedules: {}, exclusions: {}, options: {} };
      const grows = Object.entries(doc.groups || {}).map(([name, g]) => ({ name, ...g }));
      const srows = Object.entries(doc.schedules || {}).map(([name, s]) => ({ name, ...s }));
      const fmtWin = (w) => `${(w.days && w.days.length) ? w.days.join(',') : 'daily'} ${w.from}–${w.to}`;
      el.innerHTML = `<div class="grid cols-2">
        ${card('Groups', `<div class="actions"><button class="btn primary" id="g-new">New group</button></div>` + table(grows, [{ t: 'Group', f: r => `<b>${esc(r.name)}</b>${r.description ? `<div class="muted small">${esc(r.description)}</div>` : ''}` }, { t: 'Members', f: r => `<span class="mono small">${esc((r.members || []).join(', '))}</span>` }, { t: '', f: r => `<button class="btn small" data-g="${esc(r.name)}">Edit</button> <button class="btn small danger" data-gd="${esc(r.name)}">Delete</button>` }]))}
        ${card('Schedules', `<div class="actions"><button class="btn primary" id="s-new">New schedule</button></div>` + table(srows, [{ t: 'Schedule', f: r => `<b>${esc(r.name)}</b>${r.description ? `<div class="muted small">${esc(r.description)}</div>` : ''}` }, { t: 'Windows', f: r => (r.windows || []).map(fmtWin).map(esc).join('<br>') }, { t: '', f: r => `<button class="btn small" data-s="${esc(r.name)}">Edit</button> <button class="btn small danger" data-sd="${esc(r.name)}">Delete</button>` }]))}
      </div>
      <div style="margin-top:14px">${card('Exclusions and options', `<form class="f" id="excl"><div class="row"><div><label>Excluded hosts (never intercepted, inspected or policed)</label><textarea name="hosts">${esc((doc.exclusions.hosts || []).join('\n'))}</textarea></div><div><label>Excluded domains (never intercepted or blocked)</label><textarea name="domains">${esc((doc.exclusions.domains || []).join('\n'))}</textarea></div></div><div class="row"><div><label>DNS block answer</label><select name="dns_block_mode"><option value="nxdomain" ${doc.options.dns_block_mode === 'nxdomain' || !doc.options.dns_block_mode ? 'selected' : ''}>NXDOMAIN</option><option value="null" ${doc.options.dns_block_mode === 'null' ? 'selected' : ''}>0.0.0.0 (null)</option><option value="refused" ${doc.options.dns_block_mode === 'refused' ? 'selected' : ''}>REFUSED</option></select></div><div><label>Block page URL (empty: built-in page)</label><input type="text" name="block_page_url" value="${esc(doc.options.block_page_url || '')}"></div></div><div class="actions"><button class="btn primary">Save</button></div></form>`)}</div>`;
      const gEdit = (name) => { const g = name ? doc.groups[name] : { members: [] }; FS.modal(`<h2>${name ? 'Edit' : 'New'} group</h2><form class="f"><label>Name</label><input type="text" name="name" value="${esc(name || '')}" required><label>Description</label><input type="text" name="description" value="${esc(g.description || '')}"><label>Members</label><textarea name="members" placeholder="10.0.0.5&#10;10.0.1.0/24&#10;mac:aa:bb:cc:dd:ee:ff&#10;device:kids-ipad&#10;zone:iot&#10;user:alice&#10;usergroup:admins">${esc((g.members || []).join('\n'))}</textarea><div class="help">Addresses, networks, mac:, device:&lt;name&gt;, zone:&lt;id&gt;, user:&lt;name&gt; or usergroup:&lt;group&gt;.</div>
          <div class="hostpick"><div class="actions" style="margin:6px 0"><input type="search" id="hp-q" placeholder="Find a device by name, address or maker" style="flex:1"><button type="button" class="btn small" id="hp-all">Add every device shown</button></div><div id="hp-list" class="hplist"><div class="muted small">Loading devices…</div></div><div class="help">Ticking a device adds it by hardware address, which covers every address it holds and every interface it uses, now and after its next lease. A device with no hardware address is added by each of its addresses.</div></div>
          <div class="actions"><button class="btn primary">Save</button><button type="button" class="btn" data-close>Cancel</button></div></form>`, (b) => { FS.hostPicker(b, FS.$('textarea[name=members]', b)); FS.$('form', b).onsubmit = async (e) => { e.preventDefault(); const f = e.target; const r = await post('/api/policy/group', { original: name || '', name: f.name.value.trim(), group: { description: f.description.value, members: f.members.value.split(/\n|,/).map(x => x.trim()).filter(Boolean) } }); if (r.error) FS.toast(r.error, true); else { FS.closeModal(); FS.render(); } }; }); };
      const sEdit = (name) => { const s = name ? doc.schedules[name] : { windows: [{ days: [], from: '20:00', to: '07:00' }] }; const days = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']; const win = (w, i) => `<div class="row" data-win="${i}" style="grid-template-columns:2fr 1fr 1fr auto;align-items:end"><div><label>Days (none = every day)</label><div class="chips">${days.map(d => `<label class="chip"><input type="checkbox" value="${d}" ${(w.days || []).includes(d) ? 'checked' : ''}> ${d}</label>`).join('')}</div></div><div><label>From</label><input type="text" name="from" value="${esc(w.from)}"></div><div><label>To</label><input type="text" name="to" value="${esc(w.to)}"></div><div><button type="button" class="btn" data-rm="${i}">×</button></div></div>`;
        FS.modal(`<h2>${name ? 'Edit' : 'New'} schedule</h2><form class="f"><label>Name</label><input type="text" name="name" value="${esc(name || '')}" required><label>Description</label><input type="text" name="description" value="${esc(s.description || '')}"><div id="wins">${(s.windows || []).map(win).join('')}</div><div class="actions"><button type="button" class="btn" id="addw">Add window</button></div><div class="help">A window that ends before it starts spans midnight (20:00–07:00 means overnight).</div><div class="actions"><button class="btn primary">Save</button><button type="button" class="btn" data-close>Cancel</button></div></form>`, (b) => {
          const wire = () => FS.$$('[data-rm]', b).forEach(x => x.onclick = () => { x.closest('[data-win]').remove(); });
          wire();
          FS.$('#addw', b).onclick = () => { FS.$('#wins', b).insertAdjacentHTML('beforeend', win({ days: [], from: '00:00', to: '23:59' }, Date.now())); wire(); };
          FS.$('form', b).onsubmit = async (e) => { e.preventDefault(); const f = e.target; const windows = FS.$$('[data-win]', b).map(w => ({ days: FS.$$('input[type=checkbox]:checked', w).map(c => c.value), from: FS.$('[name=from]', w).value, to: FS.$('[name=to]', w).value })); const r = await post('/api/policy/schedule', { original: name || '', name: f.name.value.trim(), schedule: { description: f.description.value, windows } }); if (r.error) FS.toast(r.error, true); else { FS.closeModal(); FS.render(); } };
        }); };
      FS.$('#g-new', el).onclick = () => gEdit(null); FS.$('#s-new', el).onclick = () => sEdit(null);
      FS.$$('[data-g]', el).forEach(b => b.onclick = () => gEdit(b.dataset.g)); FS.$$('[data-s]', el).forEach(b => b.onclick = () => sEdit(b.dataset.s));
      FS.$$('[data-gd]', el).forEach(b => b.onclick = async () => { if (!await FS.confirm(`Delete group "${b.dataset.gd}"?`)) return; const r = await post('/api/policy/group/delete', { name: b.dataset.gd }); if (r.error) FS.toast(r.error, true); else FS.render(); });
      FS.$$('[data-sd]', el).forEach(b => b.onclick = async () => { if (!await FS.confirm(`Delete schedule "${b.dataset.sd}"?`)) return; const r = await post('/api/policy/schedule/delete', { name: b.dataset.sd }); if (r.error) FS.toast(r.error, true); else FS.render(); });
      FS.$('#excl', el).onsubmit = async (e) => { e.preventDefault(); const f = e.target; const r = await post('/api/policy/exclusions', { exclusions: { hosts: f.hosts.value.split(/\n|,/).map(x => x.trim()).filter(Boolean), domains: f.domains.value.split(/\n|,/).map(x => x.trim()).filter(Boolean) }, options: { dns_block_mode: f.dns_block_mode.value, block_page_url: f.block_page_url.value.trim() } }); if (r.error) FS.toast(r.error, true); else FS.toast('Saved'); };
    }
  });

  // ------------------------------------------------------------- Categories
  FS.registerPage('categories', {
    title: 'Categories', refresh: 60,
    async render(el) {
      const d = await get('/api/categories'); if (d.error) { el.innerHTML = FS.err(d.error); return; }
      el.innerHTML = `<div class="actions"><button class="btn" id="refresh">Refresh all feeds</button><button class="btn primary" id="custom">New custom category</button><span style="flex:1"></span><span class="small muted">${num(d.indexed_domains)} domains indexed for classification</span></div>` +
        `<div class="help" style="margin-bottom:10px">Domain lists, matched by name and enforced by DNS and the web proxy. They are not the application categories nDPI assigns to identified flows; <a href="https://github.com/grio-co/flowsight/blob/main/docs/howto/categories-and-apps.md" target="_blank" rel="noopener">how each is identified</a>. The <b>whitelist</b> category is the one that allows: names in it are never blocked by any policy.</div>` + card('Web categories', table(d.categories || [], [{ t: 'Category', f: r => `<b>${esc(r.name)}</b><div class="muted small">${esc(r.description || '')}</div>`, sort: 'name' }, { t: 'Domains', f: r => num(r.domains), num: true, sort: 'domains' }, { t: 'Updated', f: r => r.updated ? ago(r.updated) : '<span class="muted">never</span>', sort: 'updated' }, { t: 'Source', f: r => r.source === 'custom' ? pill('custom', 'info') : `<span class="small muted" style="word-break:break-all">${esc(r.source)}</span>` }, { t: 'State', f: r => r.error ? pill(r.error, 'bad') : r.domains ? pill(r.classified ? 'ready · classifying' : 'ready', 'ok') : pill('pending', 'warn') }, { t: '', f: r => `<button class="btn small" data-up="${esc(r.name)}">Refresh</button> <button class="btn small" data-view="${esc(r.name)}" title="Read the list this category blocks">View</button> <a class="btn small" href="${esc(FS.apiURL('/api/categories/' + encodeURIComponent(r.name) + '/download'))}" download title="The list as a text file">Download</a>${r.source === 'custom' ? ` <button class="btn small" data-ed="${esc(r.name)}">Edit</button>` : ''}` }])) +
        `<div class="card" style="margin-top:14px"><h3>Lookup</h3><form class="f" id="lk" style="display:flex;gap:8px;align-items:end"><div style="flex:1"><label>Domain</label><input type="text" name="domain" placeholder="example.com"></div><button class="btn">Classify</button></form><div id="lk-out" class="small" style="margin-top:8px"></div></div>`;
      FS.$('#refresh', el).onclick = async () => { const r = await post('/api/categories/update', {}); FS.toast(r.error || r.note, !!r.error); };
      FS.$$('[data-up]', el).forEach(b => b.onclick = async () => { const r = await post('/api/categories/update', { category: b.dataset.up }); FS.toast(r.error || r.note, !!r.error); });
      // The list itself, readable: what a category claims, searchable and
      // paged, with the source and its age, and the file to take away.
      FS.$$('[data-view]', el).forEach(b => b.onclick = () => {
        const name = b.dataset.view;
        FS.modal(`<h2>${esc(name)}</h2><div class="actions"><input type="search" id="cv-q" placeholder="Find a domain" style="flex:1"><a class="btn small" href="${esc(FS.apiURL('/api/categories/' + encodeURIComponent(name) + '/download'))}" download>Download</a><button type="button" class="btn" data-close>Close</button></div>
          <div class="muted small" id="cv-meta">Loading\u2026</div><pre class="code" id="cv-list" style="max-height:50vh;overflow:auto;margin-top:8px"></pre><div class="actions"><button type="button" class="btn small" id="cv-prev" disabled>Previous</button><button type="button" class="btn small" id="cv-next" disabled>Next</button></div>`, (box) => {
          let offset = 0; const limit = 300;
          const load = async () => {
            const q = FS.$('#cv-q', box).value.trim();
            const d = await get('/api/categories/' + encodeURIComponent(name) + '/domains?limit=' + limit + '&offset=' + offset + (q ? '&q=' + encodeURIComponent(q) : ''));
            if (d.error) { FS.$('#cv-meta', box).textContent = d.error; return; }
            FS.$('#cv-meta', box).innerHTML = `${num(d.matched)} of ${num(d.total)} domains${q ? ' match' : ''} \u00b7 showing ${num(Math.min(d.offset + 1, d.matched))}\u2013${num(Math.min(d.offset + limit, d.matched))}${d.source ? ` \u00b7 source <span class="mono">${esc(d.source)}</span>` : ' \u00b7 custom list'}${d.updated ? ' \u00b7 fetched ' + esc(FS.when(d.updated)) : ''}`;
            FS.$('#cv-list', box).textContent = (d.domains || []).join('\n') || '(nothing matches)';
            FS.$('#cv-prev', box).disabled = offset === 0;
            FS.$('#cv-next', box).disabled = offset + limit >= d.matched;
          };
          FS.$('#cv-q', box).oninput = () => { offset = 0; load(); };
          FS.$('#cv-prev', box).onclick = () => { offset = Math.max(0, offset - limit); load(); };
          FS.$('#cv-next', box).onclick = () => { offset += limit; load(); };
          load();
        });
      });
      const edit = (name) => { const cur = (d.categories || []).find(c => c.name === name); FS.modal(`<h2>${name ? 'Edit' : 'New'} custom category</h2><form class="f"><label>Name (lowercase, dashes)</label><input type="text" name="name" value="${esc(name || '')}" ${name ? 'readonly' : ''} required><label>Domains</label><textarea name="domains" style="min-height:200px" id="cd">${name ? 'loading…' : ''}</textarea><div class="actions"><button class="btn primary">Save</button>${name ? '<button type="button" class="btn danger" id="del">Delete</button>' : ''}<button type="button" class="btn" data-close>Cancel</button></div></form>`, async (b) => {
        if (name) { const list = await get(`/api/policy/capabilities`); const c = (list.categories || []).find(x => x.name === name); FS.$('#cd', b).value = ''; const mods = await get('/api/system/modules'); const cat = (mods.modules || []).find(m => m.name === 'categories'); FS.$('#cd', b).value = (((cat || {}).settings || {}).custom || {})[name] ? (cat.settings.custom[name] || []).join('\n') : ''; void c; }
        FS.$('form', b).onsubmit = async (e) => { e.preventDefault(); const f = e.target; const r = await post('/api/categories/custom', { name: f.name.value.trim(), domains: f.domains.value.split(/\n|,|\s/).map(x => x.trim()).filter(Boolean) }); if (r.error) FS.toast(r.error, true); else { FS.closeModal(); FS.render(); } };
        const del = FS.$('#del', b); if (del) del.onclick = async () => { const r = await post('/api/categories/custom', { name, delete: true }); if (r.error) FS.toast(r.error, true); else { FS.closeModal(); FS.render(); } };
        void cur;
      }); };
      FS.$('#custom', el).onclick = () => edit(null); FS.$$('[data-ed]', el).forEach(b => b.onclick = () => edit(b.dataset.ed));
      FS.$('#lk', el).onsubmit = async (e) => { e.preventDefault(); const r = await get('/api/categories/lookup?domain=' + encodeURIComponent(e.target.domain.value)); FS.$('#lk-out', el).innerHTML = r.error ? `<span class="sev-high">${esc(r.error)}</span>` : (r.categories && r.categories.length ? r.categories.map(c => pill(c, 'info')).join(' ') : '<span class="muted">not in any category</span>'); };
    }
  });

  // ------------------------------------------------------------- Findings
  FS.registerPage('findings', {
    title: 'Findings', refresh: 60,
    async render(el) {
      const d = await get('/api/system/findings'); if (d.error) { el.innerHTML = FS.err(d.error); return; }
      el.innerHTML = card(`${(d.findings || []).length} open findings`, table(d.findings || [], FS.findingCols({ ack: true })), 'who sent what, where, and why; every address links to its page, every far end to the map');
      FS.$$('[data-ack]', el).forEach(b => b.onclick = async () => { await post('/api/system/findings/ack', { id: Number(b.dataset.ack) }); FS.render(); });
    }
  });

  // ------------------------------------------------------------- Events / audit
  FS.registerPage('events', {
    title: 'Events', refresh: 30,
    async render(el, ctx) {
      const kind = ctx.params.kind || '';
      const d = await get(`/api/system/events?${FS.since()}&limit=500${kind ? '&kind=' + kind : ''}`); if (d.error) { el.innerHTML = FS.err(d.error); return; }
      el.innerHTML = `<div class="actions"><div class="seg">${['', 'block', 'policy', 'audit', 'config', 'system'].map(k => `<a class="btn ${k === kind ? 'primary' : ''}" href="#events${k ? '?kind=' + k : ''}">${k || 'all'}</a>`).join('')}</div></div>` +
        card('Events', table(d.events || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Kind', f: r => pill(r.kind, r.kind === 'block' ? 'bad' : r.kind === 'audit' ? 'info' : ''), sort: 'kind' }, { t: 'Source', k: 'source' }, { t: 'Message', f: r => esc(r.message) }, { t: 'Actor', f: r => r.actor_ip ? hostLink(r.actor_ip, r.actor_name) : esc(r.actor_name || '') }, { t: 'Target', f: r => esc(r.target_domain || r.target_ip || '') }, { t: 'Policy', k: 'rule_name' }]));
    }
  });

  // ------------------------------------------------------------- System / modules
  FS.registerPage('system', {
    title: 'Status', refresh: 30,
    async render(el) {
      const [h, info, fw] = await Promise.all([get('/api/system/health'), get('/api/system/info'), get('/api/firewall/status')]);
      if (h.error) { el.innerHTML = FS.err(h.error); return; }
      const st = h.store || {};
      el.innerHTML = `<div class="grid cols-4">${kpi('Version', esc(info.version), `${esc((info.platform || {}).name)} · ${esc(info.go)}`)}${kpi('Uptime', FS.dur(info.uptime), `since ${when(info.started)}`)}${kpi('Store', bytes((st.bytes || 0) + (st.wal_bytes || 0)), `${num(st.flows)} flows · ${num(st.dns)} dns · ${num(st.alerts)} alerts`)}${kpi('Firewall', fw.available ? (fw.referenced ? 'anchored' : 'not referenced') : 'no pf', (fw.anchors || []).join(', ') || '—', fw.available && !fw.referenced ? 'bad' : '')}</div>
      <div style="margin-top:14px">${card('Modules', table(Object.entries(h.modules || {}).map(([name, m]) => ({ name, ...m })), [{ t: '', f: r => `<i class="dot ${r.ok ? 'ok' : 'bad'}"></i>`, w: '20px' }, { t: 'Module', f: r => `<a href="#modules/${esc(r.name)}"><b>${esc(r.name)}</b></a> <span class="muted small">${esc(r.version || '')}</span><div class="muted small">${esc(r.description || '')}</div>`, sort: 'name' }, { t: 'State', f: r => esc(r.detail || (r.ok ? 'ok' : 'failed')) }, { t: 'Capabilities', f: r => (r.capabilities || []).map(c => pill(c, c.endsWith('.block') || c.endsWith('.inspect') ? 'warn' : '')).join(' ') }]))}</div>
      <div class="grid cols-2" style="margin-top:14px">${card('Capabilities', `<div class="small"><b>Observe:</b> ${(h.observe_capabilities || []).map(c => pill(c)).join(' ')}</div><div class="small" style="margin-top:6px"><b>Enforce:</b> ${(h.enforce_capabilities || []).map(c => pill(c, 'warn')).join(' ') || '<span class="muted">none</span>'}</div><div class="small" style="margin-top:6px"><b>Providers:</b> ${(h.providers || []).map(p => `${esc(p.name)} (${(p.capabilities || []).join(', ')})`).join(' · ')}</div>`)}${card('Jobs', table(h.jobs || [], [{ t: 'Job', f: r => `${esc(r.module)}/${esc(r.name)}`, sort: 'name' }, { t: 'Every', f: r => FS.dur(r.every), num: true }, { t: 'Runs', k: 'runs', num: true }, { t: 'Failed', f: r => r.failures ? `<span class="sev-high">${r.failures}</span>` : '0', num: true, sort: 'failures' }, { t: 'Last', f: r => r.last_run > 0 ? ago(r.last_run) : '—', sort: 'last_run' }, { t: 'Took', f: r => (r.duration || 0).toFixed(2) + 's', num: true, sort: 'duration' }, { t: 'State', f: r => r.ok === false ? `<span class="sev-high small">${esc(r.error)}</span>` : r.running ? pill('running', 'info') : '' }, { t: '', f: r => `<button class="btn small" data-run="${esc(r.name)}" data-mod="${esc(r.module)}">Run</button>` }]))}</div>
      <div style="margin-top:14px"><a class="btn" href="#audit">Audit log</a> <a class="btn" href="/api/openapi.json" target="_blank">API reference (OpenAPI)</a></div>`;
      FS.$$('[data-run]', el).forEach(b => b.onclick = async () => { const r = await post('/api/system/jobs/run', { job: b.dataset.run, module: b.dataset.mod }); FS.toast(r.error || 'Scheduled', !!r.error); });
    }
  });

  FS.registerPage('modules', {
    title: 'Module settings', refresh: 0,
    async render(el, ctx) {
      const d = await get('/api/system/modules'); if (d.error) { el.innerHTML = FS.err(d.error); return; }
      const mods = d.modules || []; const sel = ctx.arg || (mods[0] || {}).name;
      const m = mods.find(x => x.name === sel);
      el.innerHTML = `<div class="two"><div>${m ? card(m.name, `<p class="small muted">${esc(m.description)}</p>${m.tier ? `<div class="small">${pill(FS.tierName(m.tier) + ' tier', 'warn')}</div>` : ''}${m.error ? `<div class="sev-high small">${esc(m.error)}</div>` : ''}<div class="check"><input type="checkbox" id="en" ${m.settings.enabled !== false ? 'checked' : ''}><span>Module enabled (restart to apply)</span></div>` + (m.schema && m.schema.length ? FS.settingsForm(m) : '<div class="muted small">No settings.</div>')) : FS.empty()}</div><div>${card('Modules', mods.map(x => `<div><a href="#modules/${esc(x.name)}" class="${x.name === sel ? '' : 'muted'}"><i class="dot ${x.loaded ? 'ok' : 'warn'}"></i>${esc(x.name)}</a></div>`).join(''))}</div></div>`;
      // Module-specific extras under the settings form. The qos panel carries
      // the bandwidth-test log, because that is where the link numbers are set.
      if (m && m.name === 'qos') {
        const st = await get('/api/qos/speedtests');
        const host = document.createElement('div'); host.style.marginTop = '14px';
        host.innerHTML = card('Bandwidth tests', FS.speedTestsHTML(st || {}), 'newest first; the last 50 are kept. Use writes a test\u2019s numbers into the fields above.');
        (FS.$('.two > div', el) || el).appendChild(host);
        FS.speedTestsWire(host, () => FS.render());
        if ((st || {}).running) setTimeout(() => { if (FS.parseHash().page === 'modules') FS.render(); }, 5000);
      }
      if (m && m.name === 'dns' && FS.dnsSettings) await FS.dnsSettings(el, ctx);
      if (m && m.name === 'identity') {
        const dn = await get('/api/identity/dhcp-names');
        const host = document.createElement('div'); host.style.marginTop = '14px';
        const rows = (dn && dn.entries) || [];
        host.innerHTML = card('Names sent to the DHCP server', !dn || dn.error && !rows.length ? `<div class="small">${esc((dn && dn.error) || 'unavailable')}</div>` : !dn.server ? '<div class="small muted">No dnsmasq DHCP server on this system; names stay in FlowSight.</div>'
          : `<div class="small">${dn.enabled ? `Names given in FlowSight go to <b>dnsmasq</b>, which hands each device its name with its next lease and registers it in DNS. ${dn.error ? `<span class="sev-high">${esc(dn.error)}</span>` : dn.last_run ? 'Last sent ' + FS.ago(dn.last_run) + '.' : ''}` : 'Off: turn on <i>Send device names to the DHCP server</i> above.'}</div>`
            + (rows.length ? table(rows, [{ t: 'Device', f: x => `<b>${esc(x.name)}</b><div class="muted small mono">${esc(x.ip)}</div>` }, { t: 'Hardware address', f: x => `<span class="mono small">${esc(x.mac || '—')}</span>` },
              { t: 'DHCP host name', f: x => x.label ? `<span class="mono">${esc(x.label)}</span>` : '' },
              { t: 'Status', f: x => x.status === 'sent' ? pill('sent', 'ok') : `${pill('left alone', '')}<div class="muted small">${esc(x.why || '')}</div>` }]) : '')
            + `<div class="actions"><button class="btn small" id="dhcp-now">Send now</button></div><div class="help small">FlowSight writes its own host file (<span class="mono">${esc(dn.hosts_file || '')}</span>), named by <span class="mono">${esc(dn.include || '')}</span>; names only, never addresses. A device with its own static host in OPNsense keeps that entry. A device picks its name up at its next lease renewal.</div>`, `${num(rows.filter(x => x.status === 'sent').length)} sent`);
        (FS.$('.two > div', el) || el).appendChild(host);
        const btn = FS.$('#dhcp-now', host); if (btn) btn.onclick = async () => { const r = await post('/api/identity/dhcp-names', {}); FS.toast(r.error || 'Sent to the DHCP server', !!r.error); FS.render(); };
      }
      if (m && m.name === 'pihole') {
        const note = document.createElement('div'); note.style.marginTop = '14px';
        note.innerHTML = card('Pi-hole configuration', `<div class="small">This page connects FlowSight to your Pi-holes. What the Pi-holes do (blocking, device-specific answers, upstreams, allow and deny lists) is configured on <a href="#modules/dns?tab=pihole">Settings › dns › Pi-hole</a>.</div>`);
        (FS.$('.two > div', el) || el).appendChild(note);
      }
      const form = FS.$('form.f:not(.ph-add):not(.ph-set):not(.nm-form)', el);
      const save = async (extra) => { const settings = form ? FS.readForm(form, m.schema) : {}; Object.assign(settings, extra || {}); const r = await post('/api/system/modules/save', { module: m.name, settings }); if (r.error) FS.toast(r.error, true); else FS.toast('Saved' + (r.note ? ' — ' + r.note : '')); };
      if (form) form.onsubmit = (e) => { e.preventDefault(); save(); };
      const en = FS.$('#en', el); if (en) en.onchange = () => save({ enabled: en.checked });
    }
  });

  FS.registerPage('audit', {
    title: 'Audit log', refresh: 0,
    async render(el) {
      const [a, c] = await Promise.all([get('/api/system/audit?limit=300'), get('/api/system/changes?limit=200')]);
      el.innerHTML = `<div class="grid cols-2">${card('Write operations', table((a.events || []).map(r => { let at = {}; try { at = typeof r.attrs === 'string' ? JSON.parse(r.attrs) : (r.attrs || {}); } catch (e) {} return Object.assign({}, r, { _at: at }); }), [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Who', f: r => `<b>${esc(r.actor_name)}</b>`, sort: 'actor_name' }, { t: 'Via', f: r => r._at.via ? pill(r._at.via, r._at.via === 'gui' ? 'info' : '') : '', sort: 'actor_name' }, { t: 'From', f: r => esc(r.actor_ip) }, { t: 'Operation', f: r => `<span class="mono small">${esc(r.message)}</span>${['module', 'name', 'id', 'definition', 'policy'].filter(k => r._at[k]).map(k => ` <span class="pill">${esc(k)}: ${esc(r._at[k])}</span>`).join('')}${r._at.keys ? `<div class="muted small">fields: ${esc(r._at.keys)}</div>` : ''}` }]))}${card('Configuration changes', table(c.changes || [], [{ t: 'When', f: r => when(r.ts), sort: 'ts' }, { t: 'Subject', f: r => `<b>${esc(r.subject)}</b><div class="muted small">${esc(r.summary || '')}</div>` }, { t: 'By', k: 'actor' }, { t: '', f: r => r.diff_bytes ? `<button class="btn small" data-diff="${r.id}">diff</button>` : '' }]))}</div>`;
      FS.$$('[data-diff]', el).forEach(b => b.onclick = async () => { const r = await get('/api/system/changes?id=' + b.dataset.diff); FS.modal(`<h2>${esc((r.change || {}).subject || 'change')}</h2><pre class="code">${FS.diffHtml((r.change || {}).diff || '')}</pre><div class="actions"><button class="btn" data-close>Close</button></div>`); });
    }
  });
})();

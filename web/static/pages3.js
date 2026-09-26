/* FlowSight pages: the Firewall Analysis Engine, alerting, reports, updates, devices & zones. */
'use strict';
(function () {
  const { esc, num, bytes, ago, when, pill, card, kpi, table, bars, hostLink, domainLink, get, post } = FS;

  // ------------------------------------------------------------- Firewall Analysis Engine (FAE)
  FS.registerPage('firewall', {
    title: 'Firewall Analysis Engine (FAE)', refresh: 60,
    async render(el, ctx) {
      const [s, r, f, c] = await Promise.all([get('/api/rulehygiene/summary'), get('/api/rulehygiene/rules'), get('/api/rulehygiene/findings'), get('/api/rulehygiene/changes')]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const sev = s.by_severity || {};
      const score = Number(s.risk_score || 0);
      const kind = score >= 50 ? 'bad' : score >= 20 ? 'warn' : 'ok';
      const rules = r.rules || [];
      const findings = f.findings || [];
      el.innerHTML = `<div class="grid cols-4">${kpi('Risk score', score, 'lower is better; weighted open findings', kind)}${kpi('Rules analysed', num(s.rules_analysed), s.ruleset_loaded ? 'ruleset loaded ' + esc(s.ruleset_loaded) : '')}${kpi('Findings', num(findings.length), `${num(sev.critical || 0)} critical · ${num(sev.high || 0)} high · ${num(sev.medium || 0)} medium`, sev.critical ? 'bad' : sev.high ? 'warn' : '')}${card('Analysis', `<div class="small muted">Last run ${esc(s.last_run || 'never')}. Findings are grounded in live pf counters, so "unused" means never matched since the ruleset was loaded, not merely quiet today.</div><div class="actions"><button class="btn primary" id="run">Analyse now</button></div>`)}</div>
      <div style="margin-top:14px">${card('Findings', table(findings, [{ t: 'Severity', f: x => FS.sevPill(x.severity), sort: 'severity' }, { t: 'Kind', f: x => pill(x.kind), sort: 'kind' }, { t: 'Finding', f: x => `<b>${esc(x.title)}</b><div class="muted small">${esc(x.detail || '')}</div>` }, { t: 'Rule', f: x => `<span class="mono small">${esc(x.subject || '')}</span>` }, { t: 'Since', f: x => ago(x.ts), sort: 'ts' }]))}</div>
      <div style="margin-top:14px">${card('Rules with live counters', table(rules, [{ t: '#', f: x => x.index != null ? x.index : '', num: true, sort: 'index' }, { t: 'Rule', f: x => `<span class="mono small">${esc(x.rule || x.text || '')}</span>${x.description ? `<div class="small">${esc(x.description)}</div>` : ''}`, sort: 'rule' }, { t: 'Interface', k: 'interface' }, { t: 'Evaluations', f: x => num(x.evaluations), num: true, sort: 'evaluations' }, { t: 'Packets', f: x => num(x.packets), num: true, sort: 'packets' }, { t: 'Bytes', f: x => bytes(x.bytes), num: true, sort: 'bytes' }, { t: 'States', f: x => num(x.states), num: true, sort: 'states' }, { t: 'Findings', f: x => (x.findings || []).map(k => pill(k, 'warn')).join(' ') }]))}</div>
      <div style="margin-top:14px">${card('Ruleset changes', table(c.changes || [], [{ t: 'When', f: x => when(x.ts), sort: 'ts' }, { t: 'By', k: 'actor' }, { t: 'Summary', f: x => esc(x.summary || '') }, { t: '', f: x => x.diff_bytes ? `<button class="btn small" data-diff="${x.id}">diff</button>` : '' }]))}</div>`;
      FS.$('#run', el).onclick = async () => { const x = await post('/api/rulehygiene/run', {}); FS.toast(x.error || 'Analysis started', !!x.error); setTimeout(FS.render, 3000); };
      FS.$$('[data-diff]', el).forEach(b => b.onclick = async () => { const x = await get('/api/system/changes?id=' + b.dataset.diff); FS.modal(`<h2>${esc((x.change || {}).subject || 'change')}</h2><pre class="code">${FS.diffHtml((x.change || {}).diff || '')}</pre><div class="actions"><button class="btn" data-close>Close</button></div>`); });
    }
  });

  // ------------------------------------------------------------- Alerting
  FS.registerPage('alerts', {
    title: 'Alerting', refresh: 60,
    async render(el) {
      // Fetch all data in parallel
      const [chTypes, chList, rulesList, deliveries, maint] = await Promise.all([
        get('/api/alerting/channel-types'),
        get('/api/alerting/channels'),
        get('/api/alerting/rules'),
        get('/api/alerting/deliveries'),
        get('/api/alerting/maintenance')
      ]);

      if (chTypes.error) { el.innerHTML = FS.err(chTypes.error); return; }

      const channelTypes = chTypes.channel_types || {};
      const channels = chList.channels || [];
      const rules = rulesList.rules || {};
      const logs = Array.isArray(deliveries.deliveries) ? deliveries.deliveries : Object.values(deliveries.deliveries || {}).flat();
      const maintenance = maint || {};

      // Build HTML
      el.innerHTML = `
        <div class="grid cols-2">
          ${card('Channels', `<div class="actions"><button class="btn primary" id="ch-add" data-action="add">Add channel</button></div>` +
            table(channels, [
              { t: 'Name', f: x => `<b>${esc(x.name)}</b><div class="muted small">${esc(x.type)}</div>` },
              { t: 'Status', f: x => x.enabled ? pill('enabled', 'ok') : pill('disabled', 'warn') },
              { t: 'Last status', f: x => '' }, // Will show last delivery status
              { t: '', f: x => `<button class="btn small" data-test="${esc(x.name)}">Test</button> <button class="btn small" data-edit="${esc(x.name)}">Edit</button> <button class="btn small danger" data-del="${esc(x.name)}">Delete</button>` }
            ], { empty: 'No channels configured yet.' })
          )}
          ${card('Maintenance', `<div class="small muted">${maintenance.enabled ? `Maintenance mode active until ${esc(maintenance.until || 'indefinitely')}. ${esc(maintenance.reason || '')}` : 'Maintenance mode is off.'}</div><div class="actions"><button class="btn ${maintenance.enabled ? 'danger' : 'primary'}" id="maint-toggle">${maintenance.enabled ? 'Disable' : 'Enable'} maintenance</button></div>`)}
        </div>
        <div style="margin-top:14px">
          ${card('Rules', `<div class="actions"><button class="btn primary" id="rule-add">New rule</button></div>` +
            table(Object.entries(rules).map(([id, r]) => ({...r, id})), [
              { t: 'Enabled', f: x => `<input type="checkbox" data-rule-id="${esc(x.id)}" ${x.enabled ? 'checked' : ''}>` },
              { t: 'Rule', f: x => `<b>${esc(x.name)}</b><div class="muted small">Severity: ${x.severity} · Module: ${esc(x.module || 'any')}</div>` },
              { t: 'Channels', f: x => (x.channels || []).length ? x.channels.map(c => pill(c)).join(' ') : '<span class="muted">none</span>' },
              { t: '', f: x => `<button class="btn small" data-rule-edit="${esc(x.id)}">Edit</button> <button class="btn small danger" data-rule-del="${esc(x.id)}">Delete</button>` }
            ], { empty: 'No rules yet.' })
          )}
        </div>
        <div style="margin-top:14px">
          ${card('Actions', `<div class="actions"><button class="btn" id="sim-alert">Simulate alert</button> <button class="btn" id="import-apprise">Import Apprise URL</button></div>`)}
        </div>
        <div style="margin-top:14px">
          ${card('Recent deliveries', table(logs.slice(0, 20), [
            { t: 'When', f: x => when(x.timestamp), sort: 'timestamp' },
            { t: 'Channel', k: 'channel_id' },
            { t: 'Title', f: x => esc(x.title || '') },
            { t: 'Status', f: x => x.success ? pill('sent', 'ok') : pill('failed', 'bad') },
            { t: 'Latency', f: x => x.latency_ms ? (x.latency_ms + 'ms') : '-' }
          ], { empty: 'No deliveries yet.' }))}
        </div>
      `;

      // Handler: Add channel
      FS.$('#ch-add', el).onclick = () => showChannelModal(null, channelTypes, channels);

      // Handlers: Edit channel
      FS.$$('[data-edit]', el).forEach(b => {
        b.onclick = () => {
          const ch = channels.find(x => x.name === b.dataset.edit);
          showChannelModal(ch, channelTypes, channels);
        };
      });

      // Handlers: Delete channel
      FS.$$('[data-del]', el).forEach(b => {
        b.onclick = async () => {
          if (!await FS.confirm(`Delete channel "${b.dataset.del}"?`)) return;
          const r = await post(`/api/alerting/channels/${b.dataset.del}`, {});
          if (r.error) FS.toast(r.error, true);
          else { FS.toast('Channel deleted'); FS.render(); }
        };
      });

      // Handlers: Test channel
      FS.$$('[data-test]', el).forEach(b => {
        b.onclick = async () => {
          const r = await post(`/api/alerting/channels/${b.dataset.test}/test`, {});
          FS.toast(r.error || 'Test sent', !!r.error);
        };
      });

      // Handler: Maintenance toggle
      FS.$('#maint-toggle', el).onclick = async () => {
        const enabled = !maintenance.enabled;
        const r = await post('/api/alerting/maintenance', { enabled, minutes: enabled ? 60 : undefined });
        if (r.error) FS.toast(r.error, true);
        else { FS.toast(enabled ? 'Maintenance enabled' : 'Maintenance disabled'); FS.render(); }
      };

      // Handler: Simulate alert
      FS.$('#sim-alert', el).onclick = () => {
        FS.modal(`<h2>Simulate alert</h2><form class="f">
          <label>Severity</label>
          <select name="severity">
            <option>critical</option>
            <option>high</option>
            <option selected>medium</option>
            <option>low</option>
            <option>info</option>
          </select>
          <label>Title</label>
          <input type="text" name="title" value="Test Alert" required>
          <label>Message</label>
          <textarea name="text" placeholder="Optional message">This is a test alert</textarea>
          <div class="actions">
            <button class="btn primary">Send</button>
            <button type="button" class="btn" data-close>Cancel</button>
          </div>
        </form>`, b => {
          FS.$('form', b).onsubmit = async e => {
            e.preventDefault();
            const f = e.target;
            const r = await post('/api/alerting/simulate', {
              severity: f.severity.value,
              title: f.title.value,
              text: f.text.value
            });
            if (r.error) FS.toast(r.error, true);
            else { FS.toast('Alerts sent to enabled channels'); FS.closeModal(); }
          };
          FS.$$('[data-close]', b).forEach(btn => btn.onclick = () => FS.closeModal());
        });
      };

      // Handler: Import Apprise
      FS.$('#import-apprise', el).onclick = () => {
        FS.modal(`<h2>Import Apprise URL</h2><form class="f">
          <label>Apprise URL</label>
          <input type="text" name="apprise_url" placeholder="slack://..., discord://..., tgram://... etc" required>
          <div class="actions">
            <button class="btn primary">Import</button>
            <button type="button" class="btn" data-close>Cancel</button>
          </div>
        </form>`, b => {
          FS.$('form', b).onsubmit = async e => {
            e.preventDefault();
            const f = e.target;
            const r = await post('/api/alerting/import-apprise', { url: f.apprise_url.value });
            if (r.error) FS.toast(r.error, true);
            else { FS.toast('Channel imported'); FS.closeModal(); FS.render(); }
          };
          FS.$$('[data-close]', b).forEach(btn => btn.onclick = () => FS.closeModal());
        });
      };

      // Handler: Rule enable/disable
      FS.$$('[data-rule-id]', el).forEach(cb => {
        cb.onchange = async () => {
          const id = cb.dataset.ruleId;
          const rule = rules[id];
          if (!rule) return;
          rule.enabled = cb.checked;
          const r = await FS.api(`/api/alerting/rules/${id}`, { method: 'PUT', body: rule });
          if (r.error) { FS.toast(r.error, true); cb.checked = !cb.checked; }
        };
      });

      // Handler: Edit rule
      FS.$$('[data-rule-edit]', el).forEach(b => {
        b.onclick = () => {
          const id = b.dataset.ruleEdit;
          const rule = rules[id];
          if (!rule) return;
          showRuleModal(id, rule);
        };
      });

      // Handler: Delete rule
      FS.$$('[data-rule-del]', el).forEach(b => {
        b.onclick = async () => {
          if (!await FS.confirm(`Delete rule?`)) return;
          const id = b.dataset.ruleDel;
          const r = await FS.api(`/api/alerting/rules/${id}`, { method: 'DELETE', body: {} });
          if (r.error) FS.toast(r.error, true);
          else { FS.toast('Rule deleted'); FS.render(); }
        };
      });

      // Handler: New rule
      FS.$('#rule-add', el).onclick = () => {
        showRuleModal(null, {
          id: 'rule-' + Date.now(),
          name: 'New rule',
          enabled: true,
          severity: 'medium',
          module: '',
          category: '',
          device: '',
          zone: '',
          channels: [],
          cooldown: 300,
          digest_minutes: 0
        });
      };
    }
  });

  // Modal for adding/editing channels
  function showChannelModal(channel, channelTypes, allChannels) {
    let selectedType = channel ? channel.type : Object.keys(channelTypes)[0];
    const getTypeSchema = (type) => {
      for (const family in channelTypes) {
        const types = channelTypes[family];
        for (const t of types) {
          if (t.type === type) return t;
        }
      }
      return { schema: [] };
    };

    const renderForm = (type) => {
      const typeInfo = getTypeSchema(type);
      const schema = typeInfo.schema || [];
      const value = channel ? channel.config || {} : {};
      return schema.map(field => {
        const val = value[field.key] || '';
        const inputType = field.type === 'password' ? 'password' : 'text';
        return `<label>${esc(field.label)} ${field.required ? '*' : ''}</label>
          <input type="${inputType}" name="${field.key}" value="${esc(val)}" ${field.required ? 'required' : ''} placeholder="${esc(field.help || '')}">
        `;
      }).join('');
    };

    FS.modal(`<h2>${channel ? 'Edit' : 'Add'} channel</h2><form class="f">
      <label>Name *</label>
      <input type="text" name="name" value="${esc(channel?.name || '')}" required>
      <label>Type *</label>
      <select name="type" id="ch-type">
        ${Object.entries(channelTypes).map(([family, types]) =>
          `<optgroup label="${esc(family)}">${types.map(t =>
            `<option value="${t.type}" ${t.type === selectedType ? 'selected' : ''}>${esc(t.label)}</option>`
          ).join('')}</optgroup>`
        ).join('')}
      </select>
      <div id="schema">${renderForm(selectedType)}</div>
      <div class="actions">
        <button class="btn primary">Save</button>
        <button type="button" class="btn" data-close>Cancel</button>
      </div>
    </form>`, modal => {
      const typeSelect = FS.$('#ch-type', modal);
      typeSelect.onchange = () => {
        selectedType = typeSelect.value;
        FS.$('#schema', modal).innerHTML = renderForm(selectedType);
      };

      FS.$('form', modal).onsubmit = async e => {
        e.preventDefault();
        const f = e.target;
        const config = {};
        const typeInfo = getTypeSchema(f.type.value);
        (typeInfo.schema || []).forEach(field => {
          const inp = FS.$(`input[name="${field.key}"], textarea[name="${field.key}"], select[name="${field.key}"]`, modal);
          if (inp) config[field.key] = inp.value;
        });

        const data = {
          name: f.name.value.trim(),
          type: f.type.value,
          enabled: true,
          config
        };

        const url = channel ? `/api/alerting/channels/${channel.name}` : '/api/alerting/channels';
        const method = channel ? 'PUT' : 'POST';
        const r = method === 'POST'
          ? await post(url, data)
          : await post(url, data); // Need to handle PUT properly

        if (r.error) FS.toast(r.error, true);
        else { FS.toast(channel ? 'Channel updated' : 'Channel created'); FS.closeModal(); FS.render(); }
      };

      FS.$$('[data-close]', modal).forEach(btn => btn.onclick = () => FS.closeModal());
    });
  }

  // Modal for adding/editing rules
  function showRuleModal(id, rule) {
    FS.modal(`<h2>${id ? 'Edit' : 'New'} rule</h2><form class="f">
      <label>Name *</label>
      <input type="text" name="name" value="${esc(rule.name)}" required>
      <label>Severity (trigger at or above) *</label>
      <select name="severity">
        <option ${rule.severity === 'critical' ? 'selected' : ''}>critical</option>
        <option ${rule.severity === 'high' ? 'selected' : ''}>high</option>
        <option ${rule.severity === 'medium' ? 'selected' : ''}>medium</option>
        <option ${rule.severity === 'low' ? 'selected' : ''}>low</option>
        <option ${rule.severity === 'info' ? 'selected' : ''}>info</option>
      </select>
      <label>Module (leave blank for all)</label>
      <input type="text" name="module" value="${esc(rule.module || '')}">
      <label>Category (leave blank for all)</label>
      <input type="text" name="category" value="${esc(rule.category || '')}">
      <label>Device IP/MAC (leave blank for all)</label>
      <input type="text" name="device" value="${esc(rule.device || '')}">
      <label>Zone (leave blank for all)</label>
      <input type="text" name="zone" value="${esc(rule.zone || '')}">
      <label>Channels (comma-separated)</label>
      <input type="text" name="channels" value="${esc((rule.channels || []).join(', '))}">
      <label>Cooldown (seconds)</label>
      <input type="number" name="cooldown" value="${rule.cooldown || 300}" min="0">
      <label>Digest minutes (0 = no digest, bundle alerts if > 0)</label>
      <input type="number" name="digest_minutes" value="${rule.digest_minutes || 0}" min="0">
      <div class="actions">
        <button class="btn primary">Save</button>
        <button type="button" class="btn" data-close>Cancel</button>
      </div>
    </form>`, modal => {
      FS.$('form', modal).onsubmit = async e => {
        e.preventDefault();
        const f = e.target;
        const updated = {
          id: id || `rule-${Date.now()}`,
          name: f.name.value.trim(),
          enabled: true,
          severity: f.severity.value,
          module: f.module.value.trim(),
          category: f.category.value.trim(),
          device: f.device.value.trim(),
          zone: f.zone.value.trim(),
          channels: f.channels.value.split(',').map(x => x.trim()).filter(Boolean),
          cooldown: Number(f.cooldown.value),
          digest_minutes: Number(f.digest_minutes.value)
        };

        const url = id ? `/api/alerting/rules/${id}` : '/api/alerting/rules';
        const r = await post(url, updated);
        if (r.error) FS.toast(r.error, true);
        else { FS.toast(id ? 'Rule updated' : 'Rule created'); FS.closeModal(); FS.render(); }
      };

      FS.$$('[data-close]', modal).forEach(btn => btn.onclick = () => FS.closeModal());
    });
  }

  // ------------------------------------------------------------- Reports
  FS.registerPage('reports', {
    title: 'Reports', refresh: 0,
    async render(el) {
      const defs = await get('/api/reports/definitions'); if (defs.error) { el.innerHTML = FS.err(defs.error); return; }
      const runs = await get('/api/reports/runs'); if (runs.error) { el.innerHTML = FS.err(runs.error); return; }
      const channels = await get('/api/alerting/channels');
      const definitions = defs.definitions || [];
      const runsList = runs.runs || [];
      const channelList = (channels.channels || []).map(c => c.name);

      const allSections = ['executive_summary', 'traffic_by_device', 'traffic_by_zone', 'traffic_by_app', 'traffic_by_category', 'traffic_by_site', 'blocked_activity', 'egress_activity', 'dns_summary', 'scan_findings', 'tls_posture', 'device_inventory', 'alerting_deliveries', 'system_health', 'alerts'];
      const sectionLabels = { executive_summary: 'Executive Summary', traffic_by_device: 'Traffic by Device', traffic_by_zone: 'Traffic by Zone', traffic_by_app: 'Traffic by Application', traffic_by_category: 'Traffic by Category', traffic_by_site: 'Traffic by Site', blocked_activity: 'Blocked Activity', egress_activity: 'Egress Activity & DLP', dns_summary: 'DNS Summary', scan_findings: 'Scan Findings', tls_posture: 'TLS Posture', device_inventory: 'Device Inventory', alerting_deliveries: 'Alerting Deliveries', system_health: 'System Health', alerts: 'Security Alerts' };

      el.innerHTML = `<div class="grid cols-1">
        ${card('Report Definitions', `<div class="actions"><button class="btn primary" id="new-def">New Definition</button></div>` + table(definitions, [{ t: 'Name', f: x => `<b>${esc(x.name)}</b>${x.read_only ? ' ' + pill('built-in', 'info') : ''}` }, { t: 'Sections', f: x => x.sections.length + ' selected' }, { t: 'Schedule', f: x => x.schedule && x.schedule.enabled ? esc(x.schedule.cadence + ' at ' + x.schedule.time_utc) : 'not scheduled' }, { t: '', f: x => `<button class="btn small" data-run="${esc(x.id)}">Run now</button> ${x.read_only ? '<button class="btn small" data-dup="${esc(x.id)}">Duplicate</button>' : `<button class="btn small" data-edit="${esc(x.id)}">Edit</button> <button class="btn small danger" data-del="${esc(x.id)}">Delete</button>`}` }], { empty: 'No definitions yet.' }))}
      </div>
      <div style="margin-top:14px">${card('Recent Runs', table(runsList.slice(0, 20), [{ t: 'Definition', k: 'definition' }, { t: 'Status', f: x => pill(x.status, x.status === 'done' ? 'ok' : x.status === 'failed' ? 'bad' : 'info') }, { t: 'Started', f: x => when(x.started_at), sort: 'started_at' }, { t: 'Size', f: x => bytes(Object.values(x.sizes || {}).reduce((a,b)=>a+b,0)) }, { t: 'Formats', f: x => (x.formats || []).map(f => pill(f, 'info')).join(' ') }, { t: '', f: x => x.formats.map(f => `<a class="btn small" href="/api/reports/runs/${esc(x.id)}/download?format=${f}">${f}</a>`).join(' ') }], { empty: 'No runs yet.' }))}
      </div>`;

      const editDef = (id) => {
        const def = definitions.find(x => x.id === id) || { name: '', sections: [], filters: {}, formats: ['html'], schedule: { enabled: false, cadence: 'daily', time_utc: '09:00' }, recipients: [] };
        const sections_html = allSections.map(s => `<label><input type="checkbox" name="section" value="${s}" ${def.sections.includes(s) ? 'checked' : ''}> ${esc(sectionLabels[s] || s)}</label>`).join('<br>');
        const modal_html = `<h2>${id ? 'Edit Definition' : 'New Definition'}</h2>
          <form class="f">
            <label>Name</label><input type="text" name="name" value="${esc(def.name)}" required>
            <label>Sections (select one or more)</label><div style="border:1px solid #ccc;padding:10px;max-height:150px;overflow-y:auto">${sections_html}</div>
            <label>Formats</label><div><label><input type="checkbox" name="format" value="html" ${def.formats.includes('html') ? 'checked' : ''}> HTML</label><label><input type="checkbox" name="format" value="pdf" ${def.formats.includes('pdf') ? 'checked' : ''}> PDF</label><label><input type="checkbox" name="format" value="markdown" ${def.formats.includes('markdown') ? 'checked' : ''}> Markdown</label><label><input type="checkbox" name="format" value="json" ${def.formats.includes('json') ? 'checked' : ''}> JSON</label><label><input type="checkbox" name="format" value="csv" ${def.formats.includes('csv') ? 'checked' : ''}> CSV</label></div>
            <div class="row"><div><label>Cadence</label><select name="cadence"><option ${def.schedule.cadence === 'hourly' ? 'selected' : ''}>hourly</option><option ${def.schedule.cadence === 'daily' ? 'selected' : ''}>daily</option><option ${def.schedule.cadence === 'weekly' ? 'selected' : ''}>weekly</option><option ${def.schedule.cadence === 'monthly' ? 'selected' : ''}>monthly</option></select></div><div><label>Time (HH:MM UTC)</label><input type="text" name="time" value="${def.schedule.time_utc}" placeholder="09:00"></div></div>
            <label>Delivery channels</label><div>${channelList.map(c => `<label><input type="checkbox" name="recipient" value="${c}" ${def.recipients.includes(c) ? 'checked' : ''}> ${esc(c)}</label>`).join('<br>')}</div>
            <label><input type="checkbox" name="enabled" ${def.schedule.enabled ? 'checked' : ''}> Enable scheduling</label>
            <div class="actions"><button class="btn primary">Save</button><button type="button" class="btn" data-close>Cancel</button></div>
          </form>`;
        FS.modal(modal_html, (b) => {
          FS.$('form', b).onsubmit = async (e) => {
            e.preventDefault();
            const f = e.target;
            const sections = Array.from(FS.$$('[name="section"]', b)).filter(x => x.checked).map(x => x.value);
            const formats = Array.from(FS.$$('[name="format"]', b)).filter(x => x.checked).map(x => x.value);
            const recipients = Array.from(FS.$$('[name="recipient"]', b)).filter(x => x.checked).map(x => x.value);
            const d = { name: f.name.value, sections, formats, schedule: { enabled: FS.$('[name="enabled"]', b).checked, cadence: f.cadence.value, time_utc: f.time.value, timezone: 'UTC' }, recipients };
            if (id) { d.id = id; }
            const r = await post('/api/reports/definitions' + (id ? '/' + id : ''), d);
            if (r.error) FS.toast(r.error, true);
            else { FS.closeModal(); FS.render(); }
          };
        });
      };

      FS.$('#new-def', el).onclick = () => editDef(null);
      FS.$$('[data-edit]', el).forEach(b => b.onclick = () => editDef(b.dataset.edit));
      FS.$$('[data-dup]', el).forEach(b => b.onclick = async () => { const d = definitions.find(x => x.id === b.dataset.dup); if (d) { d.id = undefined; d.read_only = false; editDef(null); } });
      FS.$$('[data-del]', el).forEach(b => b.onclick = async () => { if (!await FS.confirm('Delete this definition?')) return; const r = await post('/api/reports/definitions/' + b.dataset.del, {}, 'DELETE'); if (r.error) FS.toast(r.error, true); else FS.render(); });
      FS.$$('[data-run]', el).forEach(b => b.onclick = async () => { const r = await post('/api/reports/run/' + b.dataset.run, {}); if (r.error) FS.toast(r.error, true); else { FS.toast('Report generated'); setTimeout(FS.render, 2000); } });
    }
  });

  // ------------------------------------------------------------- Updates
  FS.registerPage('updates', {
    title: 'Updates', refresh: 0,
    async render(el) {
      const d = await get('/api/updater/status'); if (d.error) { el.innerHTML = FS.err(d.error); return; }
      el.innerHTML = `<div class="grid cols-3">${kpi('Installed', esc(d.current_version), d.last_check > 0 ? 'checked ' + ago(d.last_check) : 'not checked yet')}${kpi('Latest', esc(d.latest_version || '—'), d.available ? (d.applicable ? 'update available' : 'available but not verifiable') : 'up to date', d.available ? 'warn' : 'ok')}${card('Actions', `<div class="actions"><button class="btn" id="check">Check now</button><button class="btn primary" id="apply" ${d.applicable ? '' : 'disabled'}>Install update</button><button class="btn" id="rollback">Roll back</button></div><div class="help">Updates are downloaded from the release manifest, verified by checksum and signature, swapped in atomically and the service restarted. The previous binary is kept for roll back.</div>`)}</div>
      ${d.notes ? `<div style="margin-top:14px">${card('Release notes', `<pre class="code">${esc(d.notes)}</pre>`)}</div>` : ''}${d.error ? `<div style="margin-top:14px">${card('Last error', `<div class="sev-high small">${esc(d.error)}</div>`)}</div>` : ''}`;
      FS.$('#check', el).onclick = async () => { const r = await post('/api/updater/check', {}); FS.toast(r.error || 'Checked', !!r.error); FS.render(); };
      FS.$('#apply', el).onclick = async () => { if (!await FS.confirm('Install the update and restart FlowSight?')) return; const r = await post('/api/updater/apply', {}); FS.toast(r.error || 'Updating… the service will restart', !!r.error); };
      FS.$('#rollback', el).onclick = async () => { if (!await FS.confirm('Roll back to the previous binary and restart?')) return; const r = await post('/api/updater/rollback', {}); FS.toast(r.error || 'Rolling back…', !!r.error); };
    }
  });

  // ------------------------------------------------------------- Devices (enrolment)
  // Every [data-identify] button runs the fast scan profile against that
  // address and re-renders when the result lands. Shared by the Devices
  // page and the zone screens.
  const identifyBtn = (x) => x.ip ? `<button class="btn small" data-identify="${esc(x.ip)}" title="Probe this device to find out what it is">Identify</button>` : '';
  const wireIdentify = (el) => FS.$$('[data-identify]', el).forEach(b => b.onclick = async () => {
    const ip = b.dataset.identify; b.disabled = true; b.textContent = 'Identifying\u2026';
    const scan = await post('/api/scan/start', { ip, profile: 'identify' });
    if (scan.error) { FS.toast(scan.error.includes('disabled') ? 'Scanning disabled: Settings \u203a Scan to enable it' : scan.error, true); b.disabled = false; b.textContent = 'Identify'; return; }
    FS.toast('Identifying ' + ip + '\u2026');
    let result; for (let i = 0; i < 60; i++) { await new Promise(r => setTimeout(r, 3000)); result = await get('/api/scan/result?ip=' + ip); if (result && !result.error && result.finished) break; }
    if (result && !result.error) FS.render();
  });
  // Shared loader: devices, zones and rules come from the enroll module; the
  // two pages cross-link on the zone id.
  const enrollLoad = async (zoneFilter) => {
    const [s, dv, z, ru] = await Promise.all([get('/api/enroll'), get('/api/enroll/devices' + (zoneFilter ? '?zone=' + encodeURIComponent(zoneFilter) : '')), get('/api/enroll/zones'), get('/api/enroll/rules')]);
    const zones = ((z && z.zones) || ((z && z.document) || {}).zones || []);
    const devices = (dv && dv.devices) || [];
    const mode = (s && s.mode) || (z && z.mode) || 'monitor';
    return { s, dv, z, ru, zones, devices, mode };
  };
  const zoneName = (zones, id) => { const zz = zones.find(x => x.id === id); return zz ? (zz.name || zz.id) : (id || ''); };
  const modeControls = (mode, el) => {
    FS.$('#mode', el).onclick = async () => { const next = mode === 'enforce' ? 'monitor' : 'enforce'; if (next === 'enforce' && !await FS.confirm('Enforce mode writes DHCP reservations and firewall isolation. Devices present now stay where they are; only new devices are placed. Continue?')) return; const r = await post('/api/enroll/mode', { mode: next }); FS.toast(r.error || 'Mode: ' + next, !!r.error); FS.render(); };
  };

  FS.registerPage('devices', {
    title: 'Devices', refresh: 30,
    async render(el, ctx) {
      const [{ s, zones, devices, mode }, sv] = await Promise.all([enrollLoad(ctx.params.zone), get('/api/enroll/services')]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const svc = (sv && sv.services) || {};
      const svcCell = (x) => {
        const v = svc[x.mac]; if (!v) return '<span class="muted small">quiet</span>';
        const uses = (v.uses || []).slice(0, 5).map(u => `<span title="${bytes(u.bytes)} in the last day">${esc(u.name)}</span>`).join(', ');
        const offers = (v.offers || []).slice(0, 5).map(o => `<span class="mono" title="${num(o.flows)} connections from ${num(o.clients)} local host${o.clients === 1 ? '' : 's'}">${esc(o.name || (o.proto + '/' + o.port))}</span> <span class="muted">(${num(o.clients)})</span>`).join(', ');
        return `${uses ? `<div class="small"><span class="muted">uses</span> ${uses}</div>` : ''}${offers ? `<div class="small"><span class="muted">offers</span> ${offers}</div>` : ''}` || '<span class="muted small">quiet</span>';
      };
      const zoneOpts = (cur) => `<option value="">—</option>` + zones.map(x => `<option value="${esc(x.id)}" ${x.id === cur ? 'selected' : ''}>${esc(x.name || x.id)}</option>`).join('');
      const byZone = {}; devices.forEach(d => { byZone[d.zone || ''] = (byZone[d.zone || ''] || 0) + 1; });
      const unplaced = byZone[''] || 0;
      el.innerHTML = `<div class="grid cols-4">${kpi('Mode', mode === 'enforce' ? 'enforcing' : 'monitor', mode === 'enforce' ? 'placement and isolation are applied' : 'classifying only; nothing is written', mode === 'enforce' ? 'warn' : '')}${kpi('Devices', num(devices.length), `${num(s.unidentified || 0)} unidentified · ${num(unplaced)} without a zone · ${num(devices.filter(d => d.excluded).length)} excluded from inspection`)}${kpi('Zones', num(zones.length), zones.map(x => `<a href="#zones?zone=${esc(x.id)}">${esc(x.id)}</a> ${num(byZone[x.id] || 0)}`).join(' · ') || 'none defined')}${card('Actions', `<div class="actions"><button class="btn" id="reconcile">Re-identify</button><a class="btn" href="#zones">Zones &amp; placement</a><button class="btn ${mode === 'enforce' ? 'danger' : ''}" id="mode">${mode === 'enforce' ? 'Switch to monitor' : 'Switch to enforce'}</button></div>`)}</div>
      <div style="margin-top:14px">${card('Devices' + (ctx.params.zone ? ` in zone ${esc(zoneName(zones, ctx.params.zone))}` : ''), table(devices, [{ t: 'Device', f: x => `<b>${esc(x.hostname || x.guest_name || x.mac)}</b>${x.excluded ? ` <span title="excluded from interception, inspection and policy by the entry ${esc(x.excluded_by)} under Policy › Exclusions">${pill('not inspected', 'warn')}</span>` : ''}<div class="muted small mono">${esc(x.mac)}${x.randomized ? ' · private MAC' : ''}</div>${x.proxmox ? `<div class="muted small">Proxmox: ${esc(x.proxmox.name)} (${x.proxmox.type} ${x.proxmox.vmid} on ${esc(x.proxmox.node)})</div>` : ''}`, sort: 'hostname' }, { t: 'Address', f: x => (x.ip ? FS.hostLink(x.ip) : '') + (x.ip6 ? `<div class="muted small mono">${esc(x.ip6)}</div>` : ''), sort: 'ip' }, { t: 'Services', f: svcCell }, { t: 'Vendor', f: x => esc(x.vendor || '') + (x.vendor_class ? `<div class="muted small">${esc(x.vendor_class)}</div>` : ''), sort: 'vendor' }, { t: 'Class', f: x => esc(x.class || ''), sort: 'class' }, { t: 'Zone', f: x => `<select data-mac="${esc(x.mac)}">${zoneOpts(x.zone)}</select>${x.zone ? ` <a class="small" href="#zones?zone=${esc(x.zone)}">view</a>` : ''}${x.pinned ? ' ' + pill('pinned', '') : ''}`, sort: 'zone' }, { t: 'Why', f: x => `<span class="small muted">${esc(x.why || x.rule || '')}</span>` }, { t: 'Seen', f: x => ago(x.last_seen), sort: 'last_seen' }, { t: '', f: x => `<button class="btn small" data-identify="${esc(x.ip || x.mac)}">Identify</button>` }]), ctx.params.zone ? `<a href="#devices">all devices</a>` : zones.map(x => `<a href="#devices?zone=${esc(x.id)}">${esc(x.id)}</a>`).join(' · '))}</div>
      <div class="help" style="margin-top:8px"><b>Devices</b> is the enrolment inventory: one row per physical device (by MAC) learned from DHCP, with a class and a zone, whether or not it is talking right now. <i>Services</i> is what the device did in the last day: the applications it used, and the ports other local hosts connected to on it (with how many came). A device marked <i>not inspected</i> is on the exclusion list under <a href="#policy">Policy › Exclusions and options</a>: its traffic is never intercepted, decrypted or policed, which is where to put anything that pins its certificates or cannot carry the FlowSight CA. A device with a private (randomised) address has no registered maker; the maker shown for one is read from its DHCP fingerprint or its name. <a href="#hosts">IP Addresses</a> is what traffic shows: one row per address seen in flows and DNS in the selected window, with its traffic. A device's address links to its host page. Addresses are shown by name when FlowSight knows one; with <a href="#modules/enrich">Settings › enrich</a> on, bare addresses gain their reverse-DNS name and country.</div>`;
      FS.$$('select[data-mac]', el).forEach(sel => sel.onchange = async () => { const r = await post('/api/enroll/assign', { mac: sel.dataset.mac, zone: sel.value }); FS.toast(r.error || (sel.value ? 'Assigned and pinned' : 'Unpinned: the rules place it'), !!r.error); if (!r.error) FS.render(); });
      FS.$('#reconcile', el).onclick = async () => { const r = await post('/api/enroll/reconcile', {}); FS.toast(r.error || 'Re-identified', !!r.error); FS.render(); };
      wireIdentify(el);
      modeControls(mode, el);
    }
  });

  // ------------------------------------------------------------- Zones (enrolment)
  FS.registerPage('zones', {
    title: 'Zones', refresh: 0,
    async render(el, ctx) {
      const { s, z, ru, zones, devices, mode } = await enrollLoad('');
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const byZone = {}; devices.forEach(d => { (byZone[d.zone || ''] = byZone[d.zone || ''] || []).push(d); });
      const sel = ctx.params.zone || '';
      const zoneRows = zones.map(x => Object.assign({ count: (byZone[x.id] || []).length }, x));
      el.innerHTML = `<div class="grid cols-4">${kpi('Mode', mode === 'enforce' ? 'enforcing' : 'monitor', mode === 'enforce' ? 'placement and isolation are applied' : 'classifying only; nothing is written', mode === 'enforce' ? 'warn' : '')}${kpi('Zones', num(zones.length), `${num((byZone[''] || []).length)} devices without a zone`)}${kpi('Placed devices', num(devices.length - (byZone[''] || []).length), `of ${num(devices.length)}`)}${card('Actions', `<div class="actions"><button class="btn" id="plan">Plan placement</button><button class="btn primary" id="apply" ${mode === 'enforce' ? '' : 'disabled'}>Apply placement</button><a class="btn" href="#devices">Devices</a><button class="btn ${mode === 'enforce' ? 'danger' : ''}" id="mode">${mode === 'enforce' ? 'Switch to monitor' : 'Switch to enforce'}</button></div>`)}</div>
      <div style="margin-top:14px">${card('Zones', table(zoneRows, [{ t: 'Zone', f: x => `<b>${esc(x.name || x.id)}</b><div class="muted small mono">${esc(x.id)}</div>`, sort: 'id' }, { t: 'Subnet', f: x => `<span class="mono">${esc(x.subnet || x.cidr || '')}</span>` }, { t: 'Subnet6', f: x => `<span class="mono">${esc(x.subnet6 || '')}</span>` }, { t: 'Isolation', f: x => esc(x.isolation || x.policy || (x.isolate ? 'isolated' : '')) }, { t: 'Devices', f: x => `<a href="#devices?zone=${esc(x.id)}">${num(x.count)}</a>`, num: true, sort: 'count' }, { t: 'Members', f: x => (byZone[x.id] || []).slice(0, 6).map(d => d.ip ? FS.hostLink(d.ip, d.hostname || d.guest_name) : esc(d.hostname || d.mac)).join(', ') + ((byZone[x.id] || []).length > 6 ? ` … <a href="#devices?zone=${esc(x.id)}">all</a>` : '') }]), `<a href="#devices">devices without a zone: ${num((byZone[''] || []).length)}</a>`)}</div>
      ${sel && byZone[sel] ? `<div style="margin-top:14px">${card(`Devices in ${esc(zoneName(zones, sel))}`, table(byZone[sel], [{ t: 'Device', f: x => `<b>${esc(x.hostname || x.guest_name || x.mac)}</b><div class="muted small mono">${esc(x.mac)}</div>` }, { t: 'Address', f: x => x.ip ? FS.hostLink(x.ip) : '' }, { t: 'Class', k: 'class' }, { t: 'Seen', f: x => ago(x.last_seen) }, { t: '', f: identifyBtn }]), `<a href="#devices?zone=${esc(sel)}">open in Devices</a>`)}</div>` : ''}
      ${(byZone[''] || []).length ? `<div style="margin-top:14px">${card(`Unidentified: ${num((byZone[''] || []).length)} devices without a zone`, table(byZone[''], [{ t: 'Device', f: x => `<b>${esc(x.hostname || x.guest_name || x.mac)}</b><div class="muted small mono">${esc(x.mac)}${x.randomized ? ' \u00b7 private MAC' : ''}</div>`, sort: 'hostname' }, { t: 'Address', f: x => x.ip ? FS.hostLink(x.ip) : '', sort: 'ip' }, { t: 'Vendor', f: x => esc(x.vendor || ''), sort: 'vendor' }, { t: 'Why', f: x => `<span class="small muted">${esc(x.why || '')}</span>` }, { t: 'Seen', f: x => ago(x.last_seen), sort: 'last_seen' }, { t: '', f: identifyBtn }]), `<span class="muted small">Identify probes the device from the gateway and names what it most likely is; then pick its zone on <a href="#devices">Devices</a>.</span>`)}</div>` : ''}
      <div class="grid cols-2" style="margin-top:14px">${card('Zones (zones.json)', `<form class="f" id="zf"><textarea name="doc" style="min-height:280px">${esc(JSON.stringify((z && (z.document || z)) || {}, null, 1))}</textarea><div class="actions"><button class="btn primary">Save zones</button></div></form>`)}${card('Classification rules (enroll-rules.json)', `<form class="f" id="rf"><textarea name="doc" style="min-height:280px">${esc(JSON.stringify((ru && (ru.document || ru)) || {}, null, 1))}</textarea><div class="actions"><button class="btn primary">Save rules</button></div></form>`)}</div>`;
      wireIdentify(el);
      FS.$('#plan', el).onclick = async () => { const r = await get('/api/enroll/plan'); FS.modal(`<h2>Placement plan</h2><pre class="code">${esc(JSON.stringify(r, null, 1))}</pre><div class="actions"><button class="btn" data-close>Close</button></div>`); };
      FS.$('#apply', el).onclick = async () => { if (!await FS.confirm('Apply device placement (DHCP reservations) and zone isolation now?')) return; const r = await post('/api/enroll/apply', {}); FS.modal(`<h2>Applied</h2><pre class="code">${esc(JSON.stringify(r, null, 1))}</pre><div class="actions"><button class="btn" data-close>Close</button></div>`); };
      modeControls(mode, el);
      FS.$('#zf', el).onsubmit = async (e) => { e.preventDefault(); let doc; try { doc = JSON.parse(e.target.doc.value); } catch (x) { FS.toast('Invalid JSON: ' + x.message, true); return; } const r = await post('/api/enroll/zones', doc); FS.toast(r.error || 'Zones saved', !!r.error); FS.render(); };
      FS.$('#rf', el).onsubmit = async (e) => { e.preventDefault(); let doc; try { doc = JSON.parse(e.target.doc.value); } catch (x) { FS.toast('Invalid JSON: ' + x.message, true); return; } const r = await post('/api/enroll/rules', doc); FS.toast(r.error || 'Rules saved', !!r.error); };
    }
  });
  // Old deep links keep working.
  FS.registerPage('enroll', { title: 'Devices', refresh: 0, async render(el, ctx) { FS.go('#devices' + (ctx.params.zone ? '?zone=' + encodeURIComponent(ctx.params.zone) : '')); } });

  // ------------------------------------------------------------- Users
  FS.registerPage('users', { title: 'Users', refresh: 15, async render(el, ctx) { const u = await get('/api/users' + (ctx.params.user ? '?user=' + encodeURIComponent(ctx.params.user) : '')); if (u.error) { el.innerHTML = FS.err(u.error); return; } const users = u.users || []; el.innerHTML = `<div class="grid cols-4">${kpi('Active users', num(u.count || 0), 'tracked from RADIUS or manual API')}${card('User sessions', users.length ? table(users, [{ t: 'User', f: x => '<b>' + esc(x.user) + '</b>' + (x.source ? '<div class="muted small">' + esc(x.source) + '</div>' : ''), sort: 'user' }, { t: 'Device', f: x => x.device_name ? '<a href="#host/' + (x.ipv4 || x.ipv6) + '">' + esc(x.device_name) + '</a>' : '<span class="muted">-</span>' }, { t: 'Addresses', f: x => (x.ipv4 ? '<span class="mono">' + esc(x.ipv4) + '</span>' : '') + (x.ipv6 ? '<div class="muted small mono">' + esc(x.ipv6) + '</div>' : '') }, { t: 'NAS', f: x => esc(x.nas_ip || x.nas_id || ''), sort: 'nas_ip' }, { t: 'Active', f: x => x.active ? pill('yes', 'ok') : pill('no', '') }, { t: 'Since', f: x => ago(x.start_ts), sort: 'start_ts' }], users.length <= 20 ? '' : '<a href="#users?show=all">show all</a>') : '<span class="muted">no active sessions</span>')}</div><div style="margin-top:14px">${card('Add session manually', '<form class="f" id="addform"><input name="user" placeholder="username" required /><input name="ipv4" placeholder="IPv4 (optional)" /><input name="mac" placeholder="MAC (optional)" /><div class="actions"><button class="btn primary">Add</button></div></form>')}</div>`; FS.$('#addform', el).onsubmit = async (e) => { e.preventDefault(); const r = await post('/api/users/session', new URLSearchParams(new FormData(e.target))); FS.toast(r.error || 'Session recorded', !!r.error); if (!r.error) { e.target.reset(); FS.render(); } }; } });


  // ------------------------------------------------------------- Ask
  // A question in plain English, answered by the model calling FlowSight's
  // own API. The answer streams; every tool call is shown so the reader can
  // see what the answer rests on; the page says plainly when data leaves.
  FS.registerPage('ask', {
    title: 'Ask', refresh: 0,
    async render(el, ctx) {
      const [st, hist] = await Promise.all([get('/api/assistant/status'), get('/api/assistant/conversations?limit=20')]);
      if (st.error) { el.innerHTML = FS.err(st.error); return; }
      const on = !!st.enabled, ready = !!st.ready;
      const provider = st.provider === 'claude-code' ? 'Claude Code (Agent SDK)' : st.provider === 'anthropic' ? 'Anthropic' : 'nobody';
      const suggestions = ['Which devices talked to a country other than mine today?', 'What is 192.168.1.115 and what does it talk to?', 'Which device sent the most data in the last hour, and where did it go?', 'Are any IoT devices reaching new countries or ports this week?'];
      const convs = hist.conversations || [];
      const trail = (calls) => (calls || []).length ? `<details class="small" style="margin-top:6px"><summary>Looked at ${num(calls.length)} thing${calls.length === 1 ? '' : 's'}</summary><ul class="small">${calls.map(c => `<li><span class="mono">${esc(c.tool_name)}</span> · <span class="muted">${esc(c.route || '')}</span>${c.summary ? ` → ${esc(c.summary)}` : ''}</li>`).join('')}</ul></details>` : '';
      el.innerHTML = `${on ? `<div class="card" style="border-color:var(--warn)"><b>Questions and the data the model asks for leave this gateway for ${esc(provider)}.</b> <span class="small muted">Only the tools' results for your question are sent; the API token never is. Turn it off under <a href="#modules/assistant">Settings › assistant</a>.</span>${!ready ? `<div class="sev-high small" style="margin-top:6px">Not ready: ${esc(st.reason || st.last_error || 'see settings')}</div>` : ''}</div>`
        : `<div class="card"><b>The assistant is off.</b> <span class="small">Choose a provider under <a href="#modules/assistant">Settings › assistant</a>: <b>Anthropic</b> (an API key; the daemon runs the agent loop itself) or <b>Claude Code</b> (the Claude Code CLI on the gateway, driven headless with FlowSight attached as an MCP server). When it is on, your questions and the data the model asks for leave this gateway for that provider; nothing leaves while it is off. Claude Code and anything built on the Agent SDK can also use FlowSight directly: <span class="mono">claude mcp add flowsight -- flowsightd mcp</span>.</span></div>`}
        <div style="margin-top:14px">${card('Ask FlowSight', `<form class="f" id="askf"><textarea name="q" rows="3" placeholder="Ask about a device, a country, a domain, a policy…"${ready ? '' : ' disabled'}>${esc(ctx.params.q || '')}</textarea>
          <div class="actions" style="margin-top:8px"><button class="btn primary"${ready ? '' : ' disabled'}>Ask</button><span class="small muted" id="askstate"></span></div></form>
          <div class="small muted" style="margin-top:6px">Try: ${suggestions.map(q => `<a href="#ask?q=${encodeURIComponent(q)}" data-suggest="${esc(q)}">${esc(q)}</a>`).join(' · ')}</div>
          <div id="answer" hidden style="margin-top:12px"><div id="atext" style="white-space:pre-wrap"></div><ul class="small" id="atrail"></ul></div>`)}</div>
        <div style="margin-top:14px">${card('Recent questions', convs.length ? convs.map(c => `<details style="margin-bottom:8px"><summary><b>${esc(c.question)}</b> <span class="muted small">${ago(c.created_at)}${c.error ? ' · ' + pill('failed', 'bad') : ''}</span></summary><div style="white-space:pre-wrap;margin-top:6px">${esc(c.answer || c.error || '')}</div>${trail(c.tool_calls)}<div class="actions" style="margin-top:6px"><button class="btn small danger" data-forget="${esc(c.id)}">Forget</button></div></details>`).join('') : '<div class="empty">Nothing asked yet.</div>', `${num(st.questions || 0)} kept · ${num(st.tools || 0)} tools available`)}</div>`;
      FS.$$('[data-suggest]', el).forEach(a => a.onclick = (e) => { e.preventDefault(); const f = FS.$('#askf', el); if (f && f.q) { f.q.value = a.dataset.suggest; if (ready && f.onsubmit) f.onsubmit({ preventDefault() {} }); } });
      FS.$$('[data-forget]', el).forEach(b => b.onclick = async () => { await FS.api(`/api/assistant/conversations/${encodeURIComponent(b.dataset.forget)}`, { method: 'DELETE', body: {} }); FS.render(); });
      const f = FS.$('#askf', el);
      if (!f) return;
      f.onsubmit = async (e) => {
        e.preventDefault();
        const q = (f.q.value || '').trim(); if (!q) return;
        const box = FS.$('#answer', el), text = FS.$('#atext', el), trailEl = FS.$('#atrail', el), state = FS.$('#askstate', el);
        box.hidden = false; text.textContent = ''; trailEl.innerHTML = ''; state.textContent = 'asking…';
        FS.askInFlight = true;
        try {
          const url = FS.base ? FS.base + encodeURIComponent('/api/assistant/ask') : '/api/assistant/ask';
          const headers = { 'Content-Type': 'application/json', 'Accept': 'text/event-stream', 'X-Requested-With': 'Flowsight' };
          if (window.FS_CSRF) headers['X-CSRFToken'] = window.FS_CSRF;
          const r = await fetch(url, { method: 'POST', headers, credentials: 'same-origin', body: JSON.stringify({ question: q }) });
          if (!r.ok || !r.body) { const t = await r.text(); state.textContent = ''; text.textContent = 'Failed: ' + t.slice(0, 300); return; }
          const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = '';
          const handle = (ev) => {
            if (ev.type === 'text') text.textContent += ev.text;
            else if (ev.type === 'tool_call') { const li = document.createElement('li'); li.innerHTML = `<span class="mono">${esc(ev.tool)}</span> <span class="muted">${esc(ev.route || '')}</span> <span class="muted">…</span>`; trailEl.appendChild(li); }
            else if (ev.type === 'tool_result') { const lis = trailEl.querySelectorAll('li'); const li = lis[lis.length - 1]; if (li) li.innerHTML = `<span class="mono">${esc(ev.tool)}</span> <span class="muted">${esc(ev.route || '')}</span> → ${esc(ev.summary || (ev.bytes + ' bytes'))}`; }
            else if (ev.type === 'error') { text.textContent += (text.textContent ? '\n' : '') + 'Error: ' + ev.error; }
            else if (ev.type === 'done') { state.textContent = `done · ${num(ev.turns || 0)} turn${ev.turns === 1 ? '' : 's'}`; }
          };
          for (;;) {
            const { value, done } = await reader.read(); if (done) break;
            buf += dec.decode(value, { stream: true });
            let i; while ((i = buf.indexOf('\n\n')) >= 0) { const chunk = buf.slice(0, i); buf = buf.slice(i + 2); chunk.split('\n').forEach(l => { if (l.startsWith('data:')) { try { handle(JSON.parse(l.slice(5).trim())); } catch (err) { } } }); }
          }
          if (!state.textContent || state.textContent === 'asking…') state.textContent = 'done';
        } catch (err) { state.textContent = ''; text.textContent += '\nFailed: ' + err.message; }
        finally { FS.askInFlight = false; }
      };
      if (ctx.params.q && ready) setTimeout(() => f.onsubmit({ preventDefault() {} }), 50);
    }
  });

  // ------------------------------------------------------------- Stateful Packet Inspection
  FS.registerPage('deep', {
    title: 'Stateful Packet Inspection', refresh: 15,
    async render(el, ctx) {
      const [s, r] = await Promise.all([get('/api/mitm/status'), get('/api/mitm/requests?limit=300' + (ctx.params.q ? '&q=' + encodeURIComponent(ctx.params.q) : ''))]);
      if (s.error) { el.innerHTML = FS.err(s.error); return; }
      const state = !s.licensed ? pill('business tier', 'warn') : !s.scanning ? pill('off', '') : s.listening ? pill('inspecting', 'ok') : pill('not listening', 'bad');
      el.innerHTML = `<div class="grid cols-4">
        ${kpi('State', state, s.error ? esc(s.error) : (s.scanning ? `loopback port ${s.port}` : 'switch it on under Settings › mitm'))}
        ${kpi('Requests', num(s.requests), `${bytes(s.bytes_in)} in · ${bytes(s.bytes_out)} out`)}
        ${kpi('Decoded', num(s.decoded), 'DNS-over-HTTPS questions recovered')}
        ${card('Scope', `<div class="small">Clients: ${(s.clients || []).length ? (s.clients || []).map(c => `<span class="mono">${esc(c)}</span>`).join(', ') : '<span class="muted">every client a policy decrypts</span>'}</div>
          <div class="small" style="margin-top:4px">Names: ${(s.names || []).length ? (s.names || []).map(c => `<span class="mono">${esc(c)}</span>`).join(', ') : '<span class="muted">every name that is decrypted</span>'}</div>
          <div class="actions"><a class="btn" href="#modules/mitm">Settings</a><a class="btn" href="#tls">Pinned sites</a></div>`)}
      </div>
      <div style="margin-top:14px">${card('Recent requests', table(r.requests || [], [
        { t: 'When', f: x => when(x.ts), sort: 'ts' },
        { t: 'Client', f: x => FS.hostLink(x.client), sort: 'client' },
        { t: 'Request', f: x => `<span class="mono small">${esc(x.method)} ${esc(x.url)}</span>`, sort: 'url' },
        { t: 'Status', f: x => x.status ? pill(String(x.status), x.status >= 400 ? 'bad' : 'ok') : pill('failed', 'bad'), sort: 'status' },
        { t: 'Type', f: x => `<span class="small muted">${esc((x.content_type || '').split(';')[0])}</span>`, sort: 'content_type' },
        { t: 'Size', f: x => bytes(x.bytes_in), num: true, sort: 'bytes_in' },
        { t: 'Took', f: x => (x.ms || 0).toFixed(0) + ' ms', num: true, sort: 'ms' },
        { t: '', f: x => `<button class="btn small" data-det="${esc(JSON.stringify(x).replace(/"/g, '&quot;'))}">Headers</button>` },
      ]), `<span class="muted small">${esc(s.note || '')}</span>`)}</div>`;
      FS.$$('[data-det]', el).forEach(b => b.onclick = () => {
        const x = JSON.parse(b.dataset.det);
        FS.modal(`<h2>${esc(x.method)} ${esc(x.url)}</h2><pre class="code">${esc(Object.entries(x.headers || {}).map(([k, v]) => k + ': ' + v).join('\n') || 'headers were not recorded')}</pre>
          <div class="small muted">${esc(x.note || '')}</div><div class="actions"><button class="btn" data-close>Close</button></div>`);
      });
    }
  });

  // ------------------------------------------------------------- DLP
  // The one page that is about the present tense. Everything else in
  // FlowSight reports what happened; this reports what is happening, because
  // a transfer you read about tomorrow is a transfer that finished.
  const rate = (b) => b > 0 ? FS.bps(b * 8) : '<span class="muted">idle</span>';
  // The pill says what kind of destination this is, in words. An unnamed one
  // is called out in red: an address nothing can put a name to is the row
  // most worth reading on this page.
  const groupPill = (t) => {
    const tone = { unknown: 'bad', tunnel: 'warn', 'cloud-storage': 'warn', 'file-transfer': 'warn',
      webmail: 'warn', 'remote-access': 'warn', ai: 'warn' }[t.group] || '';
    return pill(t.group_title || t.group, tone);
  };
  FS.registerPage('egress', {
    title: 'DLP', refresh: 5,
    async render(el, ctx) {
      const [live, sum, ev, abroad] = await Promise.all([
        get('/api/egress/live?min_kb=' + (ctx.params.all ? 0 : 64) + (ctx.params.group ? '&group=' + encodeURIComponent(ctx.params.group) : '')),
        get('/api/egress/summary'),
        get('/api/egress/events?limit=200'),
        get(`/api/visibility/abroad?${FS.since()}`)]);
      if (live.error && !live.transfers) { el.innerHTML = FS.err(live.error); return; }
      const rows = live.transfers || [];
      // Only connections this network opened count as data leaving. A server
      // here answering the internet has really sent the bytes, and saying so
      // is useful, but it is not the same question.
      const outbound = rows.filter(t => !t.serving);
      const watched = outbound.filter(t => ['cloud-storage', 'file-transfer', 'webmail', 'messaging',
        'ai', 'remote-access', 'code-host', 'tunnel', 'unknown'].includes(t.group));
      const events = ev.events || [];
      const open = events.filter(e => e.severity === 'high' || e.severity === 'medium').length;

      el.innerHTML = `<div class="grid cols-4">
        ${kpi('Leaving now', FS.bps((sum.rate_out || 0) * 8), `${num(sum.transfers)} connections carrying data`, sum.rate_out > 1e6 ? 'warn' : '')}
        ${kpi('Sent, open connections', bytes(outbound.reduce((a, t) => a + t.out, 0)), `${num(rows.length - outbound.length)} more are this network serving requests from outside`)}
        ${kpi('To watched destinations', num(watched.length), 'cloud storage, mail, tunnels, unnamed', watched.length ? 'warn' : '')}
        ${kpi('Flagged', num(open), 'transfers that crossed a threshold', open ? 'bad' : '')}</div>

      <div class="grid cols-2" style="margin-top:14px">
        ${card('By destination', bars((sum.groups || []).map(g => ({ label: g.title || g.key, value: g.out, href: '#egress?group=' + encodeURIComponent(g.key) + (ctx.params.all ? '&all=1' : ''), title: 'Show the connections of this kind' })), bytes))}
        ${card('By device', bars((sum.devices || []).map(d => ({ label: d.name || d.key, sub: d.name ? d.key : '', value: d.out, href: '#host/' + d.key })), bytes))}
      </div>

      <div style="margin-top:14px" id="live-card">${card(`Moving now (${num(rows.length)})`, table(rows, [
        { t: 'Device', f: r => FS.addrCell(r.local, r.local_name), sort: 'local' },
        { t: 'Direction', f: r => r.serving
            ? `<span class="muted small" title="The far side opened this connection: something here is answering the internet, not reaching out to it">serving</span>`
            : pill('reaching out', ''), sort: 'serving' },
        { t: 'Destination', f: r => `<b>${esc(r.service || r.peer_name || r.peer)}</b>${(r.peer_name && r.peer_name !== r.service) ? `<div class="muted small">${esc(r.peer_name)}</div>` : ''}<div class="muted small">${esc(r.peer)}:${r.peer_port} ${esc(r.proto)}</div>`, sort: 'peer_name' },
        { t: 'Kind', f: r => groupPill(r), sort: 'group' },
        { t: 'Sending', f: r => `<b>${rate(r.rate_out)}</b>`, num: true, sort: 'rate_out' },
        { t: 'Sent', f: r => bytes(r.out), num: true, sort: 'out' },
        { t: 'Received', f: r => bytes(r.in), num: true, sort: 'in' },
        { t: 'Open for', f: r => FS.dur(r.age), num: true, sort: 'age' },
        { t: 'Flags', f: r => (r.flags || []).map(f => pill(f, 'warn')).join(' ') },
        { t: '', f: r => `<button class="btn small danger" data-stop="${esc(r.local)}" data-peer="${esc(r.peer)}">Stop</button>` }],
        { rowAttr: r => (r.flags || []).length ? 'class="flagged"' : '' }),
        (ctx.params.group ? `showing <b>${esc(((sum.groups || []).find(g => g.key === ctx.params.group) || {}).title || ctx.params.group)}</b> · <a href="#egress${ctx.params.all ? '?all=1' : ''}">every kind</a> · ` : '') +
        (ctx.params.all ? `<a href="#egress${ctx.params.group ? '?group=' + encodeURIComponent(ctx.params.group) : ''}">hide small connections</a>` : `<a href="#egress?all=1${ctx.params.group ? '&group=' + encodeURIComponent(ctx.params.group) : ''}">show every connection</a>`))}</div>

      <div style="margin-top:14px">${card('Flagged transfers', table(events, [
        { t: 'When', f: r => when(r.ts), sort: 'ts' },
        { t: 'Severity', f: r => FS.sevPill(r.severity), sort: 'severity' },
        { t: 'What', f: r => `<b>${esc(r.message)}</b>`, sort: 'message' },
        { t: 'Kind', f: r => pill(r.kind), sort: 'kind' },
        { t: 'Device', f: r => hostLink(r.transfer.local, r.transfer.local_name), sort: 'transfer' }],
        { empty: 'Nothing has crossed a threshold. Thresholds are in Settings, under egress.' }))}</div>

      <div class="help" style="margin-top:12px">${esc(live.note || '')} Sampled ${live.sampled ? ago(live.sampled) : 'never'}.</div>`;
      // Which devices talk to other countries, and to whom. Built from the
      // sessions themselves (each carries the far end's country), so it needs
      // no extra database; "home" is the country this gateway sits in.
      const homeCC = (abroad && abroad.home_country) || '';
      const adev = (abroad && abroad.devices) || [];
      el.innerHTML += `<div style="margin-top:14px">${card(`Leaving the country${homeCC ? ` (outside ${esc(FS.countryName(homeCC))})` : ''}`, adev.length ? table(adev, [
        { t: 'Device', f: x => FS.hostLink(x.ip, x.name) + (x.mac ? `<div class="muted small mono">${esc(x.mac)}</div>` : ''), sort: 'name' },
        { t: 'Sessions abroad', f: x => `<a href="#flows?ip=${encodeURIComponent(x.ip)}&abroad=1">${num(x.sessions)}</a>`, num: true, sort: 'sessions' },
        { t: 'Via anycast', f: x => x.anycast_sessions ? `<a href="#flows?ip=${encodeURIComponent(x.ip)}&anycast=1" title="Reached at a nearby site of a globally announced service (${esc((x.anycast_destinations || []).map(d => d.domain || d.name || d.ip).slice(0, 3).join(', '))}); not counted as abroad">${num(x.anycast_sessions)}</a>` : '<span class="muted">0</span>', num: true, sort: 'anycast_sessions' },
        { t: 'Countries', f: x => (x.countries || []).map(c => FS.cc(c.country, { cls: 'pill warn', title: `${num(c.sessions)} sessions, ${bytes(c.bytes_in + c.bytes_out)}`, suffix: num(c.sessions) })).join(' ') },
        { t: 'Talking to', f: x => (x.countries || []).slice(0, 3).map(c => `<div class="small"><b title="${esc(FS.countryName(c.country))}">${esc(c.country)}</b>: ${(c.destinations || []).slice(0, 3).map(d => `<a href="#flows?ip=${encodeURIComponent(x.ip)}&country=${esc(c.country)}" title="${esc(d.ip)}">${esc(d.domain || d.name || d.ip)}</a>`).join(', ')}</div>`).join('') },
        { t: '', f: x => `<button class="btn small" data-block-abroad="${esc(x.mac ? 'mac:' + x.mac : x.ip)}" data-cc="${esc((x.countries || []).map(c => c.country).join(','))}" title="Open a policy denying these countries for this device">Block…</button>` }]) : `<div class="empty">${homeCC ? 'No device reached another country in this window.' : 'The country of this gateway is not known yet: turn on Country lookup under Settings › enrich so sessions carry a country and "home" can be told.'}</div>`,
        `<span class="muted small">${num(adev.length)} devices · window ${FS.state.hours}h · home ${homeCC ? FS.cc(homeCC, { cls: 'pill' }) : ''} · <a href="#flows?abroad=1">all sessions outside the country</a> · <a href="#flows?anycast=1">anycast sessions</a>. Anycast far ends (Cloudflare, public resolvers, root servers and the like) answer from a nearby site whatever country their range is registered in, so they are shown apart and never count as abroad.</span>`)}</div>`;
      FS.$$('[data-block-abroad]', el).forEach(b => b.onclick = () => FS.quickPolicy({ countries: b.dataset.cc.split(',').filter(Boolean), members: [b.dataset.blockAbroad] }));

      FS.$$('[data-stop]', el).forEach(b => b.onclick = async () => {
        if (!await FS.confirm(`Stop the transfer from ${b.dataset.stop} to ${b.dataset.peer}? The connection is dropped at the firewall. The device may open another one.`)) return;
        const r = await post('/api/egress/stop', { local: b.dataset.stop, peer: b.dataset.peer });
        FS.toast(r.error || 'Transfer stopped', !!r.error);
        FS.render();
      });
    }
  });

  // ------------------------------------------------------------- Priority
  // The page for the one module that changes traffic rather than describing
  // it, so it leads with whether shaping is actually in force and what the
  // queues are holding, not with the settings.
  FS.registerPage('qos', {
    title: 'Priority', refresh: 15,
    async render(el, ctx) {
      const [s, p] = await Promise.all([get('/api/qos/status'), get('/api/qos/preview')]);
      if (s.error && !s.rules) { el.innerHTML = FS.err(s.error); return; }
      const rules = s.rules || [];
      const broken = rules.filter(r => r.error);
      const state = !s.active ? pill('off', '')
        : s.applied ? pill('shaping', 'warn') : pill('not applied', 'bad');

      el.innerHTML = `<div class="grid cols-4">
        ${card('State', `<div>${state}</div><div class="small muted" style="margin-top:6px">${s.applied ? 'The queue is on this firewall' : 'The carrier still decides what waits'}</div>`)}
        ${kpi('Link, as shaped', s.applied ? `${Math.round(s.down_mbit)} / ${Math.round(s.up_mbit)}` : '—', 'Mbit/s down / up, after headroom')}
        ${kpi('Rules', num(rules.length - broken.length), broken.length ? `${broken.length} cannot be read` : 'all readable', broken.length ? 'bad' : '')}
        ${kpi('Resolved names', num(Object.keys(s.resolved || {}).length), 'domains with addresses to match on')}</div>

      ${!s.active ? `<div class="help" style="margin-top:14px">Shaping is off, so the link behaves exactly as it does now and nothing below is in force. It is switched on in <a href="#modules?m=qos">Settings › qos</a>, which also needs the rates the link really carries.</div>` : ''}
      ${s.error ? `<div style="margin-top:14px">${card('Not applied', `<div class="sev-high">${esc(s.error)}</div>`)}</div>` : ''}

      <div style="margin-top:14px">${card('Rules', table(rules, [
        { t: 'Match', f: r => `<b>${esc(r.match)}</b><div class="muted small">${r.is_host ? 'an address here' : 'a service out there'}</div>`, sort: 'match' },
        { t: 'Class', f: r => r.class ? pill(r.class, r.class === 'high' ? 'ok' : r.class === 'low' ? '' : 'info') : '<span class="muted">unchanged</span>', sort: 'class' },
        { t: 'Ceiling', f: r => r.ceiling ? `${r.ceiling} Mbit/s` : '<span class="muted">none</span>', num: true, sort: 'ceiling' },
        { t: 'Matches', f: r => r.is_host ? '<span class="muted small">the address itself</span>'
            : ((s.resolved || {})[r.match] ? `${num(s.resolved[r.match])} addresses` : '<span class="muted small">nothing looked it up yet</span>') },
        { t: 'Problem', f: r => r.error ? `<span class="sev-high small">${esc(r.error)}</span>` : '' }],
        { empty: 'No rules. Everything shares the link equally.' }))}</div>

      ${s.applied ? `<div style="margin-top:14px">${card('Queues', table(s.queues || [], [
        { t: 'Queue', f: r => esc(r.name), sort: 'name' },
        { t: 'From dummynet', f: r => `<span class="mono small">${esc(r.detail)}</span>` }],
        { empty: 'Nothing queued yet. A queue only holds something back when the link is full.' }))}</div>` : ''}

      <div style="margin-top:14px">${card('Firewall rules these settings produce', `<pre class="mono small" style="white-space:pre-wrap;overflow-x:auto">${esc(p.anchor || 'nothing; there is no rule to apply')}</pre>`,
        p.lan ? `on <b>${esc(p.lan)}</b>` : '<span class="sev-high">no LAN interface detected</span>')}</div>

      <div class="help" style="margin-top:12px">${esc(s.note || '')}</div>`;
    }
  });

  // ------------------------------------------------------------- Paths
  // A map of where traffic goes, drawn from measured routes.
  //
  // Two honesties are built into the drawing rather than written in a
  // caption. Legs shared by several destinations are one line in a neutral
  // colour, because that is literally one piece of wire carrying both. And
  // hops with no coordinates are not placed at zero, which would pile a
  // stack of routers into the Gulf of Guinea; they go in their own row
  // underneath, counted and named.
  const MAPW = 720, MAPH = 360;
  FS.registerPage('paths', {
    title: 'Map', refresh: 120, fullbleed: true,
    async render(el, ctx) {
      const q = [];
      if (ctx.params.device) q.push('device=' + encodeURIComponent(ctx.params.device));
      if (ctx.params.country) q.push('country=' + encodeURIComponent(ctx.params.country));
      if (ctx.params.max_latency) q.push('max_latency=' + encodeURIComponent(ctx.params.max_latency));
      if (ctx.params.max_hops) q.push('max_hops=' + encodeURIComponent(ctx.params.max_hops));
      const picked = ctx.params.dst || '';
      // Choosing a route must not throw away the filters that led to it.
      const routeQ = (dst, hop, device) => {
        const p = [];
        ['device', 'country', 'max_latency', 'max_hops'].forEach(k => {
          const v = (k === 'device' && device !== undefined) ? device : ctx.params[k];
          if (v) p.push(k + '=' + encodeURIComponent(v));
        });
        if (dst) p.push('dst=' + encodeURIComponent(dst));
        if (hop) p.push('hop=' + encodeURIComponent(hop));
        return p.join('&');
      };
      const [st, g, dests, devs, home, cab, route] = await Promise.all([
        get('/api/paths/status'),
        get('/api/paths/graph' + (q.length ? '?' + q.join('&') : '')),
        get('/api/paths/destinations?limit=400'),
        get('/api/paths/devices'),
        get('/api/paths/home'),
        get('/api/paths/cables?detail=36'),
        picked ? get('/api/paths/path?dst=' + encodeURIComponent(picked)
          + (ctx.params.device ? '&device=' + encodeURIComponent(ctx.params.device) : '')) : Promise.resolve(null)]);
      if (st.error && !g.nodes) { el.innerHTML = FS.err(st.error); return; }

      const nodes = g.nodes || [], legs = g.legs || [];
      const byId = {}; nodes.forEach(n => byId[n.id] = n);
      const located = nodes.filter(n => n.located);
      const impossible = nodes.filter(n => n.impossible);
      const unlocated = nodes.filter(n => !n.located && !n.silent);
      // Counted by the server. Silent hops are no longer sent -- they were
      // six of every seven nodes and nothing draws them.
      const silent = g.silent_count || nodes.filter(n => n.silent).length;

      // One colour per destination for the legs only it uses; everything
      // shared takes a single neutral colour, which is what "these are the
      // same leg" should look like.
      const dstColour = {};
      let ci = 0;
      legs.forEach(l => (l.destinations || []).forEach(d => {
        if (!(d in dstColour)) dstColour[d] = FS.palette[ci++ % FS.palette.length];
      }));
      const legColour = (l) => l.shared ? 'var(--muted)' : (dstColour[(l.destinations || [])[0]] || FS.palette[0]);

      // The legs the chosen route uses. Everything else is dimmed rather than
      // hidden: a route means little without the other routes it diverges
      // from, and removing them would make a shared leg look exclusive.
      const onRoute = {};
      if (picked) legs.forEach(l => { if ((l.destinations || []).includes(picked)) onRoute[l.from + '>' + l.to] = true; });
      const routeHops = (route && route.hops) || [];
      const inRoute = {}; routeHops.forEach(n => { inRoute[n.id] = true; });
      // A node on the map is one router, and several routes cross it at
      // different steps: hop 16 of one is hop 18 of another. The labels on
      // a chosen route use that route's numbering and that route's timings,
      // not whichever route happened to define the node.
      const rcOf = (l) => picked ? (onRoute[l.from + '>' + l.to] ? ' onroute' : ' offroute') : '';
      const routeIndex = {}, routeRTT = {};
      routeHops.forEach(n => { routeIndex[n.id] = n.index; if (n.rtt_ms) routeRTT[n.id] = n.rtt_ms; });
      const hopNo = (n) => (picked && routeIndex[n.id] != null) ? routeIndex[n.id] : n.index;
      const hopRTT = (n) => (picked && routeRTT[n.id]) ? routeRTT[n.id] : n.rtt_ms;

      // Who was talking, and about what. The route says where the traffic
      // went; this says whose it was and what it was doing -- device by
      // device, and under each the services: the application, the name it
      // was for, the port. It sits with the trail, because the near end of
      // the journey belongs beside the far end.
      const svcLabel = (s) => [s.app, s.domain, s.port ? `${s.proto ? s.proto + '/' : ''}${s.port}` : (s.proto || '')].filter(Boolean).join(' \u00b7 ') || 'unclassified';
      const talkersHTML = (t, compact) => {
        if (!t || !(t.devices || []).length) return '';
        const devs = compact ? t.devices.slice(0, 4) : t.devices;
        const rows = devs.map(d => {
          const svcs = (d.services || []).slice(0, compact ? 3 : 6).map(s =>
            `<li class="svc" data-svc="${esc(s.app || '')}"><span class="svcn">${esc(svcLabel(s))}</span><span class="svcb">${bytes((s.bytes_in || 0) + (s.bytes_out || 0))}</span></li>`).join('');
          const more = (d.services || []).length > (compact ? 3 : 6) ? `<li class="svc muted small">+${(d.services || []).length - (compact ? 3 : 6)} more</li>` : '';
          return `<li class="talker">
            <div class="tkhead"><a href="#paths?${esc(routeQ(picked))}&device=${encodeURIComponent(d.key)}" title="Narrow the map to this device"><b>${esc(d.name || d.addresses[0])}</b></a>${d.vendor ? ` <span class="muted small">${esc(d.vendor)}</span>` : ''}<span class="tkb">${bytes((d.bytes_in || 0) + (d.bytes_out || 0))} \u00b7 ${num(d.flows)} flow${d.flows === 1 ? '' : 's'}</span></div>
            ${d.name ? `<div class="muted small mono">${esc(d.addresses.slice(0, 2).join(', '))}${d.addresses.length > 2 ? ` +${d.addresses.length - 2}` : ''}</div>` : ''}
            <ul class="svcs">${svcs}${more}</ul></li>`;
        }).join('');
        const summary = (t.services || []).slice(0, 4).map(svcLabel).join(', ');
        return `<div class="talkers${compact ? ' compact' : ''}">
          <div class="tkgrp">Who and what \u2014 last ${t.hours} h</div>
          ${summary ? `<div class="small muted" style="margin-bottom:6px">${esc(summary)}</div>` : ''}
          <ul class="tklist">${rows}${compact && t.devices.length > 4 ? `<li class="muted small">+${t.devices.length - 4} more devices in the trail below</li>` : ''}</ul>
        </div>`;
      };


      const xy = (n) => FS.project(n.lat, n.lon, MAPW, MAPH);

      // Where you are, drawn.
      //
      // A route's first hops are your own machine and your own gateway, and
      // both have private addresses that no database can place. Left out, the
      // route appeared to begin at whichever carrier router first answered --
      // a couple of hundred miles away, with nothing joining it to you. The
      // origin is known: it is the point every other placement is judged
      // against. So it is on the map, and the route reaches it.
      const origin = home.ok ? FS.project(home.lat, home.lon, MAPW, MAPH) : null;
      let originArt = '';
      if (origin) {
        const where = home.detected ? [home.detected.city, home.detected.region, home.detected.country].filter(Boolean).join(', ') : '';
        originArt = `<circle class="homering" data-r="9" cx="${origin[0].toFixed(1)}" cy="${origin[1].toFixed(1)}" r="9"/>`
          + `<circle class="home" data-r="3.5" cx="${origin[0].toFixed(1)}" cy="${origin[1].toFixed(1)}" r="3.5">`
          + `<title>You are here\n${home.lat.toFixed(4)}, ${home.lon.toFixed(4)}${where ? '\n' + esc(where) : ''}\nfrom the ${esc(home.source)}</title></circle>`;
      }
      // Cables first, so they sit behind the routes. A run is broken wherever
      // it wraps the antimeridian rather than drawn straight across the map.
      let cables = '';
      (cab.cables || []).forEach(c => {
        (c.runs || []).forEach(run => {
          let d = '', prev = null;
          run.forEach(p => {
            const [x, y] = FS.project(p[1], p[0], MAPW, MAPH);
            d += (prev === null || Math.abs(x - prev) > MAPW * 0.5 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1) + ' ';
            prev = x;
          });
          cables += `<path class="cable" d="${d.trim()}"/>`;
        });
      });
      // The short way round. Two points 350 degrees apart in longitude are ten
      // degrees apart on a globe, and drawing the straight line between their
      // x positions draws the 350 -- a link that crosses the whole map to
      // reach a neighbour. Shifting one end by whole worlds until it is
      // nearest the other gives the leg people actually travel; the repeated
      // copies below make it appear at both edges.
      const near = (x, ref) => {
        let best = x, bestD = Math.abs(x - ref);
        for (let k = -2; k <= 2; k++) {
          const c = x + k * MAPW, d = Math.abs(c - ref);
          if (d < bestD) { best = c; bestD = d; }
        }
        return best;
      };
      // Which legs touch a node, and which destinations run through it. A hop
      // means little on its own: the reader wants the journey it belongs to.
      const legsAt = {};
      legs.forEach(l => {
        (legsAt[l.from] = legsAt[l.from] || []).push(l);
        (legsAt[l.to] = legsAt[l.to] || []).push(l);
      });
      const routeOf = (id) => {
        const seen = {}, out = [];
        (legsAt[id] || []).forEach(l => (l.destinations || []).forEach(d => {
          if (!seen[d]) { seen[d] = 1; out.push(d); }
        }));
        return out;
      };

      // Routes through a hop, busiest first, so "the route this hop is on"
      // has one answer when there are several, and a next one after it.
      const bytesTo = {};
      (dests.destinations || []).forEach(d => { bytesTo[d.dst] = (d.bytes_in || 0) + (d.bytes_out || 0); });
      const routesThrough = (id) => routeOf(id).sort((a, b) => (bytesTo[b] || 0) - (bytesTo[a] || 0));

      let lines = '', dots = '', labels = '', arrows = '';
      if (origin && picked) {
        const first = routeHops.find(n => n.located);
        if (first) {
          const [fx, fy] = xy(first);
          const skipped = routeHops.filter(n => n.index < first.index).length;
          lines += `<path class="leg local" d="M${origin[0].toFixed(1)},${origin[1].toFixed(1)} L${near(fx, origin[0]).toFixed(1)},${fy.toFixed(1)}"><title>`
            + `you \u2192 ${esc(first.ips.join(', '))}`
            + (skipped ? `\nthrough ${skipped} hop${skipped === 1 ? '' : 's'} on your own network and your carrier's, which have no position` : '')
            + `</title></path>`;
        }
      }
      legs.forEach(l => {
        const a = byId[l.from], b = byId[l.to];
        if (!a || !b || !a.located || !b.located) return;
        const [x1, y1] = xy(a); let [x2, y2] = xy(b);
        x2 = near(x2, x1);
        // A crossing follows its cable. Drawing it straight rules a line
        // through water the cable does not go near and understates the
        // journey; the route is the shape the packet actually took, as far as
        // the cable record can say. Each point is shifted by whole worlds to
        // sit nearest the one before, so a run over the antimeridian bends
        // round rather than snapping back across the map.
        let pts = [[x1, y1], [x2, y2]];
        if ((l.route || []).length > 1) {
          let prev = null;
          pts = l.route.map(p => {
            let [px, py] = FS.project(p.lat, p.lon, MAPW, MAPH);
            px = prev === null ? near(px, x1) : near(px, prev);
            prev = px;
            return [px, py];
          });
        }
        const d = 'M' + pts.map(q => `${q[0].toFixed(1)},${q[1].toFixed(1)}`).join(' L');
        // Which way the packets went. A line has no direction and a route
        // has one; the arrow sits on the middle segment, points from this
        // hop to the next, and is rewritten on zoom so it stays the same
        // size on screen. Off by a switch in the key.
        {
          const si = Math.floor((pts.length - 1) / 2);
          const [ax0, ay0] = pts[si], [ax1, ay1] = pts[si + 1];
          if (Math.hypot(ax1 - ax0, ay1 - ay0) > 1.5) {
            const ax = (ax0 + ax1) / 2, ay = (ay0 + ay1) / 2;
            const aa = Math.atan2(ay1 - ay0, ax1 - ax0) * 180 / Math.PI;
            arrows += `<polygon class="arrow${rcOf(l)}" data-dsts="${esc((l.destinations || []).join(' '))}" data-ax="${ax.toFixed(1)}" data-ay="${ay.toFixed(1)}" data-aa="${aa.toFixed(1)}" points="-3.6,-2.2 3.6,0 -3.6,2.2" transform="translate(${ax.toFixed(1)} ${ay.toFixed(1)}) rotate(${aa.toFixed(1)})"/>`;
          }
        }
        const n = (l.destinations || []).length;
        const cbl = (l.cables || []).length
          ? `\ncould have crossed: ${l.cables.map(c => `${c.name} (${num(c.km)} km)`).join(', ')}`
          : (l.straight_km ? `\nno cable serves both ends` : '');
        const rc = picked ? (onRoute[l.from + '>' + l.to] ? ' onroute' : ' offroute') : '';
        // A leg standing in for hops that could not be placed is a weaker
        // claim than one router to the next, and is drawn as one.
        const gap = (l.gap ? ' gapleg' : '') + (l.via ? ' sea' : '');
        // What this leg cost, written on it. The panel gives one hop's round
        // trip; the question a reader actually has is where the time went,
        // and that is the difference between one hop and the next.
        const dms = (hopRTT(b) && hopRTT(a)) ? hopRTT(b) - hopRTT(a) : null;
        if (dms !== null && dms > 0.05) {
          const mid = (l.route || []).length > 2
            ? (() => { const p = l.route[Math.floor(l.route.length / 2)];
                       const [mx, my] = FS.project(p.lat, p.lon, MAPW, MAPH); return [near(mx, x1), my]; })()
            : [(x1 + x2) / 2, (y1 + y2) / 2];
          // The hop the leg arrives at, beside what it cost. The number is
          // what ties the label to its step in the route below; the
          // milliseconds alone left a reader counting dots to work out which
          // leg they were reading.
          labels += `<text class="legms" data-dsts="${esc((l.destinations || []).join(' '))}" x="${mid[0].toFixed(1)}" y="${(mid[1] - 2).toFixed(1)}">#${hopNo(b)} \u00b7 ${dms.toFixed(dms < 10 ? 1 : 0)} ms</text>`;
        }
        lines += `<path class="leg ${l.shared ? 'shared' : ''}${rc}${gap}" data-dsts="${esc((l.destinations || []).join(' '))}" stroke="${legColour(l)}" d="${d}"><title>${esc(a.ips.join(', '))} &rarr; ${esc(b.ips.join(', '))}\n${n} destination${n === 1 ? '' : 's'}${l.gap ? `\nthrough ${l.through} hop${l.through === 1 ? '' : 's'} with no known position` : ''}${l.via ? `\ndrawn along ${esc(l.via)} — ${num(l.via_km)} km, against ${num(l.straight_km)} km straight` : ''}${esc(cbl)}</title></path>`;
      });
      located.forEach(n => {
        const [x, y] = xy(n);
        const label = [n.city, n.region, n.country].filter(Boolean).join(', ');
        // data-r is the radius at 1x. Zooming rewrites r from it, so a dot
        // stays the same size on screen however far in you go and stops
        // swallowing the neighbours it is meant to distinguish.
        if (n.impossible) dots += `<circle class="ruledout" data-r="7" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="7"/>`;
        else if (n.tight) dots += `<circle class="doubtful" data-r="6" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="6"/>`;
        if (n.moved_km && n.db_lat) {
          // Drawn from where the database put it to where the name says it is,
          // so a reader can see the size of the correction rather than take it.
          const [px, py] = xy({ lat: n.db_lat, lon: n.db_lon });
          dots += `<path class="corrected" d="M${px.toFixed(1)},${py.toFixed(1)} L${x.toFixed(1)},${y.toFixed(1)}"/><circle class="ghost" data-r="2.5" cx="${px.toFixed(1)}" cy="${py.toFixed(1)}" r="2.5"/>`;
        }
        const hr = (2 + Math.min(3, n.ips.length)).toFixed(1);
        // An endpoint is somewhere this network was talking to; everything
        // else is a router it crossed on the way. Drawn the same, there was
        // no telling the destination from the plumbing.
        if (n.endpoint) {
          // A second radius, grown by how much went here, for the reader who
          // switches the key to size endpoints by traffic. Logarithmic: a
          // megabyte and a terabyte both have to fit on one map.
          const mb = ((n.bytes_in || 0) + (n.bytes_out || 0)) / 1e6;
          const rt = Math.min(22, 8 + Math.log10(1 + mb) * 3.2).toFixed(1);
          dots += `<circle class="endpoint" data-r="8" data-rt="${rt}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="8"/>`;
        }
        dots += `<circle class="hop ${n.detail && n.detail.asn ? 'rich' : ''}${n.endpoint ? ' isend' : ''}${n.inferred ? ' guessed' : ''}${n.location_source === 'measured' ? ' measured' : ''}${n.location_source === 'provider' ? ' provider' : ''}${n.location_source === 'identified' ? ' measured' : ''}${picked ? (inRoute[n.id] ? ' onroute' : ' offroute') : ''}" data-hop="${esc(n.id)}" data-r="${hr}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${hr}" fill="${FS.palette[n.index % FS.palette.length]}"><title>hop ${n.index}\n${esc(n.ips.join(', '))}${label ? '\n' + esc(label) : ''}${n.rtt_ms ? '\n' + n.rtt_ms + ' ms' : ''}${n.endpoint ? '\nENDPOINT — traffic was going here' : ''}${n.inferred ? '\nPLACED BY TIMING, not located: ' + esc(n.between_how || '') : ''}${n.why ? '\n' + (n.impossible ? 'RULED OUT: ' : 'TOO FAST: ') + esc(n.why) : ''}\nclick for detail</title></circle>`;
      });

      // What a hop is, told in the order the evidence deserves: what was
      // measured, then what the router called itself, then what a registry
      // says about the block, then buildings -- each labelled, so a street
      // address published by an operator is never mistaken for this router's
      // address, and a head office is never mistaken for either.
      const hopCard = (n) => {
        const d = n.detail || {};
        const r = (k, v, cls) => v ? `<div class="hr ${cls || ''}"><span>${esc(k)}</span><b>${esc(v)}</b></div>` : '';
        const grp = (t) => `<div class="hg">${esc(t)}</div>`;
        const addrs = (n.ips || []).join(', ');
        // A hop that never answered still has a card. It is a real step on
        // the route and a reader who picks it deserves to be told what it is,
        // not handed an empty panel that reads like a fault.
        if (n.silent) {
          return `<h4>Hop ${n.index} &mdash; <span class="muted">no answer</span></h4>`
            + `<div class="endnote">Nothing replied at this position. The traffic still went through it &mdash; a router that does not answer a traceroute forwards perfectly well &mdash; so the step is kept and the numbering stays honest. There is nothing more to know about it: no address came back, so there is no name, no operator and no position.</div>`;
        }
        let h = `<h4>${n.endpoint ? 'Endpoint' : 'Hop ' + n.index} &mdash; <span class="mono">${esc(addrs)}</span></h4>`;
        if (n.endpoint) {
          h += `<div class="endnote">Traffic was going here; the hops before it are the way in. Click it on the map to follow the whole path from you.</div>`;
          if (n.bytes_in || n.bytes_out) {
            h += grp('Traffic, last 24 hours') + r('Received from it', bytes(n.bytes_in || 0)) + r('Sent to it', bytes(n.bytes_out || 0));
          }
          if (picked && (n.reaches || []).includes(picked) && route && route.talkers) h += talkersHTML(route.talkers, true);
        }
        if (n.anycast) {
          h += `<div class="endnote"><b>Anycast.</b> This address is announced from many datacentres at once${n.anycast_sites ? ` (the census has seen it served from ${num(n.anycast_sites)} sites)` : ''}${n.provider ? ` \u2014 ${esc(n.provider)}` : ''}. From here you are reaching a <b>local or regional instance</b>${n.location_source === 'identified' ? ', and it identified itself' : (n.location_source === 'anycast' || n.location_source === 'near') ? ', placed beside the hop before it' : ''}. A registered or remotely measured position for it says nothing about which instance that is.</div>`;
        }
        h += grp('Measured') + r('Round trip', n.rtt_ms ? n.rtt_ms + ' ms' : '');
        if (n.names && n.names.length) h += grp('Resolved') + r('Router name', n.names.join(', '));
        if (!d.pop_city && d.pop_why) h += r('Name suggests', d.pop_why, 'warn');
        if (d.pop_city) {
          h += grp('Site, read from the router name') + r('Code in the name', d.pop_code) + r('Site', d.pop_city);
          if (d.pop_score) h += r('Confidence', `${Math.round(d.pop_score * 100)}%${d.pop_how ? ' — matched as a ' + d.pop_how : ''}`, d.pop_score < 0.55 ? 'soft' : '');
          if (d.pop_why) h += r('How it was settled', d.pop_why, 'soft');
          if (n.database_said && n.location_source !== 'corrected') h += r('The database said', `${n.database_said} — ${num(Math.round(n.moved_km))} km away; the name is first-hand, so it wins`, 'warn');
        }
        if (n.location_source === 'corrected') {
          h += grp('Corrected') + r('The database said', `${n.database_said} — ${num(Math.round(n.moved_km))} km away`, 'warn')
             + r('Learned from', `${n.corrected_by}${n.corrected_at ? ', ' + FS.when(n.corrected_at) : ''} — a router in the same announced prefix, shown to be here; every address of the prefix now follows it`);
        }
        if (n.identity) {
          const q = n.identity;
          h += grp('Asked to identify itself') + r('It answered', q.id || '(no answer)', q.id ? '' : 'soft')
             + (q.site ? r('Which is', `${q.site}${q.letter ? ' \u2014 ' + q.letter + '.root-servers.net site' : ''}`) : '')
             + r('Read by', q.by || '', 'soft')
             + (q.located ? '' : r('Standing', 'not used for placement', 'soft'));
        }
        if (n.guess && n.location_source === 'assistant') {
          const q = n.guess;
          h += grp('Read by a language model') + r('Its answer', `${q.city}${q.country ? ', ' + q.country : ''} \u2014 ${Math.round((q.confidence || 0) * 100)}% confident`, 'soft')
             + (q.reason ? r('Its reasoning', q.reason, 'soft') : '')
             + r('Model', `${q.model}, ${FS.when(q.at)}`, 'soft')
             + r('Standing', 'a hypothesis: drawn as an inference, checked against the round trip, overruled by any source that knows', 'soft');
        }
        if (n.ips && n.ips.length && !n.silent) {
          const sd = d.shodan;
          h += grp('Shodan');
          if (sd && !sd.empty) {
            h += (sd.ports && sd.ports.length ? r('Open ports', sd.ports.join(', ')) : r('Open ports', 'none seen', 'soft'))
               + (sd.hostnames && sd.hostnames.length ? r('Seen as', sd.hostnames.slice(0, 6).join(', ')) : '')
               + (sd.org ? r('Organisation', sd.org + (sd.isp && sd.isp !== sd.org ? ' \u00b7 ' + sd.isp : '')) : '')
               + (sd.os ? r('Operating system', sd.os) : '')
               + (sd.city || sd.country ? r('Shodan\u2019s location', [sd.city, sd.country].filter(Boolean).join(', ') + ' (its record, not this map\u2019s placement)', 'soft') : '')
               + (sd.cpes && sd.cpes.length ? r('Products', sd.cpes.slice(0, 5).join(', '), 'soft') : '')
               + (sd.vulns && sd.vulns.length ? r('Known vulnerabilities', `${num(sd.vulns.length)}: ${sd.vulns.slice(0, 5).join(', ')}${sd.vulns.length > 5 ? ' \u2026' : ''}`, 'warn') : '')
               + (sd.tags && sd.tags.length ? r('Tags', sd.tags.join(', '), 'soft') : '')
               + r('Record', `${sd.keyed ? 'full host record' : 'InternetDB (free)'}, ${FS.when(sd.at)} \u00b7 <a href="https://www.shodan.io/host/${encodeURIComponent(n.ips[0])}" target="_blank" rel="noopener">open on shodan.io</a>`, 'soft');
          } else if (sd && sd.empty) {
            h += r('Shodan', `nothing on record for ${esc(n.ips[0])} \u00b7 <a href="https://www.shodan.io/host/${encodeURIComponent(n.ips[0])}" target="_blank" rel="noopener">shodan.io</a>`, 'soft');
          } else {
            h += `<div class="hr"><span></span><b><button type="button" class="btn small shodan-go" data-ip="${esc(n.ips[0])}">Look up on Shodan</button> <span class="muted small">ports, names, fingerprints, vulnerabilities; free without a key</span></b></div>`;
          }
        }
        if (d.fcc) {
          const f = d.fcc;
          h += grp('FCC broadband map') + r('Registered provider', `${esc(f.name)}${f.holding && f.holding !== f.name ? ' (' + esc(f.holding) + ')' : ''}`)
             + (f.states ? r('Reports fixed service in', `${num(f.states)} state${f.states === 1 ? '' : 's'}${f.locations ? ', ' + num(f.locations) + ' locations' : ''}`) : '')
             + (f.techs ? r('Technologies', esc(f.techs), 'soft') : '')
             + r('Standing', 'a national filing matched by name; it says the operator is a US broadband provider, not where this router is', 'soft');
        }
        if (d.abuse) {
          const a = d.abuse;
          h += grp('Reputation') + r('Abuse confidence', `${a.score}%${a.reports ? ` \u2014 ${num(a.reports)} report${a.reports === 1 ? '' : 's'}${a.reporters ? ` from ${num(a.reporters)} reporters` : ''}` : ' \u2014 no reports in 90 days'}${a.whitelisted ? ' (whitelisted)' : ''}${a.tor ? ' (Tor exit)' : ''}`, a.score >= 50 ? 'warn' : (a.score > 0 ? 'soft' : ''))
             + r('ISP', a.isp) + r('Usage type', a.usage_type) + r('Domain', a.domain)
             + (a.last_reported ? r('Last reported', a.last_reported.slice(0, 10), 'soft') : '')
             + r('Source', `${a.source}, ${FS.when(a.at)}`, 'soft');
        }
        if (d.asn) {
          h += grp('Who runs it') + r('Network', 'AS' + d.asn + (d.as_name ? '  ' + d.as_name : ''))
             + r('Announced prefix', d.prefix)
             + r('Registry', d.rir ? d.rir.toUpperCase() + (d.allocated ? ', allocated ' + d.allocated : '') : '')
             + r('Allocation', d.net_name) + r('Registrant', d.org)
             + r('Registrant address', d.org_addr ? d.org_addr + '  (head office, not this router)' : '', 'soft');
        }
        if ((d.facilities || []).length) {
          h += grp(d.facilities_scoped ? `Buildings this operator occupies in ${d.pop_city.split(',')[0]}` : 'Operator buildings, not narrowed to this hop');
          h += d.facilities.map(f => `<div class="hfac ${d.facilities_scoped ? '' : 'dim'}"><b>${esc(f.name)}</b>${f.address ? `<div class="muted small">${esc(f.address)}</div>` : ''}</div>`).join('');
          h += `<div class="muted small" style="margin-top:5px">${d.facilities_scoped
            ? 'One of these, most likely. An operator publishes which buildings it occupies; it does not publish which rack answers a traceroute.'
            : 'The router name gave no site, so this is everywhere that operator is. It is not evidence about this hop.'}</div>`;
        }
        h += grp('Placement');
        if (n.inferred) {
          h += `<div class="endnote">Nothing places this hop: no site in its name and no coordinates for its address block. It answered, though, and the hops either side of it are placed &mdash; so it has been put between them at the point its round trip falls between theirs. That is a guess about where, not about whether: the hop is certainly on this route.</div>`
            + r(n.location_source === 'near' ? 'Put beside' : 'Put between', (n.between || []).join(' and '))
            + r('By', n.between_how, 'soft')
            + r('Source', 'inferred from timing; it is not drawn as a located hop', 'soft');
        } else if (!n.located) {
          h += n.database_set_aside
            ? `<div class="muted small">It answered. ${n.anycast ? 'It is an <b>anycast</b> address: ' : 'The address database has coordinates for its block, but they are not believed: '}${esc(n.database_set_aside)}. It is listed under <em>Not on the map</em> rather than drawn somewhere it is not.</div>`
            : `<div class="muted small">It answered, but nothing places it: no site in its name, and the address database has no coordinates for the block. It is listed under <em>Not on the map</em> rather than drawn somewhere invented.</div>`;
        } else {
          h += r('Shown at', [n.city, n.region, n.country].filter(Boolean).join(', '))
            + r('Source', { name: 'the router\u2019s own name',
                             measured: 'RIPE IPmap \u2014 measured from thousands of probes, not registered',
                             corrected: 'a learned correction \u2014 the address database, overruled for this prefix',
                             provider: 'the provider\u2019s own published range list' + (n.provider ? ' \u2014 ' + n.provider : ''),
                             near: 'beside the last placed hop \u2014 the timing says the same metro',
                             identified: 'the server identified itself' + (n.identity ? ' as ' + n.identity.id + (n.identity.by ? ' \u2014 ' + n.identity.by : '') : ''),
                             anycast: 'anycast \u2014 the census site nearest the hop before it; a local or regional instance',
                             assistant: 'a language model\u2019s reading of the name \u2014 a hypothesis the clock did not rule out',
                             between: 'inferred from timing' }[n.location_source] || 'address database');
        }
        if (n.distance_km) h += r('Distance used', `${num(n.distance_km)} km${n.via ? ' along ' + n.via : ' (straight line)'}`);
        if (n.floor_ms) h += r('Light alone allows', `${n.floor_ms} ms — nothing can beat this${n.slack_km ? `, measured from ${num(n.slack_km)} km nearer in case your own position is out` : ''}`);
        if (n.expected_ms) h += r('A built route needs', `${n.expected_ms} ms${n.expected_via ? ' along ' + n.expected_via : ` over ${num(n.expected_km)} km once fibre's detours are allowed for`}`);
        if (n.why) h += r(n.impossible ? 'Impossible' : 'Too fast for the distance', n.why, 'warn');
        return h;
      };
      // Every card is rendered into the page rather than built on click, so
      // the detail is in the document a reader can search, print or save, and
      // the panel is never empty on arrival.
      // Anything that can be picked needs a card. Building them only for
      // placed hops meant clicking a silent step, or an unplaceable one, or
      // your own location emptied the panel -- which reads as a fault rather
      // than as an answer.
      const carded = [];
      const seenCard = {};
      located.concat(routeHops).forEach(n => {
        if (!n || seenCard[n.id]) return;
        seenCard[n.id] = 1;
        carded.push(n);
      });
      let hopCards = carded.map((n, i) =>
        `<div class="hopcard" data-for="${esc(n.id)}"${i ? ' hidden' : ''}>${hopCard(n)}</div>`).join('');
      if (home.ok) {
        const ins = route && route.inside;
        const where = home.detected ? [home.detected.city, home.detected.region, home.detected.country].filter(Boolean).join(', ') : '';
        hopCards += `<div class="hopcard" data-for="__origin" hidden>`
          + `<h4>You &mdash; <span class="mono">${esc(home.lat.toFixed(4))}, ${esc(home.lon.toFixed(4))}</span></h4>`
          + `<div class="endnote">Where every route on this map starts, and the point each hop's distance is measured from.</div>`
          + `<div class="hg">Origin</div>`
          + `<div class="hr"><span>Position</span><b>${esc(where || 'declared')}</b></div>`
          + `<div class="hr"><span>Source</span><b>${esc(home.source)}</b></div>`
          + ((home.public_v4 || []).length ? `<div class="hr"><span>Public IPv4</span><b class="mono">${esc((home.public_v4 || []).join(', '))}</b></div>` : '')
          + ((home.public_v6 || []).length ? `<div class="hr"><span>Public IPv6</span><b class="mono">${esc((home.public_v6 || []).join(', '))}</b></div>` : '')
          + (ins ? `<div class="hg">On this network</div><div class="hr"><span>Device</span><b>${esc(ins.name || ins.addresses[0])}</b></div>`
              + `<div class="hr"><span>Addresses</span><b class="mono">${esc(ins.addresses.slice(0, 3).join(', '))}${ins.addresses.length > 3 ? ` +${ins.addresses.length - 3}` : ''}</b></div>` : '')
          + `</div>`;
      }

      // The whole route, in the Route panel. The trail in the data drawer
      // tells the same story at length; this is the compact version that
      // stays in view while the reader is zoomed in on one corner of it --
      // every step from the machine inside the network to the endpoint,
      // with the place and the round trip, each row lighting its dot.
      const routeRows = () => {
        if (!picked || !routeHops.length) return '';
        const row = (o) => `<li class="rb${o.cls ? ' ' + o.cls : ''}" data-crumb="${esc(o.id)}">
            <span class="rbn">${esc(o.n)}</span><span class="rbm">${o.main}</span><span class="rbt">${esc(o.t || '')}</span>
            ${o.sub ? `<span class="rbs">${esc(o.sub)}</span>` : ''}</li>`;
        const rows = [];
        const ins = route.inside;
        if (ins) rows.push(row({ id: '__origin', cls: 'inside', n: 'in', main: `<b>${esc(ins.name || ins.addresses[0])}</b>`, sub: ins.addresses[0] }));
        routeHops.forEach((n, i) => {
          const last = i === routeHops.length - 1;
          if (n.silent) { rows.push(row({ id: n.id, cls: 'silent', n: '#' + n.index, main: '<span class="muted">no answer</span>' })); return; }
          const cls = [n.impossible ? 'bad' : (n.tight ? 'doubt' : ''), last ? 'endpoint' : ''].filter(Boolean).join(' ');
          const name = (n.names || [])[0] || '';
          rows.push(row({ id: n.id, cls, n: '#' + n.index, main: `<b>${esc(name || n.ips[0])}</b>`,
            t: n.rtt_ms ? n.rtt_ms.toFixed(n.rtt_ms < 10 ? 1 : 0) + ' ms' : '',
            sub: [name ? n.ips[0] : '', [n.city, n.country].filter(Boolean).join(', ') || (n.located ? '' : 'not placed')].filter(Boolean).join(' \u00b7 ') }));
        });
        return `<ol class="rbrows">${rows.join('')}</ol>`;
      };

      // The route as a trail, beginning inside the network.
      //
      // A traceroute's output starts at the first router that answered, which
      // is already one step out. Starting there asks the reader to supply the
      // beginning from memory, and the beginning -- which of their own
      // machines this was -- is usually the thing they came to find out.
      const crumbs = () => {
        if (!picked) return '';
        if (!routeHops.length) return `<div class="trailbox"><div class="muted small">No route stored for ${esc(picked)} yet.</div></div>`;
        const dest = (dests.destinations || []).find(d => d.dst === picked) || {};
        const one = (o) => {
          const cls = ['crumb'];
          if (o.silent) cls.push('silent');
          if (o.impossible) cls.push('bad');
          else if (o.doubtful) cls.push('doubt');
          if (o.kind) cls.push(o.kind);
          return `<li class="${cls.join(' ')}"${o.id ? ` data-crumb="${esc(o.id)}"` : ''}>
            <span class="ct">${esc(o.top)}</span>
            <span class="cm">${o.main}</span>
            ${o.sub ? `<span class="cs">${esc(o.sub)}</span>` : ''}</li>`;
        };
        const items = [];
        const ins = route.inside;
        if (ins) {
          items.push(one({ kind: 'inside', id: '__origin', top: 'inside', main: `<b>${esc(ins.name || ins.addresses[0])}</b>`,
            sub: ins.addresses.slice(0, 2).join(', ') + (ins.addresses.length > 2 ? ` +${ins.addresses.length - 2}` : '') }));
        }
        routeHops.forEach((n, i) => {
          const last = i === routeHops.length - 1;
          const where = [n.city, n.country].filter(Boolean).join(', ');
          if (n.silent) {
            items.push(one({ id: n.id, silent: true, top: 'hop ' + n.index, main: '<span class="muted">no answer</span>',
              sub: 'traffic passed through' }));
            return;
          }
          items.push(one({ id: n.id, impossible: !!n.impossible, doubtful: !!n.tight, kind: last ? 'endpoint' : '',
            top: (last ? 'endpoint \u00b7 hop ' : 'hop ') + n.index,
            main: `<b>${esc((n.names || [])[0] || n.ips[0])}</b>${n.ips.length > 1 ? ` <span class="muted">+${n.ips.length - 1}</span>` : ''}`,
            sub: [where, n.rtt_ms ? n.rtt_ms + ' ms' : ''].filter(Boolean).join(' \u00b7 ') }));
        });
        // A plain block rather than a card: it lives inside the map column
        // now, and a card inside a card is a border for the sake of one.
        return `<div class="trailbox">
          <div class="trailhead">Route to ${esc(dest.name || picked)}</div>
          <ol class="trail">${items.join('')}</ol>
          ${route.reached === false && route.probed_to ? `<div class="small muted" style="margin-top:6px">The destination did not answer the probe. The last reply came from hop ${num(route.last_answer)}; the probe went on to hop ${num(route.probed_to)} without a reply, and those steps are not shown. The traffic itself still got there: many servers answer connections and ignore probes.</div>` : ''}
          ${talkersHTML(route.talkers, false)}
          <div class="help" style="margin-top:8px">Left to right, from the machine on this network that made the connection to the address it reached. Hover a step to pick it out on the map. A step with no answer still carried the traffic; its position is kept so the numbering stays honest.${route.inside ? '' : ' No flow records name the device that used this route, so the trail begins at the first router.'}</div>
          <div class="actions" style="margin-top:8px"><button class="btn small" id="r-clear">Show every route</button></div>
        </div>`;
      };
      const trail = crumbs();

      // Built before the template so it is part of the page, not appended to it.
      // Two tables, because the claims differ. One says a reading is
      // disproved; the other says it is only doubted, and running them
      // together would either accuse the doubtful or excuse the disproved.
      // Each table is measured against the number its own verdict used.
      //
      // They shared one set of columns and the shared column was the
      // speed-of-light floor, so the doubtful table showed a hop answering in
      // 19.4 ms against a floor of 19.3 and called it too fast. The verdict
      // was right and the arithmetic printed beside it said the opposite,
      // which is worse than printing nothing.
      const plHead = [
          { t: 'Hop', f: r => num(r.index), num: true, sort: 'index' },
          { t: 'Address', f: r => `<span class="mono small">${esc(r.ips)}</span>`, sort: 'ips' },
          { t: 'Placed at', f: r => esc(r.where) || '<span class="muted">unknown</span>', sort: 'where' },
          { t: 'Answered in', f: r => `${r.rtt} ms`, num: true, sort: 'rtt' }];
      const plTail = [
          { t: 'Away', f: r => `${num(r.km)} km`, num: true, sort: 'km' },
          { t: 'Measured', f: r => r.via ? `<span class="small">along ${esc(r.via)}</span>` : '<span class="muted small">straight line</span>', sort: 'via' }];
      const shortBy = (k) => ({ t: 'Short by', num: true, sort: 'rtt',
          f: r => r[k] > 0 ? `${(r[k] - r.rtt).toFixed(1)} ms` : '—' });
      const impossibleCols = plHead.concat(
          [{ t: 'Light alone needs', f: r => `${r.floor} ms${r.slack ? `<div class="muted small">allowing ${num(r.slack)} km for your own position</div>` : ''}`, num: true, sort: 'floor' }, shortBy('floor')], plTail);
      const doubtfulCols = plHead.concat(
          [{ t: 'A built route needs', f: r => r.expected ? `${r.expected} ms` : '—', num: true, sort: 'expected' },
           shortBy('expected'),
           { t: 'Light alone allows', f: r => `${r.floor} ms`, num: true, sort: 'floor' }], plTail);
      const plRow = (n) => ({ index: n.index, ips: n.ips.join(', '),
          where: [n.city, n.region, n.country].filter(Boolean).join(', '),
          rtt: n.rtt_ms, floor: n.floor_ms, expected: n.expected_ms, km: n.distance_km, via: n.via || '', slack: n.slack_km || 0 });
      const doubtful = nodes.filter(n => n.tight);
      const doubtOut = doubtful.length ? `<div style="margin-top:14px">${card('Placements too fast for any built route', table(doubtful.map(plRow), doubtfulCols),
          'read the middle two columns together: each answered sooner than the route to it could deliver, which is the whole verdict. The last column is the speed-of-light floor and sits below the time measured, because that is not what ruled on them. Being slow is never suspicious — congestion and indirect routing explain themselves. Being too fast is, because the only thing that makes a reply quicker is the place being nearer. So these are wrong in the same direction as the table above, and for the same reason: the coordinates, not the measurement — just not provably')}</div>` : '';

      // Two kinds of ruled-out placement share the table. One came from a
      // router's own name and is still drawn where the name says, as an
      // accusation to be read. The other came from a database, a
      // measurement service or a learned correction, and has been taken off
      // the map: the source was simply wrong, and the hop is placed by
      // timing instead.
      const rejected = (g.rejected || []).map(r => ({
          index: r.index, ips: (r.ips || []).join(', '), where: r.where, rtt: r.rtt_ms, floor: r.floor_ms, km: 0, via: '',
          by: { database: 'address database', measured: 'RIPE IPmap', corrected: 'learned correction', provider: 'provider range list' }[r.source] || r.source,
          now: 'set aside — not drawn there' }));
      const accused = impossible.map(n => ({
          index: n.index, ips: n.ips.join(', '),
          where: [n.city, n.region, n.country].filter(Boolean).join(', '),
          rtt: n.rtt_ms, floor: n.floor_ms, km: n.distance_km, via: n.via || '',
          by: 'the router\u2019s own name', now: 'still drawn there; the name is first-hand' }));
      const rulesOut = (impossible.length || rejected.length) ? `<div style="margin-top:14px">${card('Placements the physics rules out', table(accused.concat(rejected), [
          { t: 'Hop', f: r => num(r.index), num: true, sort: 'index' },
          { t: 'Address', f: r => `<span class="mono small">${esc(r.ips)}</span>`, sort: 'ips' },
          { t: 'Said to be at', f: r => esc(r.where) || '<span class="muted">unknown</span>', sort: 'where' },
          { t: 'Said by', f: r => esc(r.by), sort: 'by' },
          { t: 'Answered in', f: r => `${r.rtt} ms`, num: true, sort: 'rtt' },
          { t: 'Light alone needs', f: r => `${r.floor} ms`, num: true, sort: 'floor' },
          { t: 'Now', f: r => `<span class="small ${r.now.indexOf('set aside') === 0 ? 'muted' : 'sev-med'}">${esc(r.now)}</span>`, sort: 'now' },
          { t: 'Short by', f: r => r.floor > 0 ? `${(r.floor - r.rtt).toFixed(1)} ms` : '—', num: true, sort: 'floor' },
          { t: 'Away', f: r => `${num(r.km)} km`, num: true, sort: 'km' },
          { t: 'Measured', f: r => r.via ? `<span class="small">along ${esc(r.via)}</span>` : '<span class="muted small">straight line</span>', sort: 'via' }]),
          'light in fibre covers about 200,000 km/s, so nothing can answer sooner than twice the distance divided by that. Between continents the distance is measured along the shortest cable that joins the two, not across the map: cables follow shelves and come ashore where there is a station, so the real journey is longer than the straight line and the floor correspondingly higher')}</div>` : '';

      const countries = {};
      nodes.forEach(n => { if (n.country) countries[n.country] = (countries[n.country] || 0) + 1; });

      // One panel's frame. The panel manager adopts these by their data-panel
      // name, so the content is in the document from the first paint and a
      // reader (or a test) can find it without waiting for anything to run.
      const panelHTML = (id, title, html, cls) => `<section class="fspanel${cls ? ' ' + cls : ''}" data-panel="${id}" tabindex="0" aria-label="${esc(title)}">
          <header class="fsph"><span class="grip" aria-hidden="true">⠿</span><span class="fspt">${esc(title)}</span>
          <span class="fspa"><button type="button" class="fspfold" title="Fold to the title (Esc)" aria-expanded="true">▁</button><button type="button" class="fspclose" title="Close; bring it back from Panels" aria-label="Close ${esc(title)}">×</button></span></header>
          <div class="fspb">${html}</div><i class="fspr" aria-hidden="true"></i></section>`;
      const destName = picked ? ((dests.destinations || []).find(d => d.dst === picked) || {}).name || picked : '';

      // The key. Nothing on this map is self-evident: a thick grey line and a
      // thin coloured one are opposite claims, and a red ring is a statement
      // about physics. Each entry is also a switch for the thing it
      // describes; a key that only names the marks leaves a reader to pick
      // one kind of line out of twelve hundred by eye.
      const legendHTML = (() => {
        const sw = (cls, style) => `<svg class="lg" viewBox="0 0 22 10" aria-hidden="true"><line class="${cls}" style="${style || ''}" x1="1" y1="5" x2="21" y2="5"/></svg>`;
        const dot = (fill, cls) => `<svg class="lg" viewBox="0 0 12 12" aria-hidden="true"><circle class="${cls || ''}" cx="6" cy="6" r="3.4" fill="${fill || 'none'}"/></svg>`;
        const it = (mark, text, layer) => layer
          ? `<button type="button" class="lgi" data-layer="${layer}" aria-pressed="true">${mark}<span>${esc(text)}</span></button>`
          : `<span class="lgi">${mark}${esc(text)}</span>`;
        return `<div class="legend" id="maplegend"><div class="lgitems">
          ${it(sw('leg shared', 'stroke:var(--muted)'), 'a leg several destinations share', 'shared')}
          ${it(sw('leg', 'stroke:' + FS.palette[0]), 'a leg used by one destination', 'single')}
          ${it(`<svg class="lg" viewBox="0 0 22 10" aria-hidden="true"><line class="leg" style="stroke:var(--ink)" x1="1" y1="5" x2="14" y2="5"/><polygon points="13,1.8 20,5 13,8.2" fill="var(--ink)"/></svg>`, 'direction of travel, hop to hop', 'arrows')}
          ${(cab.cables || []).length ? it(sw('cable'), 'submarine cable', 'cable') : ''}
          ${it(`<svg class="lg" viewBox="0 0 12 12" aria-hidden="true"><circle class="homering" cx="6" cy="6" r="4.5"/><circle class="home" cx="6" cy="6" r="2"/></svg>`, 'you', 'you')}
          ${it(`<svg class="lg" viewBox="0 0 12 12" aria-hidden="true"><circle class="endpoint" cx="6" cy="6" r="4.6"/><circle cx="6" cy="6" r="2.2" fill="${FS.palette[2]}"/></svg>`, 'an endpoint: traffic was going here', 'endpoint')}
          <button type="button" class="lgi lgmode" data-mode="traffic" aria-pressed="false">${`<svg class="lg" viewBox="0 0 12 12" aria-hidden="true"><circle class="endpoint" cx="6" cy="6" r="5.4"/><circle class="endpoint" cx="6" cy="6" r="2.4"/></svg>`}<span>size endpoints by traffic</span></button>
          ${it(dot(FS.palette[2]), 'a hop it crossed on the way', 'hop')}
          ${it(dot(FS.palette[1], 'measured'), 'position measured, not registered', 'measured')}
          ${it(dot(FS.palette[5], 'provider'), 'position from the provider’s own range list', 'provider')}
          ${it(dot('', 'guessed'), 'answered but unplaceable: put between its neighbours by timing', 'guessed')}
          ${it(dot(FS.palette[2], 'rich'), 'operator known', 'rich')}
          ${it(dot('', 'ruledout'), 'the latency rules this placement out', 'ruledout')}
          ${it(dot('', 'doubtful'), 'too fast for any built route', 'doubtful')}
          ${it(sw('leg gapleg', 'stroke:var(--muted)'), 'the route continues through hops with no known position', 'gap')}
          ${it(sw('leg sea', 'stroke:' + FS.palette[4]), 'a sea crossing, drawn along its likeliest cable', 'sea')}
          ${it(sw('corrected'), 'correction: database → the site in the router’s name', 'corrected')}
          ${picked ? it(sw('leg onroute', 'stroke:' + FS.palette[0]), 'the route you picked; the rest is dimmed', 'onroute') : ''}
          </div></div>`;
      })();

      // The data drawer: everything that used to sit under and beside the
      // map, one tab each, folded to a line of numbers until it is wanted.
      const S = st.sources || {};
      const sourcesHTML = (() => {
        const row = (name, on, detail, err) => `<tr><td>${esc(name)}</td><td>${on ? pill('on', 'ok') : pill('off', '')}</td><td class="small">${detail}</td><td class="small sev-high">${esc(err || '')}</td></tr>`;
        const ipm = S.ipmap || {}, cabS = S.cables || {}, land = S.land_routes || {}, reg = S.registry || {}, nm = S.router_names || {}, fx = S.corrections || {}, osm = S.osm_telecom || {}, pv = S.providers || {};
        const rep = S.reputation || {}, gf = S.geofeeds || {}, ai = S.assistant || {}, idn = S.identify || {}, shd = S.shodan || {}, fcc = S.fcc || {};
        const pvFeeds = Object.values(pv.feeds || {});
        const pvText = pvFeeds.length ? pvFeeds.map(f => `${f.name} ${num(f.prefixes || 0)}${f.error ? ' (failed)' : ''}`).join(' · ') : 'nothing fetched yet';
        const pvErr = pvFeeds.filter(f => f.error).map(f => `${f.name}: ${f.error}`).join('; ');
        const backoff = ipm.backing_off_until && ipm.backing_off_until * 1000 > Date.now() ? ` — backing off until ${FS.when(ipm.backing_off_until)}` : '';
        return card('Data sources', `<table>
          <tr><th>Source</th><th></th><th>State</th><th></th></tr>
          ${row('Router names', nm.on, `${num(nm.codes || 0)} site codes known, plus spelled-out and shortened forms`)}
          ${row('RIPE IPmap', ipm.on, `${num(ipm.answered || 0)} positions known (${num(ipm.this_session || 0)} this session), ${num(ipm.queued || 0)} waiting, ${num(ipm.per_minute || 0)} a minute${backoff}`)}
          ${row('Routing table &amp; registry', reg.on, `${num(reg.queued || 0)} addresses waiting for their operator`)}
          ${row('Submarine cables', cabS.on, cabS.on ? `${num(cabS.loaded || 0)} cables loaded` : 'not loaded', cabS.error)}
          ${row('Land routes', land.on, land.on ? `${num(land.loaded || 0)} routes loaded` : 'not loaded', land.error)}
          ${row('FCC broadband map', fcc.on, fcc.on ? (fcc.as_of ? `release ${esc(fcc.as_of)}, ${num(fcc.files || 0)} files listed${fcc.providers ? `; kept ${num(fcc.providers)} providers${fcc.state ? `, ${num(fcc.places || 0)} places in ${esc(fcc.state)}` : ''}` : ''}; checked ${FS.when(fcc.checked_at)}` : 'credentials entered, not yet checked') + ` <button type="button" class="btn small" id="fcc-check">Check FCC access</button> <button type="button" class="btn small" id="fcc-pull">Pull FCC data</button>` : 'no account — enter the username and API token under Settings › paths › FCC broadband map', fcc.error)}
          ${row('Shodan', shd.mode && shd.mode !== 'off', shd.mode === 'off' ? 'off' : `${shd.mode === 'all' ? 'every hop' : 'on click'}, ${shd.keyed ? 'with a key (full records)' : 'no key (InternetDB only)'}: ${num(shd.known || 0)} addresses on record`, shd.error)}
          ${row('Servers identifying themselves', idn.on, idn.on ? `${num(idn.known || 0)} anycast servers asked, ${num(idn.placed_this_session || 0)} placed this session, ${num(idn.queued || 0)} waiting; ${num(idn.root_sites || 0)} root-server sites on file` : 'off')}
          ${row('AI lookup', ai.on, ai.on ? `${esc(ai.provider)} / ${esc(ai.model)}: ${num(ai.known || 0)} hops answered, ${num(ai.queued || 0)} waiting, ${num(ai.per_hour || 0)} an hour` : 'off — choose a provider under Settings › paths › AI lookup', ai.error)}
          ${row('AbuseIPDB reputation', rep.on, rep.on ? `${num(rep.known || 0)} addresses known (${num(rep.asked_this_session || 0)} asked this session)` : 'no key — set one under Settings › paths › Reputation', rep.error)}
          ${row('Cloud provider ranges', pv.on, pv.on ? `${num(pv.prefixes || 0)} prefixes: ${pvText}` : 'off', pvErr)}
          ${row('Registry geofeeds', gf.on, gf.on ? `${num(gf.urls || 0)} feeds named in registry objects, ${num(gf.fetched || 0)} fetched, ${num(gf.rows || 0)} placed prefixes${gf.failed ? `, ${num(gf.failed)} failing` : ''}` : 'off')}
          ${row('OpenStreetMap telecom lines', osm.on, osm.on ? `${num(osm.ways || 0)} lines from ${num(osm.regions_loaded || 0)} of ${num(osm.regions_total || 0)} regions, counted at ${Math.round((osm.weight || 0) * 100)}%${osm.next_region ? ` — next: ${esc(osm.next_region)}` : ''}${osm.backing_off_until && osm.backing_off_until * 1000 > Date.now() ? ` — backing off until ${FS.when(osm.backing_off_until)}` : ''}` : 'off', osm.error)}
          ${row('Learned corrections', fx.on, `${num(fx.prefixes || 0)} prefixes placed by their own routers, ${num(fx.set_aside || 0)} registrant addresses set aside`)}
        </table>`, `each is a setting under <a href="#modules/paths">Settings › paths</a>, grouped under <em>Where things are</em>`);
      })();
      const locationHTML = card('Your location', `
        <div class="small">${home.ok
          ? `Drawing from <b>${home.lat.toFixed(4)}, ${home.lon.toFixed(4)}</b> <span class="muted">(${esc(home.source)})</span>`
          : `<span class="sev-high">Not known yet.</span> Without it the map has no origin and nothing can be checked against the speed of light.`}</div>
        ${(() => {
          const v4 = home.public_v4 || [], v6 = home.public_v6 || [];
          if (!v4.length && !v6.length) return `<div class="muted small" style="margin-top:4px">No public address found on this gateway&rsquo;s own interfaces.</div>`;
          const one = (ip) => `<span class="mono">${esc(ip)}</span>${ip === home.public_address && (v4.length + v6.length) > 1 ? ' <span class="muted">(used for the origin)</span>' : ''}`;
          const line = (label, ips) => ips.length ? `<div class="small" style="margin-top:3px"><span class="muted" style="display:inline-block;min-width:46px">${label}</span>${ips.map(one).join(', ')}</div>` : '';
          return line('IPv4', v4) + line('IPv6', v6);
        })()}
        ${home.detected && (home.detected.lat || home.detected.lon) ? `<div class="muted small" style="margin-top:4px">That address is registered near ${esc([home.detected.city, home.detected.region, home.detected.country].filter(Boolean).join(', '))} &mdash; usually the right town, occasionally the wrong state.</div>` : ''}
        <div class="actions" style="margin-top:8px">
          <input id="h-lat" style="width:110px" placeholder="latitude" value="${home.ok ? home.lat.toFixed(4) : ''}">
          <input id="h-lon" style="width:110px" placeholder="longitude" value="${home.ok ? home.lon.toFixed(4) : ''}">
          <button class="btn primary" id="h-save">Save</button>
          <button class="btn" id="h-browser">Use this browser's location</button>
          ${home.detected && (home.detected.lat || home.detected.lon) ? `<button class="btn" id="h-detect">Use the public address</button>` : ''}
          ${home.configured ? `<button class="btn" id="h-clear">Go back to detecting it</button>` : ''}
        </div>
        <div class="help" style="margin-top:6px">${esc(home.note || '')}</div>`);
      const overviewHTML = `<div class="grid cols-4">
        ${kpi('Destinations with a route', num((dests.destinations || []).length), `${num(st.hops)} hops measured`)}
        ${kpi('Placed on the map', num(located.length), `${num(unlocated.length)} have no coordinates`, unlocated.length > located.length ? 'warn' : '')}
        ${kpi('Ruled out by latency', num(impossible.length), impossible.length ? 'too far away to have answered that fast' : 'every placement is possible', impossible.length ? 'bad' : '')}
        ${card('Tracing', st.active ? `<div>${pill('on', 'ok')}</div><div class="small muted" style="margin-top:6px">Last run ${st.last_run > 0 ? ago(st.last_run) : 'not yet'}.</div>`
          : `<div>${pill('off', '')}</div><div class="small muted" style="margin-top:6px">Switch it on in <a href="#modules?m=paths">Settings &rsaquo; paths</a>. Nothing is probed that this network has not already contacted.</div>`)}</div>`;
      const unlocatedHTML = (unlocated.length || silent) ? `<div class="unlocated">${card('Not on the map', table(unlocated.map(n => ({
          index: n.index, ips: n.ips.join(', '), names: (n.names || []).join(', '), country: n.country || '',
          why: n.database_set_aside ? 'database not believed: ' + n.database_set_aside : 'no site in the name, no coordinates for the block' })), [
          { t: 'Hop', f: r => num(r.index), num: true, sort: 'index' },
          { t: 'Address', f: r => `<span class="mono small">${esc(r.ips)}</span>`, sort: 'ips' },
          { t: 'Name', f: r => esc(r.names) || '<span class="muted">none</span>', sort: 'names' },
          { t: 'Country', f: r => r.country ? FS.cc(r.country, { cls: '' }) : '<span class="muted">unknown</span>', sort: 'country' },
          { t: 'Why', f: r => `<span class="small ${r.why.indexOf('not believed') === 0 ? 'sev-med' : 'muted'}">${esc(r.why)}</span>`, sort: 'why' }],
          { empty: 'Every hop has coordinates.' }),
          `${num(silent)} hop${silent === 1 ? '' : 's'} never answered and are not shown at all`)}</div>` : '<div class="muted small">Every hop has coordinates.</div>';
      const destinationsHTML = card('Destinations', table(dests.destinations || [], [
        { t: 'Destination', f: r => `<a href="#paths?${esc(routeQ(r.dst))}"><b>${esc(r.name || r.dst)}</b></a>${r.name ? `<div class="muted small mono">${esc(r.dst)}</div>` : ''}`, sort: 'dst' },
        { t: 'Where', f: r => (r.city || r.country) ? `${esc(r.city || '')}${r.city && r.country ? ', ' : ''}${r.country ? FS.cc(r.country, { cls: '' }) : ''}` : '<span class="muted">unknown</span>', sort: 'country' },
        { t: 'Hops', f: r => num(r.hops), num: true, sort: 'hops' },
        { t: 'In / out (24h)', f: r => (r.bytes_in || r.bytes_out) ? `${bytes(r.bytes_in || 0)} / ${bytes(r.bytes_out || 0)}` : '<span class="muted">—</span>', num: true, sort: 'bytes_in' },
        { t: 'Answered', f: r => num(r.answered), num: true, sort: 'answered' },
        { t: 'Reached', f: r => r.complete ? pill('yes', 'ok') : pill('no', ''), sort: 'complete' },
        { t: 'Traced', f: r => ago(r.ts), sort: 'ts' }],
        { empty: 'Nothing traced yet.' }));
      const aboutHTML = `<details class="maphelp" id="maphelp">
          <summary>About this map</summary>
          <div class="help" style="margin-top:6px">Land outlines are Natural Earth 1:110m, public domain. ${(cab.cables || []).length ? `${num(cab.cables.length)} submarine cables drawn behind the routes. ${esc(cab.attribution || '')} A traceroute never names a cable, so hovering a long leg shows which ones <em>could</em> have carried it, after discarding any too long to have produced the latency measured. ` : ''}Wheel to zoom, drag to pan. A thick grey line is a leg several destinations share. Coloured lines belong to one destination each. Coordinates come from an address database: dependable for end-user addresses and rough for carrier equipment, which is why placements the measured latency rules out are circled rather than trusted. Where a router's hostname carries a site code, that is used instead of the database, and an amber line shows where the two disagreed.</div>
        </details>
        <div class="help" style="margin-top:8px">Panels: drag one by its title; near an edge it docks. Double-click a title to send it home, fold with the small button, and bring closed ones back from <b>Panels</b> in the toolbar. The arrangement is kept in this browser.</div>`;
      const tabs = [
        ['overview', 'Overview', overviewHTML],
        ['sources', 'Data sources', sourcesHTML],
        ['location', 'Location', locationHTML],
        ['physics', `Physics${(impossible.length + rejected.length + doubtful.length) ? ' · ' + num(impossible.length + rejected.length + doubtful.length) : ''}`, (rulesOut || doubtOut) ? rulesOut + doubtOut : '<div class="muted small">Every placement is possible: nothing answered faster than the distance allows.</div>'],
        ['unplaced', `Not on the map${unlocated.length ? ' · ' + num(unlocated.length) : ''}`, unlocatedHTML],
        ['destinations', `Destinations · ${num((dests.destinations || []).length)}`, destinationsHTML],
        ['route', 'Route', trail || '<div class="muted small">Pick a destination on the map, in the Destinations tab, or by clicking an endpoint, and the whole route is laid out here.</div>'],
        ['about', 'About', aboutHTML]];
      let dataTab = 'overview';
      try { dataTab = localStorage.getItem('fs.mapdata.tab') || 'overview'; } catch (e) { }
      if (!tabs.some(t => t[0] === dataTab)) dataTab = 'overview';
      const dataHTML = `<div class="datatabs" role="tablist">${tabs.map(t => `<button type="button" role="tab" data-tab="${t[0]}" class="${t[0] === dataTab ? 'on' : ''}" aria-selected="${t[0] === dataTab}">${t[1]}</button>`).join('')}</div>`
        + tabs.map(t => `<div class="datapane" data-pane="${t[0]}" ${t[0] === dataTab ? '' : 'hidden'}>${t[2]}</div>`).join('');
      const dataTitle = `Data · ${num((dests.destinations || []).length)} routes · ${num(located.length)} placed · ${num(impossible.length)} ruled out`;

      el.innerHTML = `
      <div class="mapcanvas" id="mapcanvas">
        <div class="mapstage" id="mapstage">
        <svg class="pathmap" id="pathmap" viewBox="0 0 ${MAPW} ${MAPH}" preserveAspectRatio="xMidYMid meet">
          ${/* Land and cables are the heavy part -- one long outline and up to a
                couple of thousand cable runs -- so the copies either side
                reference them rather than repeat them. Their styling is inline:
                a <use> renders a shadow copy that a descendant selector does not
                reach, and var() still resolves inline, so the theme is kept. */''}
          <defs>
            <clipPath id="fs-world-clip"><rect x="0" y="0" width="${MAPW}" height="${MAPH}"/></clipPath>
            <g id="fs-world">
            ${FS.landPath ? `<path class="land" style="fill:color-mix(in srgb, var(--ink) 13%, transparent);stroke:var(--line);stroke-width:.4;vector-effect:non-scaling-stroke" d="${FS.landPath}"/>` : ''}
            <g class="cablegroup" style="fill:none;stroke:var(--line);stroke-width:.6;opacity:.9;vector-effect:non-scaling-stroke">${cables}</g>
          </g></defs>
          <g class="stage">
          <use class="worldcopy" href="#fs-world" x="${-MAPW}"/><use href="#fs-world"/><use class="worldcopy" href="#fs-world" x="${MAPW}"/>
          ${/* Routes and markers are drawn for real, a world either side: a <use>
                copy cannot be clicked, and a reader who pans past the edge would
                find a map whose hops no longer answer. */''}
          ${[-MAPW, 0, MAPW].map(dx => `<g class="${dx ? 'worldcopy' : ''}" transform="translate(${dx},0)">${FS.graticule(MAPW, MAPH, 30)}${lines}${arrows}${labels}${dots}${originArt}</g>`).join('')}
          </g>
        </svg>
        <div class="hovercard" id="hovercard" hidden></div>
        </div>
        ${/* Filters act on choice: a select applies itself, the typed boxes apply
              on Enter or when they lose focus. No Apply button, because a
              filter chosen and not applied is a filter that is lying. */''}
        <div class="maptoolbar" role="toolbar" aria-label="Where the traffic goes">
          <label class="tool"><span class="lbl">Country</span>
            <select id="f-country"><option value="">any</option>${Object.keys(countries).sort().map(c => `<option value="${esc(c)}" ${ctx.params.country === c ? 'selected' : ''}>${esc(c)} · ${esc(FS.countryName(c))} (${countries[c]})</option>`).join('')}</select></label>
          <label class="tool"><span class="lbl">Device</span>
            <select id="f-dev"><option value="">every device</option>${(ctx.params.device || '').includes(',') ? `<option value="${esc(ctx.params.device)}" selected>${ctx.params.device.split(',').length} devices through the clicked hop</option>` : ''}${(devs.devices || []).map(d => {
              const sel = (d.addresses || []).includes(ctx.params.device) ? 'selected' : '';
              const n = (d.addresses || []).length;
              return `<option value="${esc(d.key)}" ${sel}>${esc(d.name || d.key)} &middot; ${d.destinations} dest${n > 1 ? ` (${n} addresses)` : ''}</option>`;
            }).join('')}</select></label>
          <label class="tool"><span class="lbl">Slower than</span><input id="f-lat" type="number" min="0" value="${esc(ctx.params.max_latency || '')}" placeholder="any"><span class="lbl">ms</span></label>
          <label class="tool"><span class="lbl">Within</span><input id="f-hops" type="number" min="1" max="64" value="${esc(ctx.params.max_hops || '')}" placeholder="any"><span class="lbl">hops</span></label>
          <button class="btn small" id="f-clear">Clear</button>
          ${/* Shown once a hop has narrowed the map. Anything that hides most of
                what was on screen has to say so and be undoable in one click. */''}
          <span class="mapfilter" id="mapfilter" hidden><span id="mapfilter-text"></span><button type="button" id="mapfilter-next" class="linkish" hidden title="Load the next route through this hop">next &rsaquo;</button><button type="button" id="mapfilter-off" aria-label="Show every route">&times;</button></span>
          <span class="sp"></span>
          <button class="btn small" id="panels-menu" title="Show, hide or reset the panels">Panels</button>
        </div>
        <div class="mapzoom"><button type="button" id="z-in" title="Zoom in">+</button><button type="button" id="z-out" title="Zoom out">&minus;</button><button type="button" id="f-reset" title="The whole world">&#8962;</button></div>
        ${picked && routeHops.length ? panelHTML('route', 'Route to ' + destName, routeRows()
          + ((route && route.talkers) ? talkersHTML(route.talkers, true) : '')
          + `<div class="actions" style="margin-top:8px"><button class="btn small" id="r-clear">Show every route</button></div>`) : ''}
        ${panelHTML('hop', 'Hop detail', `<div class="hpbody">${hopCards || '<div class="muted small">No hop has coordinates yet.</div>'}</div>
          <div class="muted small hphint">Hover or click any hop on the map, or any step in the route, for who runs it, where it is, and how that was decided.</div>`, 'hoppanel')}
        ${panelHTML('key', 'Key', legendHTML)}
        ${panelHTML('data', dataTitle, dataHTML)}
      </div>`;


      const saveHome = async (lat, lon) => {
        const r = await post('/api/paths/home', { lat: lat, lon: lon });
        FS.toast(r.error || 'Location saved', !!r.error);
        if (!r.error) FS.render();
      };
      FS.$('#h-save', el).onclick = () => {
        const la = parseFloat(FS.$('#h-lat', el).value), lo = parseFloat(FS.$('#h-lon', el).value);
        if (isNaN(la) || isNaN(lo)) { FS.toast('Give a latitude and a longitude', true); return; }
        saveHome(la, lo);
      };
      const browserBtn = FS.$('#h-browser', el);
      if (browserBtn) browserBtn.onclick = () => {
        if (!navigator.geolocation) { FS.toast('This browser will not share a location', true); return; }
        FS.toast('Asking the browser…');
        navigator.geolocation.getCurrentPosition(
          (p) => saveHome(p.coords.latitude, p.coords.longitude),
          (e) => FS.toast('The browser declined: ' + (e && e.message ? e.message : 'no reason given'), true),
          { enableHighAccuracy: false, timeout: 15000, maximumAge: 600000 });
      };
      const detectBtn = FS.$('#h-detect', el);
      if (detectBtn) detectBtn.onclick = () => saveHome(home.detected.lat, home.detected.lon);
      const clearBtn = FS.$('#h-clear', el);
      if (clearBtn) clearBtn.onclick = async () => {
        const r = await post('/api/paths/home', { clear: true });
        FS.toast(r.error || 'Back to detecting it', !!r.error);
        if (!r.error) FS.render();
      };

      // Each key entry switches its own layer off and on, remembered per
      // reader. The switches live on the svg as off-<layer> classes so the
      // work is one class change rather than a walk over twelve hundred
      // elements.
      const svgEl = FS.$('#pathmap', el);
      // The current zoom, kept up to date by the pan/zoom handler below and
      // read by the key's traffic switch, which runs before that handler is
      // built -- so it is declared here, ahead of both.
      let lastZ = 1;
      if (svgEl) {
        let off = {};
        try { off = JSON.parse(localStorage.getItem('fs.maplayers') || '{}') || {}; } catch (e) { }
        const paint = () => {
          el.querySelectorAll('.lgi[data-layer]').forEach(b => {
            const k = b.getAttribute('data-layer'), hidden = !!off[k];
            svgEl.classList.toggle('off-' + k, hidden);
            b.setAttribute('aria-pressed', hidden ? 'false' : 'true');
            b.classList.toggle('lgoff', hidden);
          });
          try { localStorage.setItem('fs.maplayers', JSON.stringify(off)); } catch (e) { }
        };
        el.querySelectorAll('.lgi[data-layer]').forEach(b => {
          b.onclick = () => {
            const k = b.getAttribute('data-layer');
            if (off[k]) delete off[k]; else off[k] = 1;
            paint();
          };
        });
        paint();
        // Sizing endpoints by traffic is a way of reading the map rather than
        // a layer of it, so it is a mode: off unless asked for, remembered.
        const tb = el.querySelector('.lgmode[data-mode="traffic"]');
        if (tb) {
          let onT = false;
          try { onT = localStorage.getItem('fs.maptraffic') === '1'; } catch (e) { }
          const setT = (v) => {
            onT = v;
            svgEl.classList.toggle('traffic', v);
            tb.setAttribute('aria-pressed', v ? 'true' : 'false');
            try { localStorage.setItem('fs.maptraffic', v ? '1' : '0'); } catch (e) { }
            // Re-run the sizing at the current zoom so the change shows now.
            const byTraffic = v;
            svgEl.querySelectorAll('[data-r]').forEach(c => {
              const base = byTraffic && c.hasAttribute('data-rt') ? c.getAttribute('data-rt') : c.getAttribute('data-r');
              c.setAttribute('r', (parseFloat(base) / lastZ).toFixed(2));
            });
          };
          tb.onclick = () => setT(!onT);
          setT(onT);
        }
      }

      // Folded or not is a per-reader preference, so it is remembered here and
      // nowhere else; losing it costs nothing.
      // Whether the notes are open is the same kind of preference as the key.
      const mh = FS.$('#maphelp', el);
      if (mh) {
        try { mh.open = localStorage.getItem('fs.maphelp') === '1'; } catch (e) { }
        mh.addEventListener('toggle', () => {
          try { localStorage.setItem('fs.maphelp', mh.open ? '1' : '0'); } catch (e) { }
        });
      }

      // The panels: adopted by name, laid out from what this browser
      // remembers, and put back by the Panels menu. The hop panel is docked
      // right and as tall as the map; the route sits top-left under the
      // toolbar; the key and the data drawer wait folded along the bottom.
      const canvas = FS.$('#mapcanvas', el);
      const toolbarEl = FS.$('.maptoolbar', el);
      const panels = FS.panels && canvas ? FS.panels.mount(canvas, { key: 'paths', insetTop: () => (toolbarEl && toolbarEl.offsetHeight ? toolbarEl.offsetHeight + 10 : 44), panels: [
        { id: 'route', title: 'Route', home: { ax: 'l', ay: 't', x: 10, y: 8, w: 320, h: 380 } },
        { id: 'hop', title: 'Hop detail', home: { ax: 'r', ay: 't', x: 10, y: 8, w: 360, fill: true, gap: 104 } },
        { id: 'key', title: 'Key', home: { ax: 'l', ay: 'b', x: 10, y: 10, w: 290, h: 340, folded: true } },
        { id: 'data', title: 'Data', home: { ax: 'l', ay: 'b', x: 310, y: 10, w: 760, wfill: 390, h: 400, folded: true } }] }) : null;
      const pm = FS.$('#panels-menu', el);
      if (pm && panels) pm.onclick = () => panels.menu();
      // The drawer's tabs.
      el.querySelectorAll('.datatabs [data-tab]').forEach(b => {
        b.onclick = () => {
          const t = b.getAttribute('data-tab');
          el.querySelectorAll('.datatabs [data-tab]').forEach(x => { const on = x === b; x.classList.toggle('on', on); x.setAttribute('aria-selected', on ? 'true' : 'false'); });
          el.querySelectorAll('.datapane').forEach(p => { p.hidden = p.getAttribute('data-pane') !== t; });
          try { localStorage.setItem('fs.mapdata.tab', t); } catch (e) { }
        };
      });
      // While the map is being moved the panels step back.
      const stageEl = FS.$('#mapstage', el);
      if (canvas && stageEl) {
        let wheelT = null;
        stageEl.addEventListener('pointerdown', () => canvas.classList.add('moving'));
        const done = () => canvas.classList.remove('moving');
        stageEl.addEventListener('pointerup', done); stageEl.addEventListener('pointercancel', done); stageEl.addEventListener('pointerleave', done);
        stageEl.addEventListener('wheel', () => { canvas.classList.add('moving'); clearTimeout(wheelT); wheelT = setTimeout(done, 260); }, { passive: true });
      }

      // Look up on Shodan: fetch now, then redraw the card's block in place.
      el.addEventListener('click', async (ev) => {
        const b = ev.target && ev.target.closest ? ev.target.closest('.shodan-go') : null;
        if (!b) return;
        const ip = b.getAttribute('data-ip');
        b.disabled = true; b.textContent = 'Asking Shodan\u2026';
        try {
          const rec = await FS.get('/api/paths/shodan?ip=' + encodeURIComponent(ip) + '&now=1');
          const card = b.closest('.hopcard');
          const node = nodes.find(x => x.ips && x.ips[0] === ip);
          if (node) { node.detail = node.detail || {}; node.detail.shodan = rec && rec.ip ? rec : { ip, empty: true, at: Date.now() / 1000 }; }
          if (card && node) card.innerHTML = hopCard(node);
        } catch (e) { b.textContent = 'Shodan did not answer'; }
      });

      const fccPull = FS.$('#fcc-pull', el);
      if (fccPull) fccPull.onclick = async () => {
        fccPull.disabled = true; fccPull.textContent = 'Pulling\u2026 (a minute or two)';
        const r = await FS.post('/api/paths/fcc/pull', {});
        FS.toast(r.ok ? `FCC: ${num(r.providers)} providers, ${num(r.places)} places in ${r.state || 'your state'}` : (r.error || (r.errors || []).join('; ') || 'FCC pull failed'), !r.ok);
        FS.render();
      };
      const fccBtn = FS.$('#fcc-check', el);
      if (fccBtn) fccBtn.onclick = async () => {
        fccBtn.disabled = true; fccBtn.textContent = 'Checking\u2026';
        const r = await FS.post('/api/paths/fcc/check', {});
        FS.toast(r.ok ? `FCC access works: release ${(r.state || {}).as_of || '?'}` : (r.error || (r.state || {}).error || 'FCC check failed'), !r.ok);
        FS.render();
      };

      const rc = FS.$('#r-clear', el);
      if (rc) rc.onclick = () => FS.go('paths?' + routeQ(''));

      const cards = el.querySelectorAll('.hopcard');
      const showHop = (want) => {
        cards.forEach(d => { d.hidden = d.getAttribute('data-for') !== want; });
      };
      // Clicking a hop lights the routes that run through it. A lone dot
      // answers "what is this"; the journey it sits on answers "why is it
      // here", which is the question somebody clicking a router actually has.
      const legEls = el.querySelectorAll('.leg');
      const hopEls = el.querySelectorAll('.hop');
      const msEls = el.querySelectorAll('.legms');
      const bar = FS.$('#mapfilter', el), barText = FS.$('#mapfilter-text', el);

      // Narrowing the map to the routes through one hop.
      //
      // Dimming the rest was not enough: on a map carrying four hundred
      // destinations the faint remainder is still most of the ink, and the
      // route you asked about is lost in it. So everything else is taken
      // away -- and because a map that is hiding most of itself must say so,
      // a chip appears that undoes it in one click.
      let focusId = null;
      const litRoute = (dsts, label, id) => {
        focusId = id || null;
        legEls.forEach(p => p.classList.remove('onpath', 'offpath'));
        hopEls.forEach(x => x.classList.remove('onpath', 'offpath'));
        msEls.forEach(t => t.classList.remove('onpath'));
        if (!dsts || !dsts.length) {
          if (bar) bar.hidden = true;
          if (FS.pathsView) FS.pathsView.focus = null;
          return;
        }
        const want = {}; dsts.forEach(d => want[d] = 1);
        const ends = {};
        legs.forEach(l => {
          if (!(l.destinations || []).some(d => want[d])) return;
          ends[l.from] = 1; ends[l.to] = 1;
        });
        legEls.forEach(p => {
          const on = (p.getAttribute('data-dsts') || '').split(' ').some(d => want[d]);
          p.classList.add(on ? 'onpath' : 'offpath');
        });
        hopEls.forEach(x => x.classList.add(ends[x.getAttribute('data-hop')] ? 'onpath' : 'offpath'));
        msEls.forEach(t => {
          const on = (t.getAttribute('data-dsts') || '').split(' ').some(d => want[d]);
          t.classList.toggle('onpath', on);
        });
        if (bar && barText) {
          barText.textContent = `${dsts.length} route${dsts.length === 1 ? '' : 's'} through ${label}`;
          bar.hidden = false;
        }
        if (FS.pathsView) FS.pathsView.focus = { dsts: dsts, label: label, id: focusId };
      };
      const crumbEls = el.querySelectorAll('[data-crumb]');

      // Picking a hop, wherever it is picked.
      //
      // A hop on the map and its step in the route are the same thing, so
      // touching either has to mark both. Only half of that was true: a step
      // lit its dot, but a dot left the step alone, and on a twenty-hop route
      // the reader was then looking at a card without being told which of the
      // twenty it belonged to.
      const select = (id) => {
        showHop(id);
        crumbEls.forEach(x => x.classList.toggle('here', x.getAttribute('data-crumb') === id));
        el.querySelectorAll('.hop.lit').forEach(x => x.classList.remove('lit'));
        el.querySelectorAll('.hop[data-hop="' + (window.CSS && CSS.escape ? CSS.escape(id) : id) + '"]')
          .forEach(d => d.classList.add('lit'));
        // The route scrolls sideways, so the step may well be off the end of
        // it. Marking something the reader cannot see is not marking it.
        const here = [...crumbEls].find(x => x.getAttribute('data-crumb') === id);
        if (here && here.scrollIntoView) {
          here.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'smooth' });
        }
      };

      // Clicking a hop goes to it; clicking it again comes back.
      //
      // A dot on a world map is a few pixels wide and a reader who wants to
      // know where it is has to zoom, then find their way back out. The same
      // click does both, because the second click on a thing you are already
      // looking at can only mean you have finished looking at it.
      let zoomedOn = null;
      const CLOSE = MAPW / 9;
      // Who made the requests that ran through a hop: the devices whose
      // traffic reached any destination routed through it. The device filter
      // follows the click, so the map narrows to those devices' traffic. One
      // device selects itself; several become one "N devices through this
      // hop" choice the server takes as a list.
      const whoThrough = async (dsts) => {
        if (!dsts || !dsts.length) return '';
        const w = await get('/api/paths/who?dsts=' + encodeURIComponent(dsts.slice(0, 200).join(',')) + '&' + FS.since());
        return ((w && w.devices) || []).map(d => d.key).join(',');
      };
      // Two lines at the pointer: the address, the place, the round trip. The
      // full card is in the Hop panel; this is for the reader sweeping across
      // a dense cluster who wants to know which dot is which without looking
      // away.
      const hover = FS.$('#hovercard', el);
      const hoverShow = (n, ev) => {
        if (!hover || !canvas || !n) return;
        const r = canvas.getBoundingClientRect();
        const place = [n.city, n.country].filter(Boolean).join(', ');
        hover.innerHTML = `<b>${esc((n.ips || [])[0] || n.id)}</b>${n.endpoint ? ' <span class="mu">endpoint</span>' : ''}<br><span class="mu">${esc([n.endpoint ? '' : 'hop ' + hopNo(n), place || (n.located ? '' : 'not placed'), hopRTT(n) ? hopRTT(n) + ' ms' : ''].filter(Boolean).join(' \u00b7 '))}</span>`;
        hover.hidden = false;
        const x = Math.min(ev.clientX - r.left + 14, Math.max(0, r.width - 270)), y = Math.min(ev.clientY - r.top + 14, Math.max(0, r.height - 48));
        hover.style.left = x + 'px'; hover.style.top = y + 'px';
      };
      const hoverHide = () => { if (hover) hover.hidden = true; };
      el.querySelectorAll('.hop').forEach(c => {
        const id = c.getAttribute('data-hop');
        c.addEventListener('mouseenter', (ev) => { select(id); hoverShow(byId[id], ev); });
        c.addEventListener('mousemove', (ev) => hoverShow(byId[id], ev));
        c.addEventListener('mouseleave', hoverHide);
        c.addEventListener('click', async () => {
          const n0 = byId[id];
          // An endpoint is a destination, and what a reader wants from one is
          // the journey to it, not a closer look at the dot. So it opens that
          // route: the trail from this network to it, the map narrowed to it,
          // and the whole thing framed, filtered to whoever talked to it.
          if (n0 && n0.endpoint && (n0.reaches || []).length && n0.reaches[0] !== picked) {
            FS.go('paths?' + routeQ(n0.reaches[0], undefined, await whoThrough(n0.reaches)));
            return;
          }
          // A hop that is not on the chosen route -- or there is no chosen
          // route -- loads the one it is on: the trail, the table and the
          // numbering all follow. Several routes through it are taken
          // busiest first, and the chip offers the next. The device filter
          // narrows to the devices whose traffic runs through this hop.
          const through = routesThrough(id);
          if (through.length && !(picked && inRoute[id])) {
            FS.go('paths?' + routeQ(through[0], id, await whoThrough(through)));
            return;
          }
          if (through.length) {
            const who = await whoThrough(through);
            if (who && who !== (ctx.params.device || '')) { FS.go('paths?' + routeQ(picked, id, who)); return; }
          }
          select(id);
          litRoute(routeOf(id), (n0 && n0.ips ? n0.ips[0] : id), id);
          const pz = FS.panZoomHandle;
          const n = byId[id];
          // Decide what can happen before recording that it did. Arming the
          // toggle first meant a click that could not move anywhere -- no
          // handle yet, or a hop with no position -- still counted, so the
          // next click on that hop came back out of a zoom that never
          // happened.
          if (!pz || !n || !n.located) { zoomedOn = null; return; }
          if (zoomedOn === id) {
            zoomedOn = null;
            litRoute(null);
            pz.reset();
            return;
          }
          zoomedOn = id;
          const [nx, ny] = xy(n);
          pz.moveTo(pz.nearest(nx), ny, CLOSE);
        });
      });

      // A step in the trail and its dot on the map are the same hop, so
      // touching either should light up both. Without that the trail reads as
      // a list beside a picture rather than a way into it.
      // The route laid out along the cylinder, each hop shifted by whole
      // worlds until it is nearest the one before it. This is what makes a
      // route from Kansas to Tokyo run west across the Pacific instead of
      // doubling back across Europe, and it is the same arithmetic the legs
      // are drawn with, so the trail and the map agree about which way round
      // the journey went.
      const placed = routeHops.filter(n => n.located);
      const laid = [];
      placed.forEach((n, i) => {
        const [px, py] = xy(n);
        laid.push({ id: n.id, x: i === 0 ? px : near(px, laid[i - 1].x), y: py });
      });
      const laidById = {}; laid.forEach(p => laidById[p.id] = p);
      const H = () => FS.panZoomHandle;

      // The whole journey in view: from you, through every placed hop, to the
      // endpoint. A route drawn without its own beginning is not the route,
      // so the origin is in the box.
      const fitRoute = () => {
        const pz = H();
        if (!pz || !laid.length) return;
        let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
        if (origin) {
          const ox = near(origin[0], laid[0].x);
          x0 = Math.min(x0, ox); x1 = Math.max(x1, ox);
          y0 = Math.min(y0, origin[1]); y1 = Math.max(y1, origin[1]);
        }
        laid.forEach(p => {
          x0 = Math.min(x0, p.x); x1 = Math.max(x1, p.x);
          y0 = Math.min(y0, p.y); y1 = Math.max(y1, p.y);
        });
        const mid = pz.nearest((x0 + x1) / 2), shift = mid - (x0 + x1) / 2;
        pz.fit(x0 + shift, y0, x1 + shift, y1);
      };

      crumbEls.forEach(li => {
        const id = li.getAttribute('data-crumb');
        const mark = () => select(id);
        li.addEventListener('mouseenter', mark);
        li.addEventListener('click', () => {
          mark();
          const pz = H(); if (!pz) return;
          // The last step frames the journey rather than visiting its end: by
          // then the question has stopped being "where is this hop" and become
          // "how far did that go". Everything before it travels, keeping the
          // zoom the reader chose.
          if (li.classList.contains('endpoint') && laid.length > 1) {
            fitRoute();
            return;
          }
          if (id === '__origin') {
            if (origin) pz.moveTo(pz.nearest(origin[0]), origin[1]);
            return;
          }
          const p = laidById[id];
          if (p) pz.moveTo(pz.nearest(p.x), p.y);
        });
      });

      // Radii are attributes, not styles, so the zoom factor has to be applied
      // to them by hand. Everything else holds its size through CSS.
      const svg = FS.$('#pathmap', el);
      const sized = svg ? svg.querySelectorAll('[data-r]') : [];
      const arrowEls = svg ? svg.querySelectorAll('.arrow') : [];
      // What the reader is looking at, so a refresh can put it back.
      //
      // The page redraws itself every couple of minutes. Zoomed in on a hop,
      // that threw the view away and dropped them back at the whole world --
      // which is the page deciding it knows better than the person using it.
      // The view is kept against the filters that produced it, so changing
      // route or device still starts fresh.
      const viewKey = ['device', 'country', 'max_latency', 'max_hops']
        .map(k => ctx.params[k] || '').concat(picked, ctx.params.hop || '').join('|');
      // Read before the map is built, because building it lays down a full
      // view of its own and publishes that -- which overwrote the very thing
      // being restored, a second before it was wanted.
      const savedFor = FS.pathsView && FS.pathsView.key === viewKey ? FS.pathsView : null;
      const savedBox = savedFor && savedFor.box;
      const savedFocus = savedFor && savedFor.focus;

      FS.panZoomHandle = FS.panZoom(svg, MAPW, MAPH, {
        wrapX: true,
        onZoom: (z) => {
          lastZ = z;
          const byTraffic = svg.classList.contains('traffic');
          sized.forEach(c => {
            const base = byTraffic && c.hasAttribute('data-rt') ? c.getAttribute('data-rt') : c.getAttribute('data-r');
            c.setAttribute('r', (parseFloat(base) / z).toFixed(2));
          });
          const k = (1 / z).toFixed(3);
          arrowEls.forEach(a => a.setAttribute('transform',
            `translate(${a.getAttribute('data-ax')} ${a.getAttribute('data-ay')}) rotate(${a.getAttribute('data-aa')}) scale(${k})`));
        },
        onView: (v) => { FS.pathsView = { key: viewKey, box: v, focus: FS.pathsView && FS.pathsView.focus }; }
      });
      // Moving the map by hand means you are no longer looking at whatever
      // was clicked, so the next click on it should take you there rather
      // than pretend to bring you back.
      if (svg) {
        svg.addEventListener('wheel', () => { zoomedOn = null; }, { passive: true });
        svg.addEventListener('pointerdown', () => { zoomedOn = null; });
      }

      const go = () => {
        const p = [];
        const c = FS.$('#f-country', el).value, la = FS.$('#f-lat', el).value,
              ho = FS.$('#f-hops', el).value, dv = FS.$('#f-dev', el).value;
        if (c) p.push('country=' + encodeURIComponent(c));
        if (la) p.push('max_latency=' + encodeURIComponent(la));
        if (ho) p.push('max_hops=' + encodeURIComponent(ho));
        if (dv) p.push('device=' + encodeURIComponent(dv));
        if (picked) p.push('dst=' + encodeURIComponent(picked));
        FS.go('paths' + (p.length ? '?' + p.join('&') : ''));
      };
      ['#f-country', '#f-dev', '#f-lat', '#f-hops'].forEach(sel => {
        const c = FS.$(sel, el);
        if (c) c.onchange = go;
      });
      // Arriving with a route chosen: show the whole of it, narrowed to it,
      // with the endpoint's detail open -- which is what was asked for by
      // coming here.
      if (savedBox) {
        // A refresh, not an arrival: put the reader back where they were,
        // with whatever they had narrowed to.
        if (savedFocus) {
          litRoute(savedFocus.dsts, savedFocus.label, savedFocus.id);
          if (savedFocus.id) select(savedFocus.id);
        }
        if (typeof requestAnimationFrame === 'function') {
          requestAnimationFrame(() => FS.panZoomHandle && FS.panZoomHandle.restore(savedBox));
        } else if (FS.panZoomHandle) {
          FS.panZoomHandle.restore(savedBox);
        }
      } else if (picked && laid.length) {
        const end = routeHops.filter(n => n.located).slice(-1)[0];
        litRoute([picked], picked);
        const landing = ctx.params.hop && byId[ctx.params.hop] ? ctx.params.hop : '';
        if (landing) {
          // Arrived by clicking this hop: it is the one to be looking at,
          // and if it lies on several routes the chip says which this is
          // and offers the next.
          select(landing);
          const through = routesThrough(landing);
          const at = through.indexOf(picked);
          if (through.length > 1 && at >= 0 && barText) {
            barText.textContent = `route ${at + 1} of ${through.length} through ${(byId[landing].ips || [landing])[0]}`;
            const nxt = FS.$('#mapfilter-next', el);
            if (nxt) {
              nxt.hidden = false;
              nxt.onclick = () => FS.go('paths?' + routeQ(through[(at + 1) % through.length], landing));
            }
          }
        } else if (end) {
          select(end.id);
        }
        if (typeof requestAnimationFrame === 'function') {
          requestAnimationFrame(() => requestAnimationFrame(fitRoute));
        } else {
          fitRoute();
        }
      }

      const off = FS.$('#mapfilter-off', el);
      if (off) off.onclick = () => {
        litRoute(null);
        zoomedOn = null;
        if (FS.panZoomHandle) FS.panZoomHandle.reset();
      };
      FS.$('#f-clear', el).onclick = () => FS.go('paths');
      FS.$('#f-reset', el).onclick = () => {
        zoomedOn = null;
        if (FS.panZoomHandle) FS.panZoomHandle.reset();
      };
      // Zoom by a step about the centre of what is in view.
      const zoomBy = (k) => {
        const pz = FS.panZoomHandle; if (!pz) return;
        const v = (FS.pathsView && FS.pathsView.box) || { x: 0, y: 0, w: MAPW, h: MAPH };
        zoomedOn = null;
        pz.moveTo(v.x + v.w / 2, v.y + v.h / 2, v.w / k, 160);
      };
      const zi = FS.$('#z-in', el), zo = FS.$('#z-out', el);
      if (zi) zi.onclick = () => zoomBy(1.7);
      if (zo) zo.onclick = () => zoomBy(1 / 1.7);
    }
  });

  // ------------------------------------------------------------- Scan
  FS.registerPage('scan', {
    title: 'Scan', refresh: 30,
    async render(el, ctx) {
      const [status, results] = await Promise.all([get('/api/scan/status'), get('/api/scan/results?hours=24')]);
      if (status.error) { el.innerHTML = FS.err(status.error); return; }
      const state = !status.scanning ? pill('disabled', 'warn') : status.running > 0 ? pill('scanning', 'info') : pill('ready', 'ok');
      el.innerHTML = `<div class="grid cols-4">
        ${kpi('Status', state, status.nmap_installed ? 'nmap installed' : 'native probes only')}
        ${kpi('Queue', num(status.queued), status.running ? num(status.running) + ' running' : 'ready')}
        ${kpi('Last sweep', status.last_sweep ? ago(status.last_sweep) : 'never')}
        ${card('Actions', `<div class="actions"><button class="btn" id="scan-btn" ${!status.scanning ? 'disabled' : ''}>Scan a host…</button><button class="btn" id="sweep-btn" ${!status.scanning ? 'disabled' : ''}>Sweep all local</button></div>${!status.scanning ? '<div class="small muted" style="margin-top:8px">Enable scanning in Settings › scan</div>' : ''}`)}
      </div>
      <div style="margin-top:14px">${card('Recent scans', table((results.results || []), [
        { t: 'Host', f: x => `<b>${esc(x.hostname || x.ip)}</b>${x.mac ? ` <div class="muted small mono">${esc(x.mac)}</div>` : ''}` },
        { t: 'OS guess', f: x => x.os_guess ? `<b>${esc(x.os_guess)}</b> (${(x.os_confidence * 100).toFixed(0)}%)` : '—' },
        { t: 'Open ports', f: x => x.open_ports && x.open_ports.length ? x.open_ports.map(p => `<span class="mono small" title="${esc(p.service || 'unknown')}">${p.port}</span>`).join(' ') : '—' },
        { t: 'Findings', f: x => x.findings && x.findings.length ? x.findings.map(f => pill(f)).join(' ') : '—' },
        { t: 'Source', f: x => x.nmap_enhanced ? pill('nmap', 'ok') : pill('native', 'info') },
        { t: 'Scanned', f: x => x.finished ? ago(x.finished) : '—' }], { empty: 'No scans yet. Scan a host to identify it.' }))}
      </div>`;
      FS.$('#scan-btn', el).onclick = () => {
        const ip = prompt('Scan this host (IP or MAC):', '');
        if (!ip) return;
        FS.post('/api/scan/start', { ip, profile: 'identify' }).then(r => {
          if (r.error) { FS.toast(r.error, true); return; }
          FS.toast('Scanning ' + ip + '…');
          let done = false;
          (async () => { for (let i = 0; i < 60 && !done; i++) { await new Promise(r => setTimeout(r, 3000)); const res = await get('/api/scan/result?ip=' + ip); if (res && res.finished) { done = true; FS.render(); } } })();
        });
      };
      FS.$('#sweep-btn', el).onclick = async () => {
        if (!await FS.confirm('Scan all devices seen in the last 7 days? This may take a while.')) return;
        const r = await post('/api/scan/sweep', {});
        FS.toast(r.error || 'Sweep started', !!r.error);
        if (!r.error) FS.render();
      };
    }
  });

  FS.scanSummary = async (ip) => {
    const r = await get('/api/scan/result?ip=' + encodeURIComponent(ip));
    if (r && !r.error && r.os_guesses) {
      return r.os_guesses[0];
    }
    return null;
  };

})();

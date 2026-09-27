// Naming a device, and giving it a DNS name.
//
// Renaming a device in FlowSight changes what FlowSight calls it. With
// "Also add it to DNS" ticked, the same dialog gives it a real name on the
// network: a forward record (nas.grio.co -> 192.168.1.10) and a reverse one
// (192.168.1.10 -> nas.grio.co), on the gateway resolver and on each
// connected Pi-hole, so every device can reach it by name whichever
// resolver it asks. Settings › dns › Device names lists them.
(function () {
  const esc = (s) => FS.esc(s);
  const DOCS = 'https://github.com/grio-co/flowsight/blob/main/docs/howto/';
  const labelFrom = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63).replace(/-+$/, '');
  const pref = (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : v === '1'; } catch (e) { return d; } };
  const setPref = (k, v) => { try { localStorage.setItem(k, v ? '1' : '0'); } catch (e) { /* private window */ } };

  // FS.nameDevice opens the dialog for one address. onDone runs after a save.
  FS.nameDevice = async (ip, current, onDone) => {
    const sg = await FS.get(`/api/dns/names/suggest?ip=${encodeURIComponent(ip)}${current ? '&name=' + encodeURIComponent(current) : ''}`);
    const ok = sg && !sg.error;
    const ex = ok ? sg.existing : null;
    const doms = ok ? (sg.domains || []) : [];
    const dom0 = ex ? ex.domain : (doms[0] || '');
    const addrs = ok ? (sg.addresses || []) : [];
    const chosen = ex ? ex.addresses : addrs.filter(a => !String(a.ip).includes(':')).slice(0, 1).map(a => a.ip);
    const piholes = ok ? (sg.piholes || []) : [];
    const dnsOn = ex ? true : pref('fs.nameDNS', true);
    const addrRow = (a) => {
      const v6 = String(a.ip).includes(':');
      const taken = (sg.reverse_taken || {})[a.ip];
      return `<label class="nm-addr"><input type="checkbox" name="addr" value="${esc(a.ip)}" ${chosen.includes(a.ip) ? 'checked' : ''}> <span class="mono">${esc(a.ip)}</span>
        ${v6 ? (a.stable ? FS.pill('stable', 'ok') : `<span class="muted small">${esc(a.note || '')}</span>`) : ''}
        ${taken ? `<span class="muted small">reverse already answers ${esc(taken.join(', '))} (gateway override; FlowSight adds forward only)</span>` : ''}</label>`;
    };
    // IPv4 and stable IPv6 first; rotating privacy addresses fold away,
    // since a name on one of them stops working within a day.
    const isPrivacy = (a) => String(a.ip).includes(':') && !a.stable && !chosen.includes(a.ip);
    const main = addrs.filter(a => !isPrivacy(a)), priv = addrs.filter(isPrivacy);
    const addrRows = (main.map(addrRow).join('') || `<label class="nm-addr"><input type="checkbox" name="addr" value="${esc(ip)}" checked> <span class="mono">${esc(ip)}</span></label>`)
      + (priv.length ? `<details class="small"><summary>${priv.length} IPv6 privacy address${priv.length === 1 ? '' : 'es'} (the device replaces these every day or so; usually leave them out)</summary>${priv.slice(0, 8).map(a => addrRow(Object.assign({}, a, { note: '' }))).join('')}</details>` : '');
    const where = [
      sg && sg.gateway ? `<label><input type="checkbox" name="gateway" ${!ex || ex.gateway ? 'checked' : ''}> Gateway resolver <span class="muted small">(devices that use the gateway for DNS)</span></label>` : '',
      ...piholes.map(t => `<label title="${t.writable ? '' : esc('FlowSight may not change this Pi-hole: turn on “Permit app password to modify config” there')}"><input type="checkbox" name="pihole" value="${esc(t.url)}" ${!t.writable ? 'disabled' : (!ex || (ex.piholes || []).includes(t.url)) ? 'checked' : ''}> Pi-hole ${esc(t.host)} ${t.writable ? '' : FS.pill('read only', 'warn')}</label>`)
    ].filter(Boolean).join('');
    FS.modal(`<h2>Name ${esc(ip)}</h2>
      <form class="f nm-form">
        <label>Name in FlowSight<input name="display" value="${esc(current || '')}" placeholder="Kitchen iPad" autocomplete="off"></label>
        ${ok ? `<label class="nm-toggle"><input type="checkbox" name="dns" ${dnsOn ? 'checked' : ''}> Also add it to DNS, so other devices reach it by name (forward and reverse lookup)</label>
        <div class="nm-dns" ${dnsOn ? '' : 'hidden'}>
          <div class="nm-name"><input name="label" value="${esc(ex ? ex.label : (sg.label || ''))}" placeholder="kitchen-ipad" autocomplete="off" spellcheck="false"><span>.</span>
            <input name="domain" list="nm-domains" value="${esc(dom0)}" placeholder="grio.co" autocomplete="off" spellcheck="false"><datalist id="nm-domains">${doms.map(d => `<option value="${esc(d)}">`).join('')}</datalist></div>
          <div class="nm-preview small mono"></div>
          <div class="nm-sec"><b class="small">Addresses</b>${addrRows}</div>
          <div class="nm-sec"><b class="small">Where</b>${where || '<span class="muted small">No resolver FlowSight can write to.</span>'}</div>
          ${sg.can_follow ? `<label class="nm-sec"><input type="checkbox" name="follow" ${!ex || ex.follow ? 'checked' : ''}> Follow the device: when its IPv4 address changes, move the name with it</label>` : '<div class="muted small nm-sec">No hardware address is known for this device, so the name stays on the address chosen; give it a DHCP reservation if its address changes.</div>'}
          ${ex ? `<div class="small muted nm-sec">In DNS now as <b>${esc(ex.fqdn)}</b>. Saving replaces it. <a href="#" data-nm-remove="${esc(ex.fqdn)}">Remove from DNS</a></div>` : ''}
          <div class="help small">Records go to FlowSight's own file on the gateway (not your OPNsense host overrides) and to each Pi-hole's local DNS records. Every change is in <a href="#system">Status</a> › Changes. <a href="${DOCS}local-names.md" target="_blank" rel="noopener">How device names work</a>.</div>
        </div>` : `<div class="muted small">DNS names are unavailable: ${esc((sg && sg.error) || 'the DNS module is off')}</div>`}
        <div class="actions"><button class="btn primary">Save</button><button type="button" class="btn" data-close>Cancel</button></div>
      </form>`, (b) => {
      const f = FS.$('form.nm-form', b);
      const dnsBox = f.dns, sec = FS.$('.nm-dns', b);
      let labelTouched = !!ex;
      const preview = () => {
        if (!sec) return;
        const fq = `${f.label.value || '…'}.${f.domain.value || '…'}`;
        const picks = FS.$$('input[name=addr]:checked', f).map(x => x.value);
        FS.$('.nm-preview', b).innerHTML = picks.length ? picks.map(a => `${esc(fq)} → ${esc(a)}<br>${esc(a)} → ${esc(fq)}`).join('<br>') : '<span class="muted">choose an address</span>';
      };
      if (dnsBox) dnsBox.onchange = () => { sec.hidden = !dnsBox.checked; setPref('fs.nameDNS', dnsBox.checked); };
      f.display.oninput = () => { if (!labelTouched && f.label) { f.label.value = labelFrom(f.display.value); preview(); } };
      if (f.label) { f.label.oninput = () => { labelTouched = true; preview(); }; f.domain.oninput = preview; FS.$$('input[name=addr]', f).forEach(x => x.onchange = preview); preview(); }
      FS.$$('[data-close]', b).forEach(x => x.onclick = () => FS.closeModal());
      const rm = FS.$('[data-nm-remove]', b);
      if (rm) rm.onclick = async (e) => {
        e.preventDefault();
        const r = await FS.post('/api/dns/names/remove', { fqdn: rm.dataset.nmRemove });
        FS.toast(r.error || r.gateway_error || 'Removed from DNS', !!(r.error || r.gateway_error)); FS.closeModal(); if (onDone) onDone();
      };
      f.onsubmit = async (e) => {
        e.preventDefault();
        const display = f.display.value.trim();
        if (display !== (current || '')) {
          const r = await FS.post('/api/identity/name', { ip, name: display });
          if (r.error) { FS.toast(r.error, true); return; }
        }
        if (dnsBox && dnsBox.checked) {
          const body = { ip, mac: sg.mac || '', display, label: f.label.value.trim(), domain: f.domain.value.trim(),
            addresses: FS.$$('input[name=addr]:checked', f).map(x => x.value),
            gateway: !!(f.gateway && f.gateway.checked), piholes: FS.$$('input[name=pihole]:checked', f).map(x => x.value),
            follow: !!(f.follow && f.follow.checked), replace: ex ? ex.fqdn : '' };
          const r = await FS.post('/api/dns/names', body);
          if (r.error) { FS.toast(r.error, true); return; }
          const bad = (r.piholes || []).filter(x => x.error).map(x => `Pi-hole ${x.host}: ${x.error}`);
          if (r.gateway_error) bad.unshift('Gateway: ' + r.gateway_error);
          FS.toast(bad.length ? bad.join('; ') : `${r.record.fqdn} is in DNS` + ((r.notes || []).length ? '. ' + r.notes.join(' ') : ''), bad.length > 0);
        } else FS.toast('Named');
        FS.closeModal(); if (onDone) onDone();
      };
    });
  };

  // The DNS name row of a device's Identity card: "kitchen-ipad.grio.co ✓"
  // or "not in DNS · Add".
  FS.dnsNameRow = (sg) => {
    if (!sg || sg.error) return '';
    const ex = sg.existing;
    return `<dt>DNS name</dt><dd>${ex ? `<span class="mono">${esc(ex.fqdn)}</span> <a href="#" class="small" data-nm-open>edit</a>` : `<span class="muted">not in DNS</span> <a href="#" class="small" data-nm-open>add</a>`}</dd>`;
  };

  // ------------------------------------------------------------ Settings › dns › Device names
  FS.registerPage('dnsnames', { title: 'Device names', refresh: 0, async render() { FS.go('#modules/dns?tab=names'); } });

  FS.renderLocalNames = async (el) => {
    {
      const tabs = '';
      const d = await FS.get('/api/dns/names');
      if (d.error) { el.innerHTML = tabs + FS.err(d.error); return; }
      const rows = d.names || [];
      const stat = (s) => (s || []).map(x => {
        const ok = x.forward_ok && x.reverse_ok;
        const tip = `forward: ${(x.forward || []).join(', ') || 'no answer'}\n` + Object.entries(x.reverse || {}).map(([a, n]) => `${a} → ${(n || []).join(', ') || 'no answer'}`).join('\n');
        return `<div title="${esc(tip)}">${FS.pill(ok ? 'answers' : !x.forward_ok ? 'no forward' : 'no reverse', ok ? 'ok' : 'warn')} <span class="small">${esc(x.label)}</span></div>`;
      }).join('');
      el.innerHTML = tabs + FS.card('Device names in DNS', rows.length ? FS.table(rows, [
        { t: 'Name', f: x => `<b class="mono">${esc(x.record.fqdn)}</b>${x.record.display ? `<div class="muted small">${esc(x.record.display)}</div>` : ''}` },
        { t: 'Addresses', f: x => (x.record.addresses || []).map(a => FS.hostLink(a)).join('<br>') },
        { t: 'Device', f: x => `<span class="mono small">${esc(x.record.mac || '')}</span>${x.record.follow ? `<div>${FS.pill('follows', 'info')}</div>` : ''}` },
        { t: 'Resolvers', f: x => stat(x.status) },
        { t: 'Changed', f: x => FS.ago(x.record.updated) },
        { t: '', f: x => `<button class="btn small" data-edit="${esc((x.record.addresses || [])[0] || '')}" data-name="${esc(x.record.display || '')}">Edit</button> <button class="btn small" data-rm="${esc(x.record.fqdn)}">Remove</button>` }])
        : FS.empty('No device has a DNS name from FlowSight yet. Rename a device on its page and tick “Also add it to DNS”.'),
        `${FS.num(rows.length)} names`)
        + `<div class="help" style="margin-top:10px">Each name answers both ways: the name gives the address, and the address gives the name back, on every resolver ticked for it. A <b>follows</b> name moves with its device when the device's IPv4 address changes. Your OPNsense host overrides are not touched and are not listed here. <a href="https://github.com/grio-co/flowsight/blob/main/docs/howto/local-names.md" target="_blank" rel="noopener">How device names work</a>.</div>`;
      FS.$$('[data-edit]', el).forEach(b => b.onclick = () => FS.nameDevice(b.dataset.edit, b.dataset.name, () => FS.render()));
      FS.$$('[data-rm]', el).forEach(b => b.onclick = async () => {
        if (!await FS.confirm(`Remove ${b.dataset.rm} from DNS?\n\nOther devices stop reaching it by that name.`)) return;
        const r = await FS.post('/api/dns/names/remove', { fqdn: b.dataset.rm });
        const bad = (r.piholes || []).filter(x => x.error);
        FS.toast(r.error || r.gateway_error || (bad.length ? bad.map(x => x.host + ': ' + x.error).join('; ') : 'Removed'), !!(r.error || r.gateway_error || bad.length)); FS.render();
      });
    }
  };
})();

/* FlowSight Packet Inspection: Stateful and Deep Inspection. */
'use strict';
(function () {
  // window.FS is the namespace itself; destructuring FS out of it left the
  // page with an undefined FS and it never registered.
  const FS = window.FS || {};
  const { esc, num, bytes, ago, when, pill, card, kpi, table, get, post } = FS;

  // Helper to format IP:port
  const ipPort = (ip, port) => port ? `${esc(ip)}:${port}` : esc(ip);

  // Protocol hierarchy bar chart (SVG)
  const protocolChart = (analysis) => {
    if (!analysis || !analysis.protocol_counts) return '';
    const counts = analysis.protocol_counts;
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (total === 0) return '';

    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const maxCount = Math.max(...entries.map(e => e[1]));

    let html = '<svg viewBox="0 0 400 300" style="width:100%;height:auto" xmlns="http://www.w3.org/2000/svg">';
    html += '<text x="10" y="20" class="small" fill="var(--fg)">Protocol Hierarchy</text>';

    let y = 50;
    entries.forEach(([proto, count], idx) => {
      const pct = (count / total * 100).toFixed(1);
      const width = (count / maxCount) * 300;
      const color = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#34495e', '#e67e22', '#c0392b', '#27ae60'][idx % 10];
      html += `<rect x="10" y="${y}" width="${width}" height="20" fill="${color}" opacity="0.8"/>`;
      html += `<text x="320" y="${y+15}" class="small mono" fill="var(--fg)">${esc(proto)} ${num(count)}</text>`;
      y += 25;
    });

    html += '</svg>';
    return html;
  };

  // State filters helper
  const stateFilterBar = () => `
    <div class="filter-bar">
      <label>Filter:</label>
      <input type="text" id="state-host" placeholder="Host IP" style="width:150px">
      <select id="state-proto" style="width:100px">
        <option value="">Protocol</option>
        <option value="tcp">TCP</option>
        <option value="udp">UDP</option>
        <option value="icmp">ICMP</option>
      </select>
      <select id="state-state" style="width:150px">
        <option value="">State</option>
        <option value="ESTABLISHED">ESTABLISHED</option>
        <option value="SYN_SENT">SYN_SENT (half-open)</option>
        <option value="SYN_RCVD">SYN_RCVD</option>
        <option value="FIN_WAIT">FIN_WAIT</option>
      </select>
      <button class="btn small" id="state-filter-btn">Filter</button>
      <button class="btn small" id="state-clear-btn">Clear</button>
    </div>
  `;

  // Main page registration
  FS.registerPage('inspect', {
    title: 'Packet Inspection',
    refresh: 30,
    async render(el, ctx) {
      el.innerHTML = `
        <div class="tabs">
          <div class="tab-header">
            <button class="tab-btn active" data-tab="states">States</button>
            <button class="tab-btn" data-tab="capture">Capture</button>
            <button class="tab-btn" data-tab="live">Live</button>
          </div>
          <div class="tab-content">
            <div class="tab-pane active" data-pane="states" id="states-pane"></div>
            <div class="tab-pane" data-pane="capture" id="capture-pane"></div>
            <div class="tab-pane" data-pane="live" id="live-pane"></div>
          </div>
        </div>
      `;

      // Tab switching
      FS.$$('.tab-btn', el).forEach(btn => {
        btn.onclick = (e) => {
          FS.$$('.tab-btn', el).forEach(b => b.classList.remove('active'));
          FS.$$('.tab-pane', el).forEach(p => p.classList.remove('active'));
          e.target.classList.add('active');
          const pane = FS.$(`[data-pane="${e.target.dataset.tab}"]`, el);
          if (pane) pane.classList.add('active');

          if (e.target.dataset.tab === 'states') renderStatesTab();
          else if (e.target.dataset.tab === 'capture') renderCaptureTab();
          else if (e.target.dataset.tab === 'live') renderLiveTab();
        };
      });

      const renderStatesTab = async () => {
        const pane = FS.$('#states-pane', el);
        const [summary, states] = await Promise.all([
          get('/api/inspect/states/summary'),
          get('/api/inspect/states?limit=200')
        ]);

        if (summary.error || states.error) {
          pane.innerHTML = FS.err(summary.error || states.error);
          return;
        }

        const s = summary;
        pane.innerHTML = `
          <div class="grid cols-4">
            ${kpi('Total states', num(s.total_states), 'firewall state table')}
            ${kpi('Half-open (SYN_SENT)', num(s.half_open_count), 'pending connections')}
            ${kpi('By protocol', Object.entries(s.by_proto).map(([p, c]) => `${p}: ${num(c)}`).join(' | '))}
            ${card('State distribution', Object.entries(s.by_state).map(([st, c]) => `<div>${esc(st)}: ${num(c)}</div>`).join(''))}
          </div>
          <div style="margin-top:14px">
            ${stateFilterBar()}
          </div>
          <div style="margin-top:14px" id="states-table">
            ${card('States', table(states.states || [], [
              { t: 'Src', f: x => ipPort(x.src, x.src_port) },
              { t: 'Dst', f: x => ipPort(x.dst, x.dst_port) },
              { t: 'Proto', k: 'proto', sort: 'proto' },
              { t: 'State', k: 'state', sort: 'state' },
              { t: 'Age', f: x => x.age + 's', sort: 'age' },
              { t: 'Packets', f: x => num(x.pkts_src) + '/' + num(x.pkts_dst), num: true },
              { t: 'Bytes', f: x => bytes(x.bytes_src) + '/' + bytes(x.bytes_dst), num: true }
            ], { empty: 'No states' }))}
          </div>
        `;

        // Wire filter button
        const filterBtn = FS.$('#state-filter-btn', pane);
        const clearBtn = FS.$('#state-clear-btn', pane);
        const hostInput = FS.$('#state-host', pane);
        const protoSelect = FS.$('#state-proto', pane);
        const stateSelect = FS.$('#state-state', pane);

        filterBtn.onclick = async () => {
          const host = hostInput.value || '';
          const proto = protoSelect.value || '';
          const state = stateSelect.value || '';
          const params = new URLSearchParams();
          if (host) params.append('host', host);
          if (proto) params.append('proto', proto);
          if (state) params.append('state', state);
          const filtered = await get('/api/inspect/states?' + params.toString());
          const tableDiv = FS.$('#states-table', pane);
          tableDiv.innerHTML = card('States', table(filtered.states || [], [
            { t: 'Src', f: x => ipPort(x.src, x.src_port) },
            { t: 'Dst', f: x => ipPort(x.dst, x.dst_port) },
            { t: 'Proto', k: 'proto' },
            { t: 'State', k: 'state' },
            { t: 'Age', f: x => x.age + 's' },
            { t: 'Packets', f: x => num(x.pkts_src) + '/' + num(x.pkts_dst) },
            { t: 'Bytes', f: x => bytes(x.bytes_src) + '/' + bytes(x.bytes_dst) }
          ], { empty: 'No matching states' }));
        };

        clearBtn.onclick = () => {
          hostInput.value = '';
          protoSelect.value = '';
          stateSelect.value = '';
          filterBtn.onclick();
        };
      };

      const renderCaptureTab = async () => {
        const pane = FS.$('#capture-pane', el);
        const captures = await get('/api/inspect/captures');

        if (captures.error) {
          pane.innerHTML = FS.err(captures.error);
          return;
        }

        const ifaces = ['em0', 'em1', 'em2', 'vlan0', 'pfsync0'];
        const presetFilters = [
          { name: 'All traffic', value: '' },
          { name: 'DNS', value: 'udp port 53' },
          { name: 'TLS/HTTPS', value: 'tcp port 443' },
          { name: 'HTTP', value: 'tcp port 80' },
          { name: 'Not local', value: 'not (src net 192.168.1.0/24 and dst net 192.168.1.0/24)' },
          { name: 'ARP', value: 'arp' }
        ];

        pane.innerHTML = `
          <div class="grid cols-2">
            ${card('Start capture', `
              <form class="f" id="capture-form">
                <label>Interface</label>
                <select name="iface" required>
                  <option value="">Select interface</option>
                  ${ifaces.map(i => `<option value="${i}">${i}</option>`).join('')}
                </select>
                <label>BPF filter (optional)</label>
                <input type="text" name="filter" placeholder="e.g. tcp port 443" style="width:100%">
                <div class="small muted">
                  <b>Presets:</b>
                  ${presetFilters.map(p => `<a href="#" data-preset="${esc(p.value)}" style="margin-right:8px">${esc(p.name)}</a>`).join('')}
                </div>
                <label>Duration (seconds)</label>
                <input type="number" name="seconds" value="60" min="1" max="600">
                <label>Snaplen (bytes)</label>
                <select name="snaplen">
                  <option value="96" selected>96 (headers only)</option>
                  <option value="65535">65535 (full payload)</option>
                </select>
                <label><input type="checkbox" name="payload"> Include full payload (contains sensitive data)</label>
                <div class="actions">
                  <button type="submit" class="btn primary">Start capture</button>
                </div>
              </form>
            `)}
            ${card('Capture status', `<div id="capture-status">Ready to capture</div>`)}
          </div>
          <div style="margin-top:14px" id="captures-list">
            ${card('Recent captures', table(captures.captures || [], [
              { t: 'ID', k: 'id', f: x => `<code>${x.id.substring(0, 12)}</code>` },
              { t: 'Interface', k: 'iface' },
              { t: 'Filter', k: 'filter', f: x => x.filter ? `<code class="small">${esc(x.filter)}</code>` : '—' },
              { t: 'Duration', f: x => x.ended ? ((new Date(x.ended) - new Date(x.started)) / 1000).toFixed(1) + 's' : 'running' },
              { t: 'Packets', f: x => num(x.packets) },
              { t: 'Bytes', f: x => bytes(x.bytes) },
              { t: 'Started', f: x => ago(x.started), sort: 'started' },
              { t: '', f: x => `<a href="#" data-analyze="${esc(x.id)}" class="btn small">Analyze</a> <a href="#" data-download="${esc(x.id)}" class="btn small">Download</a>` }
            ], { empty: 'No captures yet' }))}
          </div>
          <div id="analysis-detail" style="margin-top:14px"></div>
        `;

        // Wire form
        const form = FS.$('#capture-form', pane);
        FS.$$('[data-preset]', pane).forEach(a => {
          a.onclick = (e) => {
            e.preventDefault();
            form.filter.value = e.target.dataset.preset;
          };
        });

        form.onsubmit = async (e) => {
          e.preventDefault();
          const iface = form.iface.value;
          const filter = form.filter.value;
          const secs = parseInt(form.seconds.value);
          const snaplen = parseInt(form.snaplen.value);
          const payload = form.payload.checked;

          const status = FS.$('#capture-status', pane);
          status.textContent = 'Starting capture...';

          const r = await post('/api/inspect/capture/start', { iface, filter, seconds: secs, snaplen, payload });
          if (r.error) {
            FS.toast(r.error, true);
            status.textContent = 'Error: ' + r.error;
          } else {
            status.innerHTML = `<div class="ok">Capturing on ${esc(iface)} for ${secs}s...</div>
              <button class="btn small" id="stop-btn">Stop capture</button>`;
            FS.$('#stop-btn', pane).onclick = async () => {
              await post('/api/inspect/capture/stop', {});
              status.textContent = 'Stopped. Reloading...';
              setTimeout(() => FS.render(), 2000);
            };
          }
        };

        // Wire download/analyze buttons
        FS.$$('[data-analyze]', pane).forEach(a => {
          a.onclick = async (e) => {
            e.preventDefault();
            const id = a.dataset.analyze;
            const detail = FS.$('#analysis-detail', pane);
            const cap = await get('/api/inspect/capture/' + id);
            if (cap.error) {
              detail.innerHTML = FS.err(cap.error);
              return;
            }
            const analysis = cap.analysis;
            detail.innerHTML = `
              <div style="margin-bottom:14px">
                <h3>Analysis: ${esc(id)}</h3>
                <div class="grid cols-3">
                  ${kpi('Packets', num(analysis.packet_count))}
                  ${kpi('Bytes', bytes(analysis.byte_count))}
                  ${kpi('Conversations', num((analysis.conversations || []).length))}
                </div>
              </div>
              <div style="margin-bottom:14px">
                ${protocolChart(analysis)}
              </div>
              <div style="margin-top:14px">
                ${card('Top talkers', table(analysis.top_talkers || [], [
                  { t: 'IP', k: 'ip' },
                  { t: 'Bytes', f: x => bytes(x.bytes), num: true },
                  { t: 'Packets', f: x => num(x.pkts), num: true }
                ], { empty: 'No talkers' }))}
              </div>
              <div style="margin-top:14px">
                ${card('Conversations', table(analysis.conversations || [], [
                  { t: 'Src', f: x => ipPort(x.src, x.src_port) },
                  { t: 'Dst', f: x => ipPort(x.dst, x.dst_port) },
                  { t: 'Proto', k: 'proto' },
                  { t: 'Packets', f: x => num(x.pkts_fwd) + '/' + num(x.pkts_rev) },
                  { t: 'Bytes', f: x => bytes(x.bytes_fwd) + '/' + bytes(x.bytes_rev) }
                ], { empty: 'No conversations' }))}
              </div>
              ${analysis.dns_queries && analysis.dns_queries.length ? `
                <div style="margin-top:14px">
                  ${card('DNS queries', table(analysis.dns_queries, [
                    { t: 'Query', k: 'query' },
                    { t: 'Type', k: 'type' },
                    { t: 'Answers', f: x => (x.answers || []).join(', ') }
                  ]))}
                </div>
              ` : ''}
              ${analysis.expert_notes && analysis.expert_notes.length ? `
                <div style="margin-top:14px">
                  ${card('Expert notes', table(analysis.expert_notes, [
                    { t: 'Type', k: 'type' },
                    { t: 'Src', k: 'src' },
                    { t: 'Dst', k: 'dst' },
                    { t: 'Detail', k: 'detail' },
                    { t: 'Severity', f: x => pill(x.severity) }
                  ]))}
                </div>
              ` : ''}
            `;
          };
        });

        FS.$$('[data-download]', pane).forEach(a => {
          a.onclick = async (e) => {
            e.preventDefault();
            const id = a.dataset.download;
            const info = await get('/api/inspect/capture/' + id + '/download');
            if (!info.error) {
              // In a real implementation, would stream the file
              FS.toast('Download ready: ' + info.name);
            }
          };
        });
      };

      const renderLiveTab = async () => {
        const pane = FS.$('#live-pane', el);
        pane.innerHTML = `
          <div class="grid cols-2">
            ${card('Live packet stream', `
              <form class="f" id="live-form">
                <label>Interface</label>
                <select name="iface" required>
                  <option value="em0">em0</option>
                  <option value="em1">em1</option>
                </select>
                <label>Filter (optional)</label>
                <input type="text" name="filter" placeholder="BPF filter">
                <label>Duration (seconds, max 30)</label>
                <input type="number" name="seconds" value="10" min="1" max="30">
                <div class="actions">
                  <button type="submit" class="btn primary">Start live stream</button>
                </div>
              </form>
            `)}
          </div>
          <div style="margin-top:14px" id="live-output"></div>
        `;

        const form = FS.$('#live-form', pane);
        form.onsubmit = async (e) => {
          e.preventDefault();
          const iface = form.iface.value;
          const filter = form.filter.value;
          const secs = parseInt(form.seconds.value);
          const output = FS.$('#live-output', pane);
          output.innerHTML = '<div class="info">Streaming...</div>';
          // Would implement server-sent events streaming
          FS.toast('Live streaming not yet implemented');
        };
      };

      // Initial render
      renderStatesTab();
    }
  });
})();

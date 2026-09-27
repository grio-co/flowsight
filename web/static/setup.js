/* FlowSight Setup Wizard: first-run configuration. */
'use strict';
(function () {
  const { $, $$, esc, card, get, post } = FS;

  FS.registerPage('setup', {
    title: 'Setup wizard',
    refresh: 0,
    async render(el) {
      const state = await get('/api/setup/state');
      if (state.error) {
        el.innerHTML = FS.err(state.error);
        return;
      }

      const stepInfo = {
        1: { title: 'Welcome & license', icon: '◈' },
        2: { title: 'Site basics', icon: '⚙' },
        3: { title: 'Traffic source', icon: '⇢' },
        4: { title: 'DNS source', icon: '◎' },
        5: { title: 'Interception', icon: '🔒' },
        6: { title: 'Identity & zones', icon: '▦' },
        7: { title: 'Security', icon: '⚠' },
        8: { title: 'Inventory', icon: '▣' },
        9: { title: 'Alerting', icon: '🔔' },
        10: { title: 'Updates', icon: '▥' },
        11: { title: 'API access', icon: 'API' },
        12: { title: 'Review & finish', icon: '✓' }
      };

      let currentStep = state.completed ? 13 : 1;

      el.innerHTML = `<div style="display:grid;grid-template-columns:200px 1fr;gap:20px;max-width:1200px;margin:0 auto">
        <div class="wizard-steps" style="background:#f5f5f5;padding:16px;border-radius:8px;max-height:calc(100vh - 100px);overflow-y:auto">
          <h3 style="margin:0 0 16px 0;font-size:14px;color:#666">Steps</h3>
          ${Array.from({length: 12}, (_, i) => {
            const step = i + 1;
            const isActive = step === currentStep;
            const isComplete = step < currentStep || (state.completed && step <= 12);
            return `<div class="step" data-step="${step}" style="padding:8px;margin:4px 0;border-radius:4px;cursor:pointer;background:${isActive ? '#e8e8e8' : 'transparent'};font-size:13px;border-left:3px solid ${isActive ? '#0066cc' : isComplete ? '#66bb6a' : '#ddd'};padding-left:12px">
              <span style="margin-right:6px">${stepInfo[step].icon}</span>${esc(stepInfo[step].title)}
            </div>`;
          }).join('')}
        </div>
        <div class="wizard-content"></div>
      </div>`;

      $$('.step', el).forEach(stepEl => {
        stepEl.addEventListener('click', () => {
          const step = parseInt(stepEl.dataset.step);
          if (step < currentStep || (state.completed && step <= 12)) {
            currentStep = step;
            renderCurrentStep();
          }
        });
      });

      function renderCurrentStep() {
        const content = $('.wizard-content', el);
        if (currentStep === 13) {
          renderCompletion();
        } else {
          renderStep(currentStep);
        }
      }

      function renderStep(step) {
        const content = $('.wizard-content', el);
        let html = '';
        switch (step) {
          case 1: html = renderLicenseStep(); break;
          case 2: html = renderSiteBasicsStep(); break;
          case 3: html = renderTrafficSourceStep(); break;
          case 4: html = renderDNSSourceStep(); break;
          case 5: html = renderInterceptionStep(); break;
          case 6: html = renderIdentityStep(); break;
          case 7: html = renderSecurityStep(); break;
          case 8: html = renderInventoryStep(); break;
          case 9: html = renderAlertingStep(); break;
          case 10: html = renderUpdatesStep(); break;
          case 11: html = renderAPIAccessStep(); break;
          case 12: html = renderReviewStep(); break;
        }
        content.innerHTML = html;
        attachStepHandlers(step);
      }

      function renderLicenseStep() {
        return card('Welcome to FlowSight', `
          <p>Welcome! This wizard will guide you through the essential configuration steps.</p>
          <p style="margin-top:12px"><strong>Current tier:</strong> <span class="pill" style="margin-left:8px">${esc(state.license.tier)}</span></p>
          <p style="margin-top:12px;font-size:13px;color:#666">
            <a href="https://grio.co/flowsight" target="_blank" style="color:#0066cc">Upgrade to Pro or Business</a> for advanced features.
          </p>
          <div style="margin-top:16px">
            <label>License key (optional)</label>
            <input id="license-key" type="text" placeholder="Paste your license key" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px;font-family:monospace">
            <button class="btn small" data-action="test-license" style="margin-top:8px">Activate</button>
            <span id="license-status" style="margin-left:8px;font-size:12px"></span>
          </div>
          ${renderStepButtons(1)}
        `);
      }

      function renderSiteBasicsStep() {
        return card('Site basics', `
          <div style="margin-top:16px">
            <label>Site name</label>
            <input id="site-name" type="text" placeholder="My Network" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label>Data retention (days)</label>
            <input id="retention-days" type="number" min="1" max="90" value="7" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label>Memory limit (MB)</label>
            <input id="memory-limit" type="number" min="64" value="256" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          ${renderStepButtons(2)}
        `);
      }

      function renderTrafficSourceStep() {
        return card('Traffic source (ntopng)', `
          <p style="font-size:13px;color:#666">ntopng ${state.binaries.ntopng ? '<span class="pill ok">detected</span>' : '<span class="pill bad">not found</span>'}</p>
          <div style="margin-top:16px">
            <label>ntopng URL</label>
            <input id="ntopng-url" type="text" placeholder="http://127.0.0.1:3000" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label>Username (if required)</label>
            <input id="ntopng-username" type="text" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label>Password</label>
            <input id="ntopng-password" type="password" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <button class="btn small" data-action="test-ntopng" style="margin-top:8px">Test connection</button>
          <span id="ntopng-status" style="margin-left:8px;font-size:12px"></span>
          ${renderStepButtons(3)}
        `);
      }

      function renderDNSSourceStep() {
        const hints = state.pihole_hints || [];
        return card('DNS source', `
          <div style="margin-top:16px">
            <label>Pi-hole address</label>
            <input id="pihole-address" type="text" placeholder="${hints[0] || '192.168.1.1'}" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
            ${hints.length > 0 ? `<div class="small muted" style="margin-top:4px">Candidates: ${hints.join(', ')}</div>` : ''}
          </div>
          <div style="margin-top:12px">
            <label>API token</label>
            <input id="pihole-token" type="password" placeholder="Optional" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <button class="btn small" data-action="test-pihole" style="margin-top:8px">Test connection</button>
          <span id="pihole-status" style="margin-left:8px;font-size:12px"></span>
          ${renderStepButtons(4)}
        `);
      }

      function renderInterceptionStep() {
        const ifaces = state.interfaces || [];
        return card('Web interception', `
          <div style="margin-top:16px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input id="intercept-enable" type="checkbox">
              <span>Intercept web traffic (ports 80, 443)</span>
            </label>
          </div>
          <div style="margin-top:12px">
            <label>Interfaces (optional)</label>
            <div id="interfaces-list" style="margin-top:8px">
              ${ifaces.map(iface => `<label style="display:block;margin:4px 0;font-size:13px">
                <input type="checkbox" data-iface="${esc(iface)}" class="intercept-iface">
                ${esc(iface)}
              </label>`).join('')}
            </div>
          </div>
          ${renderStepButtons(5)}
        `);
      }

      function renderIdentityStep() {
        return card('Identity & zones', `
          <p style="font-size:13px;color:#666">Delegated to Settings › Zones</p>
          ${renderStepButtons(6)}
        `);
      }

      function renderSecurityStep() {
        return card('Security', `
          <div style="margin-top:16px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input id="ids-enable" type="checkbox">
              <span>Enable IDS (Suricata) ${state.binaries.suricata ? '<span class="pill ok">detected</span>' : ''}</span>
            </label>
          </div>
          <div style="margin-top:12px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input id="tls-probe" type="checkbox">
              <span>TLS probe (record server certificates)</span>
            </label>
          </div>
          ${renderStepButtons(7)}
        `);
      }

      function renderInventoryStep() {
        const hints = state.proxmox_hints || [];
        return card('Inventory', `
          <div style="margin-top:16px">
            <label>Proxmox host</label>
            <input id="proxmox-host" type="text" placeholder="${hints[0] || 'pve1.example.com'}" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
            ${hints.length > 0 ? `<div class="small muted" style="margin-top:4px">Candidates: ${hints.join(', ')}</div>` : ''}
          </div>
          <div style="margin-top:12px">
            <label>API token ID</label>
            <input id="proxmox-token-id" type="text" placeholder="user@pam!tokenid" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label>API token secret</label>
            <input id="proxmox-token-secret" type="password" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input id="proxmox-verify-tls" type="checkbox">
              <span>Verify TLS with system roots</span>
            </label>
          </div>
          <div style="margin-top:12px">
            <label>Certificate fingerprint (SHA-256)</label>
            <input id="proxmox-fingerprint" type="text" placeholder="Optional" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <button class="btn small" data-action="test-proxmox" style="margin-top:8px">Test connection</button>
          <span id="proxmox-status" style="margin-left:8px;font-size:12px"></span>
          ${renderStepButtons(8)}
        `);
      }

      function renderAlertingStep() {
        return card('Alerting', `
          <p style="font-size:13px;color:#666">Delegated to Settings › Alerts</p>
          ${renderStepButtons(9)}
        `);
      }

      function renderUpdatesStep() {
        return card('Updates', `
          <div style="margin-top:16px">
            <label>Manifest URL</label>
            <input id="manifest-url" type="text" placeholder="https://releases.example.com/flowsight/manifest.json" style="width:100%;box-sizing:border-box;padding:8px;border:1px solid #ddd;border-radius:4px;font-size:13px">
          </div>
          <div style="margin-top:12px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input id="auto-apply" type="checkbox">
              <span>Auto-apply updates</span>
            </label>
          </div>
          ${renderStepButtons(10)}
        `);
      }

      function renderAPIAccessStep() {
        return card('API access', `
          <p style="font-size:13px;color:#666">API bind, port and token are file-only core settings.</p>
          <div style="margin-top:16px;padding:12px;background:#f0f0f0;border-radius:4px;font-size:12px">
            <code style="display:block;background:white;padding:8px;border-radius:4px;font-size:11px;overflow-x:auto">
"bind": "0.0.0.0", "port": 8080, "api_token": "token123"
            </code>
          </div>
          ${renderStepButtons(11)}
        `);
      }

      function renderReviewStep() {
        return card('Review & finish', `
          <p style="margin-top:16px;font-size:13px">Next: review Settings and create your first policy under Protect › Policies.</p>
          <div style="margin-top:16px;display:flex;gap:12px">
            <button class="btn primary" data-action="finish-wizard">Mark completed</button>
            <button class="btn" data-action="run-again">Run again</button>
          </div>
        `);
      }

      function renderCompletion() {
        const content = $('.wizard-content', el);
        content.innerHTML = card('Setup complete!', `
          <div style="text-align:center;padding:20px">
            <div style="font-size:48px;margin-bottom:12px">✓</div>
            <h2 style="margin:0 0 12px 0">Setup wizard completed</h2>
            <div style="margin-top:20px;display:flex;gap:12px;justify-content:center">
              <a href="#overview" class="btn primary">Go to Overview</a>
              <button class="btn" data-action="run-again">Run wizard again</button>
            </div>
          </div>
        `);
        attachCompletionHandlers();
      }

      function renderStepButtons(step) {
        const isLast = step === 12;
        return `<div style="display:flex;gap:12px;margin-top:24px">
          ${step > 1 ? '<button class="btn" data-action="prev-btn">Previous</button>' : ''}
          <div style="flex:1"></div>
          <button class="btn" data-action="skip-btn">Skip</button>
          ${isLast ? '<button class="btn primary" data-action="next-btn">Finish</button>' : '<button class="btn primary" data-action="next-btn">Next</button>'}
        </div>`;
      }

      async function handleNextButton(step) {
        const values = collectStepValues(step);
        if (!values) return;
        const result = await post('/api/setup/apply', { step, values });
        if (result.error) {
          FS.toast(result.error, true);
          return;
        }
        currentStep = step === 12 ? 13 : Math.min(12, step + 1);
        renderCurrentStep();
      }

      function attachStepHandlers(step) {
        const handlers = {
          'prev-btn': () => {
            currentStep = Math.max(1, currentStep - 1);
            renderCurrentStep();
          },
          'skip-btn': () => {
            currentStep = Math.min(12, currentStep + 1);
            renderCurrentStep();
          },
          'next-btn': () => handleNextButton(step),
          'test-license': async () => {
            const key = $('#license-key', el).value.trim();
            if (!key) {
              FS.toast('Enter a license key', true);
              return;
            }
            const result = await post('/api/license/activate', { key });
            const status = $('#license-status', el);
            status.textContent = result.error ? '❌ ' + result.error : '✓ License activated: ' + result.tier;
          },
          'test-ntopng': async () => {
            const url = $('#ntopng-url', el).value;
            if (!url) { FS.toast('Enter ntopng URL', true); return; }
            const result = await post('/api/setup/test', {
              step, values: {
                ntopng_url: url,
                ntopng_username: $('#ntopng-username', el).value,
                ntopng_password: $('#ntopng-password', el).value
              }
            });
            const status = $('#ntopng-status', el);
            status.textContent = result.error ? '❌ ' + result.error : '✓ Connected';
          },
          'test-pihole': async () => {
            const addr = $('#pihole-address', el).value;
            if (!addr) { FS.toast('Enter Pi-hole address', true); return; }
            const result = await post('/api/setup/test', {
              step, values: {
                pihole_address: addr,
                pihole_token: $('#pihole-token', el).value
              }
            });
            const status = $('#pihole-status', el);
            status.textContent = result.error ? '❌ ' + result.error : '✓ Connected';
          },
          'test-proxmox': async () => {
            const host = $('#proxmox-host', el).value;
            const tokenId = $('#proxmox-token-id', el).value;
            const tokenSecret = $('#proxmox-token-secret', el).value;
            if (!host || !tokenId || !tokenSecret) { FS.toast('Enter all Proxmox fields', true); return; }
            const result = await post('/api/setup/test', {
              step: 8, values: {
                proxmox_host: host,
                proxmox_token_id: tokenId,
                proxmox_token_secret: tokenSecret,
                proxmox_fingerprint: $('#proxmox-fingerprint', el).value,
                proxmox_verify_tls: $('#proxmox-verify-tls', el).checked
              }
            });
            const status = $('#proxmox-status', el);
            status.textContent = result.error ? '❌ ' + result.error : '✓ Connected';
          },
          'finish-wizard': async () => {
            const result = await post('/api/setup/apply', { step: 12, values: {} });
            if (!result.error) {
              currentStep = 13;
              renderCurrentStep();
            }
          },
          'run-again': async () => {
            if (!await FS.confirm('Run the setup wizard again?\n\nIts steps can change tokens, resolvers, credentials and the update source.')) return;
            await post('/api/setup/reset', { reconfigure: true });
            currentStep = 1;
            state.completed = false;
            renderCurrentStep();
          }
        };

        $$('[data-action]', el).forEach(btn => {
          const action = btn.dataset.action;
          if (handlers[action]) {
            btn.addEventListener('click', handlers[action]);
          }
        });
      }

      function attachCompletionHandlers() {
        const content = $('.wizard-content', el);
        $$('[data-action]', content).forEach(btn => {
          const action = btn.dataset.action;
          if (action === 'run-again') {
            btn.addEventListener('click', async () => {
              if (!await FS.confirm('Run the setup wizard again?\n\nIts steps can change tokens, resolvers, credentials and the update source.')) return;
              await post('/api/setup/reset', { reconfigure: true });
              currentStep = 1;
              state.completed = false;
              renderCurrentStep();
            });
          }
        });
      }

      function collectStepValues(step) {
        const values = {};
        switch (step) {
          case 3:
            values.ntopng_url = $('#ntopng-url', el)?.value || '';
            values.ntopng_username = $('#ntopng-username', el)?.value || '';
            values.ntopng_password = $('#ntopng-password', el)?.value || '';
            break;
          case 4:
            values.pihole_address = $('#pihole-address', el)?.value || '';
            values.pihole_token = $('#pihole-token', el)?.value || '';
            break;
          case 5:
            values.intercept = $('#intercept-enable', el)?.checked || false;
            const ifaces = [];
            $$('.intercept-iface:checked', el).forEach(cb => ifaces.push(cb.dataset.iface));
            values.interfaces = ifaces;
            break;
          case 7:
            values.ids_enabled = $('#ids-enable', el)?.checked || false;
            values.tls_probe = $('#tls-probe', el)?.checked || false;
            break;
          case 8:
            values.proxmox_host = $('#proxmox-host', el)?.value || '';
            values.proxmox_token_id = $('#proxmox-token-id', el)?.value || '';
            values.proxmox_token_secret = $('#proxmox-token-secret', el)?.value || '';
            values.proxmox_fingerprint = $('#proxmox-fingerprint', el)?.value || '';
            values.proxmox_verify_tls = $('#proxmox-verify-tls', el)?.checked || false;
            break;
          case 10:
            values.manifest_url = $('#manifest-url', el)?.value || '';
            values.auto_apply = $('#auto-apply', el)?.checked || false;
            break;
        }
        return values;
      }

      renderCurrentStep();
    }
  });
})();

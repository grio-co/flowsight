// Device advisories render with the effect, the cause, the fix and the
// one-click Pi-hole actions, on the host page, and the Pi-hole tab renders
// its guidance and only appears while a Pi-hole is connected.
var window = this;
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{}, addEventListener:function(){}, appendChild:function(){}, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null, closest:function(){ return mkEl(); }, remove:function(){} }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, addEventListener:function(){}, body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} }; var location = { hash:'' }; var setTimeout = function(){};
function URLSearchParams(obj) { this.params = obj || {}; this.set = function(k, v) { this.params[k] = v; }; this.toString = function() { return Object.entries(this.params).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&'); }; }
load('web/static/lib.js');
FS.state = FS.state || {}; FS.state.hours = 24; FS.since = function(){ return 'hours=24'; };
FS.go = function(){}; FS.setTitle = function(){};
var relay = { id: 7, ts: 1790470000, module: 'advisor', kind: 'private_relay_blocked', severity: 'high', subject: '192.168.1.69', acked: 0,
  title: 'iCloud Private Relay is blocked', detail: 'iPhone asked…',
  attrs: { who: { ip: '192.168.1.69', name: 'iPhone', mac: 'ca:51:71:75:2f:b9', addresses: ['192.168.1.69', '2600::1'] },
    what: { kind: 'dns', domain: 'mask.icloud.com', domains: ['mask.icloud.com', 'mask-h2.icloud.com'], queries: 72 },
    where: { name: 'Pi-hole 192.168.1.53', ip: '192.168.1.53', kind: 'resolver', list: 'pihole special domain' },
    why: { kind: 'private_relay_blocked', count: 72, window_min: 15, answer: 'NXDOMAIN', list: 'pihole special domain', resolver: 'pihole:192.168.1.53',
      effect: 'Safari can stall or refuse to load pages.', fix: 'pihole-FTL --config dns.specialDomains.iCloudPrivateRelay false',
      switch: { server: '192.168.1.53', key: 'dns.specialDomains.iCloudPrivateRelay', value: false, label: 'Let Private Relay work on this Pi-hole' } } } };
var connected = 1;
FS.get = function(p){
  if (p.indexOf('/api/visibility/host') === 0) return Promise.resolve({ host: { ip: '192.168.1.69', name: 'iPhone', mac: 'ca:51:71:75:2f:b9' }, device: {}, totals: {}, dns_totals: {}, addresses: ['192.168.1.69'] });
  if (p.indexOf('/api/system/findings') === 0) return Promise.resolve({ findings: [relay] });
  if (p.indexOf('/api/pihole/status') === 0) return Promise.resolve({ connected: connected });
  if (p.indexOf('/api/pihole/config') === 0) return Promise.resolve({ servers: [{ url: 'https://192.168.1.53', host: '192.168.1.53', version: 'v6.2', writable: false, blocking: 'enabled', read_only_reason: 'app_sudo is off' }], warnings: [],
    sections: [{ id: 'special', title: 'Device-specific behaviour', intro: 'Built-in answers', settings: [{ key: 'dns.specialDomains.iCloudPrivateRelay', label: 'Block iCloud Private Relay', guide: 'On, the Pi-hole answers NXDOMAIN', type: 'boolean', values: { 'https://192.168.1.53': false }, differs: false }] }] });
  if (p.indexOf('/api/pihole/domains') === 0) return Promise.resolve({ domains: [{ domain: 'api3.siftscience.com', type: 'allow', kind: 'exact', comment: 'FlowSight', enabled: true, servers: { 'https://192.168.1.53': true } }], servers: ['https://192.168.1.53'] });
  return Promise.resolve({});
};
load('web/static/pages.js');
load('web/static/advice.js');
var FAILURE = null;
var el = mkEl();
FS.pages.host.render(el, { arg: '192.168.1.69', params: {} }).then(function () {
  var h = el.innerHTML;
  ['Needs attention on this device', 'iCloud Private Relay is blocked', 'Safari can stall', 'What to do.', 'Let Private Relay work on this Pi-hole', 'mask-h2.icloud.com', 'NXDOMAIN', 'host-findings'].forEach(function (s) {
    if (h.indexOf(s) < 0) throw new Error('host page missing: ' + s);
  });
  return FS.renderPihole(el = mkEl());
}).then(function () {
  var h = el.innerHTML;
  ['read only', 'app_sudo is off', 'Block iCloud Private Relay', 'On, the Pi-hole answers NXDOMAIN', 'Pi-hole blocking', 'Pause 5 min', 'Device advisories caused by a Pi-hole'].forEach(function (s) {
    if (h.indexOf(s) < 0) throw new Error('pihole page missing: ' + s);
  });
  if (h.indexOf('<form class="ph-set"') >= 0) throw new Error('a read-only Pi-hole must not offer edits');
  if (FS.issueMark('192.168.1.69') !== '') { /* index not loaded yet: fine */ }
  return FS.dnsTabs('pihole');
}).then(function (tabs) {
  ['#modules/dns"', '#modules/dns?tab=names', '#modules/dns?tab=pihole" class="on"', '#modules/dns?tab=phblock', 'Resolver', 'Device names'].forEach(function (x) {
    if (tabs.indexOf(x) < 0) throw new Error('settings tabs missing: ' + x);
  });
  return FS.loadIssues();
}).then(function () {
  if (FS.issueMark('2600::1').indexOf('iCloud Private Relay is blocked') < 0) throw new Error('issue mark should follow every address of the device');
  print('advice: host callout, Pi-hole tab, and device marks render');
}).catch(function (e) { FAILURE = e; });
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;

// Naming a device offers a DNS name (forward and reverse), the host page
// shows the device's DNS name, and DNS › Local names lists the names with
// what each resolver answers.
var window = this;
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{}, addEventListener:function(){}, appendChild:function(){}, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null, closest:function(){ return mkEl(); }, remove:function(){} }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, addEventListener:function(){}, body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} }; var location = { hash:'' }; var setTimeout = function(){};
function URLSearchParams(obj) { this.params = obj || {}; this.set = function(k, v) { this.params[k] = v; }; this.toString = function() { return Object.entries(this.params).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&'); }; }
load('web/static/lib.js');
FS.state = FS.state || {}; FS.state.hours = 24; FS.since = function(){ return 'hours=24'; };
FS.go = function(){}; FS.setTitle = function(){};
var modalHTML = ''; FS.modal = function (html) { modalHTML = html; };
var suggest = { ip: '192.168.1.44', mac: 'aa:bb:cc:dd:ee:ff', label: 'kitchen-ipad', domains: ['grio.co', 'internal'], can_follow: true, gateway: true,
  addresses: [{ ip: '192.168.1.44' }, { ip: '2600::44', stable: false, note: 'privacy address: the device replaces it every day or so' }],
  reverse_taken: {}, existing: null,
  piholes: [{ url: 'https://192.168.1.53', host: '192.168.1.53', writable: true }, { url: 'https://192.168.1.54', host: '192.168.1.54', writable: false }] };
FS.get = function (p) {
  if (p.indexOf('/api/dns/names/suggest') === 0) return Promise.resolve(suggest);
  if (p.indexOf('/api/dns/names') === 0) return Promise.resolve({ domains: ['grio.co'], gateway: true, piholes: [], names: [{ record: { fqdn: 'nas.grio.co', display: 'NAS', addresses: ['192.168.1.10'], mac: 'aa:bb:cc:00:00:01', follow: true, updated: 1790500000 },
    status: [{ label: 'gateway resolver', forward: ['192.168.1.10'], forward_ok: true, reverse: { '192.168.1.10': ['nas.grio.co'] }, reverse_ok: true }, { label: 'Pi-hole 192.168.1.53', forward: [], forward_ok: false, reverse: {}, reverse_ok: false }] }] });
  if (p.indexOf('/api/pihole/status') === 0) return Promise.resolve({ connected: 1 });
  if (p.indexOf('/api/visibility/host') === 0) return Promise.resolve({ host: { ip: '192.168.1.44', name: 'Kitchen iPad', mac: 'aa:bb:cc:dd:ee:ff' }, device: {}, totals: {}, dns_totals: {}, addresses: ['192.168.1.44'] });
  if (p.indexOf('/api/system/findings') === 0) return Promise.resolve({ findings: [] });
  return Promise.resolve({});
};
load('web/static/pages.js');
load('web/static/advice.js');
load('web/static/names.js');
var FAILURE = null, el = mkEl();
FS.pages.host.render(el, { arg: '192.168.1.44', params: {} }).then(function () {
  if (el.innerHTML.indexOf('<dt>DNS name</dt>') < 0 || el.innerHTML.indexOf('not in DNS') < 0) throw new Error('host page: no DNS name row');
  return FS.nameDevice('192.168.1.44', 'Kitchen iPad');
}).then(function () {
  ['Also add it to DNS', 'forward and reverse', 'kitchen-ipad', 'grio.co', 'privacy address', 'Gateway resolver', 'Pi-hole 192.168.1.53', 'read only', 'Follow the device', 'local-names.md'].forEach(function (s) {
    if (modalHTML.indexOf(s) < 0) throw new Error('name dialog missing: ' + s);
  });
  if (!/value="192\.168\.1\.44" checked/.test(modalHTML)) throw new Error('the IPv4 address should be chosen by default');
  if (/value="2600::44" checked/.test(modalHTML)) throw new Error('a privacy IPv6 address must not be chosen by default');
  if (!/value="https:\/\/192\.168\.1\.54" disabled/.test(modalHTML)) throw new Error('a read-only Pi-hole must be disabled');
  return FS.pages.dnsnames.render(el = mkEl(), { params: {} });
}).then(function () {
  ['Local names</a>', 'nas.grio.co', 'answers', 'no forward', 'follows', 'Pi-hole</a>'].forEach(function (s) {
    if (el.innerHTML.indexOf(s) < 0) throw new Error('local names page missing: ' + s);
  });
  print('names: dialog offers forward and reverse DNS, host page shows the name, Local names lists resolver answers');
}).catch(function (e) { FAILURE = e; });
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;

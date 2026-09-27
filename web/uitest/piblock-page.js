// Settings › dns › Pi-hole blocking renders every part, marks what differs
// between Pi-holes, offers the target picker and sync, and FlowSight
// categories as lists.
var window = this;
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, dataset:{}, addEventListener:function(){}, appendChild:function(){}, querySelector:function(){ return null; }, querySelectorAll:function(){ return []; } }; }
var document = { getElementById:function(){ return null; }, querySelector:function(){ return null; }, querySelectorAll:function(){ return []; }, addEventListener:function(){}, body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} }; var location = { hash:'' }; var setTimeout = function(){};
load('web/static/lib.js');
FS.state = FS.state || {}; FS.state.page = 'modules'; FS.parseHash = function(){ return { page: 'modules', arg: 'dns', params: { tab: 'phblock' } }; };
var A = 'https://192.168.1.53', B = 'https://192.168.1.54';
FS.get = function (p) {
  if (p.indexOf('/api/pihole/blocking') === 0) return Promise.resolve({
    servers: [{ url: A, host: '192.168.1.53', writable: true, gravity: { running: false, ok: true, finished: 1790500000, tail: ['[✓] Done.'] } }, { url: B, host: '192.168.1.54', writable: true }],
    groups: [{ name: 'Default', enabled: true, default: true, servers: { [A]: { id: 0 }, [B]: { id: 0 } }, missing: 0 }, { name: 'Kids', enabled: true, servers: { [A]: { id: 3 } }, missing: 1 }],
    lists: [{ address: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', type: 'block', enabled: true, groups: ['Default'], servers: { [A]: { number: 74761 }, [B]: { number: 74761 } }, missing: 0, differs: false },
      { address: 'http://192.168.0.1:8080/feeds/categories/ads.txt?key=x', type: 'block', enabled: true, groups: ['Kids'], category: 'ads', servers: { [A]: { number: 12 } }, missing: 1 }],
    clients: [{ client: '192.168.1.68', flowsight_name: 'Nintendo Switch b032', groups: ['Kids'], servers: { [A]: {}, [B]: {} }, missing: 0, differs: true }],
    domains: [{ domain: 'madison.logs.roku.com', type: 'deny', kind: 'exact', enabled: true, groups: ['Default'], servers: { [A]: {}, [B]: {} }, missing: 0 }],
    categories: [{ name: 'ads', domains: 120000, subscribed: { [A]: 'block' } }, { name: 'gambling', domains: 3000, subscribed: null }]
  });
  return Promise.resolve({});
};
load('web/static/piblock.js');
var el = mkEl(), FAILURE = null;
FS.renderPiholeBlocking(el).then(function () {
  var h = el.innerHTML;
  ['Apply changes to', 'all 2 Pi-holes', '192.168.1.54 only', 'Keep the Pi-holes the same', 'Sync now', 'Blocklists and allowlists', 'StevenBlack', 'FlowSight category ads',
   'only on 192.168.1.53', 'Add to all', 'FlowSight categories as Pi-hole lists', 'Block with it', 'Unsubscribe', 'Groups', 'Kids', 'Clients in groups', 'Nintendo Switch b032',
   'differs between Pi-holes', 'Allow and deny entries', 'madison.logs.roku.com', 'Rebuild now', 'rebuilt'].forEach(function (s) {
    if (h.indexOf(s) < 0) throw new Error('blocking tab missing: ' + s);
  });
  print('piblock: lists, categories, groups, clients, entries, gravity, target and sync render; differences marked');
}).catch(function (e) { FAILURE = e; });
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;

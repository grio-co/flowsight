var window = this; window.addEventListener = function(){};
var FAILURE = null; function fail(e){ FAILURE = e; }
function mkEl(){ return { innerHTML:'', onclick:null, dataset:{}, style:{}, classList:{ add:function(){}, remove:function(){}, toggle:function(){}, contains:function(){ return false; } }, addEventListener:function(){}, setAttribute:function(){}, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; } }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, addEventListener:function(){}, body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash:'#app/BitTorrent' };
var setTimeout = function(){};
load('web/static/lib.js');
FS.get = function(p){
  if (p.indexOf('/api/visibility/app?') === 0) return Promise.resolve({ app:'BitTorrent', category:'Download', breed:'Unsafe',
    note:{ purpose:'Peer-to-peer file sharing. Downloads and, always, uploads to many peers at once.', risk:'Heavy sustained upload. nDPI grades it unsafe.', issues:['Saturates upload'], look_for:['The device running it'], source:'curated' },
    totals:{ flows:1200, bytes_in:5e9, bytes_out:9e9, blocked:0, hosts:1, first_seen:1790300000, last_seen:1790480000 },
    devices:[{ ip:'192.168.1.128', name:'seedbox', flows:1200, bytes_in:5e9, bytes_out:9e9 }],
    domains:[{ domain:'tracker.example.org', flows:40, bytes_in:1000, bytes_out:2000 }],
    destinations:[{ ip:'203.0.113.9', port:6881, proto:'tcp', country:'NL', asn:'1136', flows:30, bytes:1e8 }],
    ports:[{ port:6881, proto:'tcp', flows:900 }], countries:[{ country:'NL', flows:300 }], visibility:{ opaque:1100, sni:100 },
    timeline:[{ t:1790470800, flows:60, bytes_in:2e8, bytes_out:4e8 }],
    policies:[{ name:'no-torrents', enabled:true, action:'block', by:'app', members:3 }] });
  if (p.indexOf('/api/visibility/app-category') === 0) return Promise.resolve({ category:'Download', note:{ purpose:'File downloads and peer-to-peer.', risk:'Volume.' }, apps:[{ app:'BitTorrent', breed:'Unsafe', flows:1200, hosts:1, bytes_in:5e9, bytes_out:9e9, blocked:0 }], devices:[], totals:{ flows:1200, hosts:1, bytes_in:5e9, bytes_out:9e9 }, policies:[] });
  if (p.indexOf('/api/visibility/unknown') === 0) return Promise.resolve({ total_flows:4200, signatures:[{ signature:'tcp/5223 apple.com', label:'TCP to apple.com on 5223 (push notifications)', name:'', flows:900, bytes_in:1e7, bytes_out:2e6, hosts:3, first_seen:1790300000, last_seen:1790480000, sample_ip:'17.57.144.86', asn:'714', devices:[{ ip:'192.168.1.119', name:'MacBookPro', flows:600 }] }], named:{}, note:'nDPI names an application from a flow.' });
  return Promise.resolve({});
};
load('web/static/apps.js');
var el = mkEl();
FS.pages.app.render(el, { arg:'BitTorrent', params:{} }).then(function(){
  var h = el.innerHTML;
  ['What it is for', 'Peer-to-peer file sharing', 'Risk', 'What to look for', 'seedbox', 'tracker.example.org', '203.0.113.9', 'no-torrents', 'Unsafe', 'Download'].forEach(function(s){ if (h.indexOf(s) < 0) throw new Error('app page missing ' + s); });
  if (h.indexOf('#appcat/Download') < 0) throw new Error('the category should be a link');
  if (h.indexOf('id="app-block"') < 0) throw new Error('the app page needs a block action');
  print('App page renders the write-up, who, where, what policy says, and the actions');
  var el2 = mkEl();
  return FS.pages.appcat.render(el2, { arg:'Download', params:{} }).then(function(){
    var t = el2.innerHTML;
    if (t.indexOf('#app/BitTorrent') < 0 || t.indexOf('File downloads') < 0) throw new Error('category page should list its apps with the note');
    print('Category page renders');
    var el3 = mkEl();
    return FS.pages.unknown.render(el3, { params:{} }).then(function(){
      var u = el3.innerHTML;
      if (u.indexOf('apple.com') < 0 || u.indexOf('push notifications') < 0 || u.indexOf('data-name-sig=') < 0) throw new Error('unknown catalogue should show signatures with a way to name them');
      print('Unknown catalogue renders');
    });
  });
}).catch(fail);
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;

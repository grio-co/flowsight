var window = this;
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, dataset:{}, addEventListener:function(){}, appendChild:function(){},
  querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; } }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){}, createElement:function(){ return mkEl(); },
  body:{ contains:function(){ return true; } } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash:'#findings' };
var setTimeout = function(){};
load('web/static/lib.js');

// A finding that names one device of several says so, and plain facts a
// module gives are shown under Why.
var cols = FS.findingCols();
function col(t){ for (var i = 0; i < cols.length; i++) if (cols[i].t === t) return cols[i].f; throw new Error('no column ' + t); }
var row = { module: 'web', kind: 'pinned', severity: 'info', subject: 'pinned.example.com',
  title: 'Pinned certificate: pinned.example.com is not inspected', detail: 'd',
  attrs: { who: { ip: '192.168.1.50', name: 'iPhone', others: 2 }, where: { domain: 'pinned.example.com' },
           why: { facts: ['refused the inspection certificate 4 times', 'relayed without inspection'] } } };
var who = col('Who')(row), why = col('Why')(row), where = col('Where')(row);
if (who.indexOf('and 2 other devices') < 0) throw new Error('who: ' + who);
if (why.indexOf('refused the inspection certificate 4 times') < 0 || why.indexOf('relayed without inspection') < 0) throw new Error('why: ' + why);
if (where.indexOf('pinned.example.com') < 0) throw new Error('where: ' + where);
row.attrs.who.others = 1;
if (col('Who')(row).indexOf('and 1 other device<') < 0) throw new Error('singular: ' + col('Who')(row));
row.attrs.why.facts = ['<b>x</b>'];
if (col('Why')(row).indexOf('<b>x</b>') >= 0) throw new Error('facts must be escaped');
print('finding columns: others and facts render');

// A bandwidth-test row whose download came from a mirror says so.
var h = FS.speedTestsHTML({ tests: [
  { id: '1', ts: 1790480000, down_mbit: 900, up_mbit: 700, down_source: 'Linode Dallas', down_source_ms: 31.4 },
  { id: '2', ts: 1790480100, down_mbit: 910, up_mbit: 710, down_source: 'Cloudflare' } ] });
if (h.indexOf('download from Linode Dallas · 31 ms') < 0) throw new Error('mirror source not shown');
if (h.indexOf('>built-in<') < 0) throw new Error('Cloudflare rows still read built-in');
print('speed log: stand-in download source shown');

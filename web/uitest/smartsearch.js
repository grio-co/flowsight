// SmartSearch: every word must match; a table filters its full data (not
// just the rows on screen), counts its matches, and says when none match;
// an address a cell only links to still counts.
var window = this;
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, dataset:{}, classList:{ toggle:function(){}, add:function(){}, remove:function(){}, contains:function(){ return false; } }, addEventListener:function(){}, appendChild:function(){}, querySelector:function(){ return null; }, querySelectorAll:function(){ return []; } }; }
var document = { getElementById:function(){ return null; }, querySelector:function(){ return null; }, querySelectorAll:function(){ return []; }, addEventListener:function(){}, body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} }; var sessionStorage = localStorage; var location = { hash:'' }; var setTimeout = function(){};
load('web/static/lib.js');
load('web/static/smartsearch.js');
FS.state = FS.state || {}; FS.state.page = 'test';
var S = FS.smart;
S.q = 'apple push'; S.terms = ['apple', 'push'];
if (!S.match('Apple Push Notification service') || S.match('Apple iCloud')) throw new Error('every word must match');
var rows = [];
for (var i = 0; i < 250; i++) rows.push({ ip: '192.168.1.' + (i % 250), app: i === 7 || i === 180 ? 'ApplePush' : 'Netflix', note: 'push' });
rows[180].app = 'Apple Push';
var cols = [{ t: 'Device', f: function (r) { return '<a href="#host/' + r.ip + '">x</a>'; } }, { t: 'App', k: 'app' }];
S.q = 'apple'; S.terms = ['apple'];
var html = FS.table(rows, cols);
if (html.indexOf('data-ss-count="2"') < 0) throw new Error('a table counts its matches across all rows, not the first page: ' + html.slice(0, 200));
if ((html.match(/<tr[ >]/g) || []).length !== 3) throw new Error('only matching rows are drawn (plus the header)');
S.q = '192.168.1.249'; S.terms = ['192.168.1.249'];
if (FS.table(rows, cols).indexOf('data-ss-count="1"') < 0) throw new Error('a raw value a cell only links to still matches');
S.q = 'zzz'; S.terms = ['zzz'];
html = FS.table(rows, cols);
if (html.indexOf('No rows match') < 0 || html.indexOf('data-ss-count="0"') < 0) throw new Error('an empty result says so');
S.q = ''; S.terms = [];
html = FS.table(rows, cols);
if (html.indexOf('data-ss-count') >= 0 || (html.match(/<tr[ >]/g) || []).length !== 101) throw new Error('without a search the table is unchanged (100 rows paged)');
print('smartsearch: words AND, tables filter all their rows and count, raw values match, empty results say so');

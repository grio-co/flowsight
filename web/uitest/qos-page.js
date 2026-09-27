var window = this;
var FAILURE = null;
function fail(e){ FAILURE = e; }
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{},
  addEventListener:function(){}, appendChild:function(){},
  querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; },
  getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){},
  body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash:'#qos' };
var setTimeout = function(){};
load('web/static/lib.js');

var STATUS = { active:true, applied:true, error:'', since:1790070000, down_mbit:93, up_mbit:56,
  rules:[
    { raw:'192.168.1.178 = low', match:'192.168.1.178', is_host:true, class:'low' },
    { raw:'redgifs.com = high', match:'redgifs.com', is_host:false, class:'high' },
    { raw:'oops', match:'oops', is_host:false, error:'expected something of the form "what = class"' } ],
  resolved:{ 'redgifs.com': 4 },
  queues:[ { queue:12, name:'download low', detail:'q00012 50 sl. 2 flows' } ],
  note:'Weights are shares, not reservations.' };
var PREVIEW = { lan:'vtnet0', anchor:'match in on vtnet0 all dnqueue(21)\nmatch in on vtnet0 from <qos_r0> to any dnqueue(22)', tables:{} };

FS.get = function(p){
  if (p.indexOf('/api/qos/status') === 0) return Promise.resolve(STATUS);
  if (p.indexOf('/api/qos/preview') === 0) return Promise.resolve(PREVIEW);
  if (p.indexOf('/api/qos/speedtests') === 0) return Promise.resolve({ running:false, stage:'', interface:'vtnet1', note:'The built-in test runs from this firewall.',
    tests:[{ id:'t1', ts:1790480000, attempt:1, rerun:false, down_mbit:912.4, up_mbit:38.1, iface_down_mbit:940.2, iface_up_mbit:39.0, base_down_mbit:12.3, base_up_mbit:0.8, load_down_mbit:27.8, load_up_mbit:0.9,
      ookla_server:'Kansas City, MO, United States', ookla_sponsor:'Example ISP', ookla_down_mbit:905.0, ookla_up_mbit:37.9, ookla_latency_ms:11.2, diverge_down:0.008, diverge_up:0.005, suggest_down_mbit:940, suggest_up_mbit:39, note:'the two measurements agree' }] });
  return Promise.resolve({});
};
load('web/static/pages3.js');

var el = mkEl();
FS.pages.qos.render(el, { params:{} }).then(function(){
  var h = el.innerHTML;
  ['192.168.1.178', 'redgifs.com', 'vtnet0', 'download low', '93 / 56'].forEach(function(s){
    if (h.indexOf(s) < 0) throw new Error('page missing ' + s);
  });
  if (h.indexOf('expected something of the form') < 0) throw new Error('a rule that cannot be read must be shown');
  if (h.indexOf('4 addresses') < 0) throw new Error('resolved address counts not shown');
  if (h.indexOf('dnqueue(22)') < 0) throw new Error('the generated ruleset must be visible before it is trusted');
  // Off state must say plainly that nothing is in force.
  STATUS.active = false; STATUS.applied = false;
  var el2 = mkEl();
  return FS.pages.qos.render(el2, { params:{} }).then(function(){
    if (el2.innerHTML.indexOf('Shaping is off') < 0) throw new Error('the off state must say nothing is in force');
    if (h.indexOf('Bandwidth test') < 0 || h.indexOf('id="speed-run"') < 0) throw new Error('the Priority page needs the bandwidth test card');
  if (h.indexOf('Use 940 / 39') < 0 || h.indexOf('Example ISP') < 0) throw new Error('a finished test should offer its numbers and name the comparison server');
  print('Priority page renders rules, queues, the generated ruleset and the off state');
  });
}).catch(fail);
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;

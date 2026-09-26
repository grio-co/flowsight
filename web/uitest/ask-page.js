// The Ask page: off, it explains how to turn the assistant on and that
// nothing leaves; on, it says what leaves, offers the box, and lists
// recent questions with their tool trail.
var window = this; var handlers = {};
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, onsubmit:null, dataset:{}, value:'', addEventListener:function(k,f){ handlers[k]=f; }, appendChild:function(){}, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; }, addEventListener:function(){}, body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} }; var location = { hash:'#ask' }; var setTimeout = function(){};
load('web/static/lib.js');
var mode = 'off';
FS.get = function(p){
  if (p.indexOf('/api/assistant/status') === 0) return Promise.resolve(mode === 'off' ? { provider:'off', enabled:false, ready:false, tools:190, questions:0 } : { provider:'anthropic', enabled:true, ready:true, model:'claude-sonnet-5', tools:190, questions:1 });
  if (p.indexOf('/api/assistant/conversations') === 0) return Promise.resolve(mode === 'off' ? { conversations:[] } : { conversations:[{ id:'c-1', question:'What is 192.168.1.115?', answer:'An Amazon Echo. It talked to NTP servers in Canada.', created_at: 1790376243, tool_calls:[{ tool_name:'identity_hosts', route:'GET /api/identity/hosts?hours=24', summary:'262 hosts' }] }], total:1 });
  return Promise.resolve({});
};
load('web/static/pages3.js');
var FAILURE = null;
var el = mkEl();
FS.pages.ask.render(el, { params:{} }).then(function(){
  var h = el.innerHTML;
  if (h.indexOf('The assistant is off') < 0 || h.indexOf('nothing leaves while it is off') < 0) throw new Error('off state not explained');
  if (h.indexOf('claude mcp add flowsight') < 0) throw new Error('MCP hint missing');
  if (h.indexOf('<textarea name="q" rows="3" placeholder="Ask about a device, a country, a domain, a policy…" disabled>') < 0) throw new Error('box should be disabled when off');
  mode = 'on'; var el2 = mkEl();
  return FS.pages.ask.render(el2, { params:{} }).then(function(){
    var g = el2.innerHTML;
    if (g.indexOf('leave this gateway for Anthropic') < 0) throw new Error('data-leaves banner missing');
    if (g.indexOf('What is 192.168.1.115?') < 0 || g.indexOf('identity_hosts') < 0) throw new Error('conversation or tool trail missing');
    if (g.indexOf('<textarea name="q" rows="3" placeholder="Ask about a device, a country, a domain, a policy…">') < 0) throw new Error('question box not enabled when ready');
    print('ask page: off explains, on warns about data leaving and shows the trail');
  });
}).catch(function(e){ FAILURE = e; });
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;

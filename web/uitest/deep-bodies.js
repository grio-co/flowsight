var window = this;
var FAILURE = null;
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, dataset:{}, onclick:null,
  addEventListener:function(){}, appendChild:function(){},
  querySelector:function(){ return null; }, querySelectorAll:function(){ return []; } }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){}, createElement:function(){ return mkEl(); },
  body:{ contains:function(){ return true; } } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash:'#deep' };
var setTimeout = function(f){ };
load('web/static/lib.js');

var STATUS = { licensed:true, scanning:true, listening:true, port:1344, requests:5, decoded:0,
  bytes_in:10, bytes_out:10, clients:[], names:[], note:'n' };
var BODIES = { recording:true, hosts:['*.insta360.com'], expires_in_minutes:60, bodies:[
  { id:7, ts:1790480000, client:'192.168.1.119', host:'openapi-g.insta360.com', method:'POST',
    url:'https://openapi-g.insta360.com/v1/view/list?page=…', direction:'request',
    content_type:'application/json', size:214, complete:true } ] };
FS.api = function(p){
  if (p.indexOf('/api/mitm/status') === 0) return Promise.resolve(STATUS);
  if (p.indexOf('/api/mitm/requests') === 0) return Promise.resolve({ requests:[] });
  if (p.indexOf('/api/mitm/bodies') === 0) return Promise.resolve(BODIES);
  return Promise.resolve({});
};
load('web/static/pages3.js');

var page = FS.pages['deep'];
if (!page) throw new Error('no deep page');
var el = mkEl();

// Recording off: the page must not mention recorded bodies at all.
page.render(el, { params:{} }).then(function(){
  if (el.innerHTML.indexOf('Recording bodies') >= 0) throw new Error('recording card shown while recording is off');
  STATUS.recording_bodies = true; STATUS.body_hosts = ['*.insta360.com'];
  STATUS.bodies_stored = 1; STATUS.expires_in_minutes = 60;
  var el2 = mkEl();
  return page.render(el2, { params:{} }).then(function(){
    var h = el2.innerHTML;
    if (h.indexOf('Recording bodies') < 0) throw new Error('recording card missing while recording');
    if (h.indexOf('*.insta360.com') < 0) throw new Error('the hosts being recorded must be named');
    if (h.indexOf('decrypted traffic with nothing removed') < 0) throw new Error('the page must say what a recorded body is');
    if (h.indexOf('id="bodies-clear"') < 0) throw new Error('no way to delete the recordings');
    if (h.indexOf('data-body="7"') < 0) throw new Error('the recording is not listed');
    print('deep page: recording bodies is announced, listed and clearable');
  });
}).catch(function(e){ FAILURE = e; });
if (FAILURE) throw FAILURE;

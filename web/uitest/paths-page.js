var window = this;
window.addEventListener = function(){};
var FAILURE = null;
function fail(e){ FAILURE = e; }
var navigator = { geolocation: { getCurrentPosition: function(){} } };
function mkEl(){ var o = { innerHTML:'', style:{ setProperty:function(){} }, hidden:true, onclick:null, value:'', dataset:{},
  classList:{ _s:{}, add:function(c){this._s[c]=1;}, remove:function(c){delete this._s[c];},
    contains:function(c){return !!this._s[c];},
    toggle:function(c,on){ if(on===undefined) on=!this._s[c]; if(on) this.add(c); else this.remove(c); return on; } },
  addEventListener:function(){}, appendChild:function(){}, setAttribute:function(){},
  getBoundingClientRect:function(){ return {left:0,top:0,width:100,height:50,bottom:0}; },
  getAttribute:function(a){ return this._a && this._a[a] != null ? this._a[a] : (a === 'data-r' ? '3' : null); },
  hasAttribute:function(a){ return a === 'data-r' || !!(this._a && a in this._a); },
  querySelector:function(){ return mkEl(); },
  // A sized marker is always found, so the code that rescales markers runs
  // in the test as it does in the page; it was skipped here once while it
  // read a variable declared further down, and only the browser noticed.
  querySelectorAll:function(sel){ return sel === '[data-r]' ? [mkEl()] : []; }, parentNode:null };
  o.setAttribute = function(a, v){ (o._a = o._a || {})[a] = String(v); };
  return o; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){},
  body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash:'#paths' };
var setTimeout = function(){};
load('web/static/lib.js');
load('web/static/land.js');

// Projection must put the equator and prime meridian in the middle.
var mid = FS.project(0, 0, 720, 360);
if (Math.abs(mid[0] - 360) > 0.001 || Math.abs(mid[1] - 180) > 0.001) throw new Error('projection centre wrong: ' + mid);
var tl = FS.project(90, -180, 720, 360);
if (tl[0] !== 0 || tl[1] !== 0) throw new Error('north-west corner wrong: ' + tl);
print('FS.project OK');

var GRAPH = { rejected: [ { id:'h30', index:30, ips:['51.10.6.166'], names:['be1013.rwa02.co8.ntwk.msn.net'], source:'database', where:'Singapore, SG', lat:1.35, lon:103.82, rtt_ms:58, floor_ms:162.6, why:'answers in 58.0 ms, but 16360 km away cannot answer in less than 163 ms', now:'not drawn there' } ], nodes: [
  { id:'h9', index:9, ips:['104.119.40.200'], rtt_ms:183, located:true, lat:37.5665, lon:126.978, city:'Seoul', country:'KR',
    location_source:'corrected', database_said:'Cambridge, Massachusetts, US', moved_km:11000, db_lat:42.3649, db_lon:-71.0888,
    corrected_by:'ae10.r02.rio01.icn.netarch.akamai.com', corrected_at:1790000000, detail:{ asn:'20940', prefix:'104.119.40.0/21' } },
  { id:'h11', index:11, ips:['23.56.140.9'], rtt_ms:205, located:false,
    database_set_aside:"the database put it at Cambridge, Massachusetts, US, the registrant's address for AS20940; 2 of that network's routers there have been shown to be elsewhere, so the database is not believed about it",
    detail:{ asn:'20940' } },
  { id:'h1', index:1, ips:['192.168.1.254'], located:false, silent:false },
  // Answered, unplaceable, put between its neighbours by timing.
  { id:'h25', index:25, ips:['203.0.113.9'], located:true, lat:40.0, lon:-60.0, rtt_ms:58.0,
    location_source:'between', inferred:true, between:['172.11.154.1','1.1.1.1'],
    between_how:'24.6 ms of the 41.2 ms between them' },
  { id:'h2', index:2, ips:['172.11.154.1'], located:true, lat:39.18, lon:-96.57, country:'US', city:'Manhattan', region:'Kansas', rtt_ms:3.4 },
  { id:'h3', index:3, ips:['32.130.107.216','32.130.107.218'], located:true, lat:32.78, lon:-96.80, country:'US', city:'Dallas', rtt_ms:16.7 },
  // Placed by its own hostname, against a database that said London.
  { id:'h35', index:6, ips:['51.10.49.216'], names:['po1.owr03.lax31.ntwk.msn.net'], located:true,
    lat:34.0522, lon:-118.2437, country:'US', region:'CA', city:'Los Angeles', rtt_ms:134.7,
    location_source:'name', database_said:'London, England, GB', moved_km:8756, db_lat:51.5072, db_lon:-0.1276,
    detail:{ pop_code:'lax', pop_city:'Los Angeles, CA, US', pop_score:0.95, pop_how:'code',
      pop_why:'134.7 ms fits 3000 km; better than London', asn:'8075',
      as_name:'MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US', prefix:'51.10.0.0/15',
      rir:'ripencc', allocated:'1993-09-01', net_name:'MSFT-51-10', org:'Microsoft Corporation',
      org_addr:'One Microsoft Way, Redmond, WA, 98052, United States',
      facilities:[{ name:'Equinix LA1 - Los Angeles', address:'600 W 7th St, Los Angeles, CA, 90017-3859, US' }],
      facilities_scoped:true } },
  { id:'h4', index:4, ips:['1.1.1.1'], located:true, lat:-33.86, lon:151.20, country:'AU', city:'Sydney', rtt_ms:18.9,
    anycast:true, anycast_sites:120, provider:'anycast census, AS13335 anycast',
    detail:{ asn:'13335', abuse:{ score:0, reports:0, isp:'Cloudflare, Inc.', usage_type:'Content Delivery Network', domain:'cloudflare.com', country:'AU', source:'AbuseIPDB', at:1790000000 }, shodan:{ ip:'1.1.1.1', ports:[53,443], hostnames:['one.one.one.one'], keyed:false, at:1790000000 }, fcc:{id:'130001', name:'AT&T Inc.', holding:'AT&T', states:21, locations:12345678, techs:'Fiber, Cable, Fixed Wireless'} },
    endpoint:true, reaches:['1.1.1.1'], bytes_in: 734003200, bytes_out: 12582912,
    impossible:true, distance_km:15320, floor_ms:153.2, via:'Southern Cross NEXT', why:'answers in 18.9 ms, but 14071 km away cannot answer in less than 141 ms' },
  // Clears the floor by 4%: physics allows it, a real route does not.
  { id:'h7', index:7, ips:['62.115.143.52'], located:true, lat:51.5072, lon:-0.1276, country:'GB', city:'London', rtt_ms:73.2,
    tight:true, distance_km:7000, floor_ms:70.0, expected_km:9450, expected_ms:95.9,
    why:'answers in 73.2 ms, which light allows over 7000 km but no built route does: 9450 km once fibre\u2019s detours are allowed for comes to 94.5 ms, and 7 hops add 1.4 ms more' },
  ],
  silent_count: 1,
  legs: [
    { from:'h2', to:'h3', destinations:['1.1.1.1','8.8.8.8'], shared:true },
    { from:'h3', to:'h4', destinations:['1.1.1.1'], shared:false, straight_km:13500,
      cables:[{ name:'Southern Cross NEXT', km:13700, floor_ms:137 }],
      // A crossing follows its cable, including over the antimeridian.
      via:'Southern Cross NEXT', via_km:13700,
      route:[{lat:32.78,lon:-96.80},{lat:21.3,lon:-157.8},{lat:-8.0,lon:179.0},
             {lat:-20.0,lon:-179.0},{lat:-33.86,lon:151.20}] },
    // Stands in for hops that could not be placed; without it h35 is a dot
    // with nothing attached to it.
    { from:'h4', to:'h35', destinations:['1.1.1.1'], shared:false, gap:true, through:3 } ] };
var DESTS = { destinations: [ { dst:'1.1.1.1', name:'one.one.one.one', country:'AU', city:'Sydney', hops:6, answered:5, complete:1, ts:1790200000, bytes_in:734003200, bytes_out:12582912 } ] };
var DEVS = { devices: [
  { key:'192.168.1.119', name:'MacBookPro', addresses:['192.168.1.119','2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6'], destinations:9 },
  { key:'192.168.2.188', name:'roku-ultra', addresses:['192.168.2.188'], destinations:2 } ] };
var HOME = { ok:true, lat:39.1836, lon:-96.5717, source:'public address', configured:'',
  public_address:'162.202.41.52',
  public_v4:['162.202.41.52'], public_v6:['2600:1700:3ab0:f43f::1'],
  detected:{ lat:39.1836, lon:-96.5717, city:'Manhattan', region:'Kansas', country:'US' },
  note:'Declaring this matters more than it looks.' };
var CAB = { cables: [
  { name:'Grace Hopper', km:6900, runs:[[[-70.0,40.7],[-30.0,45.0],[-5.0,50.1]]] },
  // A run that wraps the antimeridian; it must break, not stripe the map.
  { name:'Pacific Light', km:12800, runs:[[[170.0,20.0],[179.0,21.0],[-179.0,21.5],[-150.0,22.0]]] } ],
  attribution:"Submarine cable routes from TeleGeography's public cable map." };
var STATUS = { active:true, last_run:1790200000, destinations:2, hops:11, error:'',
  sources:{ shodan:{ mode:'click', keyed:false, known:4 }, identify:{ on:true, known:13, placed_this_session:11, queued:0, root_sites:1900 }, assistant:{ on:true, provider:'anthropic', model:'claude-haiku-4-5', known:9, queued:2, per_hour:20 }, geofeeds:{ on:true, urls:3, fetched:2, rows:512 }, reputation:{ on:true, known:42, asked_this_session:7 }, providers:{ on:true, prefixes:12345, feeds:{ aws:{name:'AWS', prefixes:8000}, azure:{name:'Microsoft Azure', prefixes:0, error:'no link found'} } }, osm_telecom:{ on:true, ways:1234, regions_loaded:3, regions_total:16, next_region:'Europe, west', weight:0.5 }, corrections:{ on:true, prefixes:3, set_aside:1 }, router_names:{on:true,codes:210}, ipmap:{on:true,answered:21,queued:300,per_minute:20,backing_off_until:0},
            registry:{on:true,queued:12}, cables:{on:true,loaded:709,error:''}, land_routes:{on:true,loaded:133,error:''}, fcc:{on:true, as_of:'2025-12-31', files:10608, providers:3758, state:'Kansas', places:600, pulled_at: 1758750000} } };

var ROUTE = { destination:'1.1.1.1',
  inside:{ addresses:['192.168.1.119','2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6'], name:'MacBookPro', vendor:'Apple' },
  talkers:{ hours:24, flows:31, services:[{app:'QUIC', domain:'one.one.one.one', port:443, proto:'udp', bytes_in:9000, bytes_out:1200, flows:20}],
    devices:[{ key:'192.168.1.119', name:'MacBookPro', vendor:'Apple', addresses:['192.168.1.119','2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6'], bytes_in:9000, bytes_out:1200, flows:20,
      services:[{app:'QUIC', domain:'one.one.one.one', port:443, proto:'udp', bytes_in:9000, bytes_out:1200, flows:20},{app:'DNS', port:53, proto:'udp', bytes_in:300, bytes_out:200, flows:11}] },
     { key:'192.168.1.53', name:'pihole', addresses:['192.168.1.53'], bytes_in:100, bytes_out:50, flows:11, services:[{app:'DNS', port:53, proto:'udp', bytes_in:100, bytes_out:50, flows:11}] }] },
  hops:[
    { id:'h1', index:1, ips:['192.168.1.254'], located:false },
    { id:'h2', index:2, ips:['172.11.154.1'], names:['172-11-154-1.lightspeed.tpkaks.sbcglobal.net'],
      located:true, city:'Topeka', country:'US', rtt_ms:3.4 },
    { id:'s3', index:3, ips:[], silent:true, located:false },
    { id:'h4', index:9, ips:['1.1.1.1'], located:true, city:'Sydney', country:'AU', rtt_ms:18.9, // hop 9 of this route; the shared node says 4
      impossible:true, why:'answers in 18.9 ms, but 14071 km away cannot answer in less than 141 ms',
      detail:{fcc:{id:'130001', name:'AT&T Inc.', holding:'AT&T', states:21, locations:12345678, techs:'Fiber, Cable, Fixed Wireless'}} } ] };

FS.get = function(p){
  if (p.indexOf('/api/paths/path') === 0) return Promise.resolve(ROUTE);
  if (p.indexOf('/api/paths/status') === 0) return Promise.resolve(STATUS);
  if (p.indexOf('/api/paths/graph') === 0) return Promise.resolve(GRAPH);
  if (p.indexOf('/api/paths/destinations') === 0) return Promise.resolve(DESTS);
  if (p.indexOf('/api/paths/devices') === 0) return Promise.resolve(DEVS);
  if (p.indexOf('/api/paths/home') === 0) return Promise.resolve(HOME);
  if (p.indexOf('/api/paths/cables') === 0) return Promise.resolve(CAB);
  return Promise.resolve({});
};
load('web/static/pages3.js');

var el = mkEl();
FS.pages.paths.render(el, { params:{} }).then(function(){
  var h = el.innerHTML;
  ['Where the traffic goes', 'one.one.one.one', 'Manhattan', 'pathmap'].forEach(function(s){
    if (h.indexOf(s) < 0) throw new Error('page missing ' + s);
  });
  // A shared leg must be drawn once, thicker, and in the neutral colour.
  if (h.indexOf('class="leg shared"') < 0) throw new Error('shared legs are not marked');
  if (h.indexOf('stroke="var(--muted)"') < 0) throw new Error('a shared leg must not take one destination\'s colour');
  // The unlocated hop must be listed, not placed at zero.
  if (h.indexOf('192.168.1.254') < 0) throw new Error('an unplaced hop must still be listed');
  if (h.indexOf('Not on the map') < 0) throw new Error('unplaced hops need their own section');
  // Silent hops are counted, never drawn.
  if (h.indexOf('never answered') < 0) throw new Error('silent hops should be counted');
  if (h.indexOf('1 hop never answered') < 0) throw new Error('the count should come from the server, which no longer sends silent nodes');
  // What feeds the map, and how each source is doing.
  if (h.indexOf('Data sources') < 0) throw new Error('the page should say what the map is fed by');
  if (h.indexOf('local or regional instance') < 0 || h.indexOf('served from 120 sites') < 0) throw new Error('an anycast hop should say what that means');
  if (h.indexOf('Abuse confidence') < 0 || h.indexOf('no reports in 90 days') < 0 || h.indexOf('Content Delivery Network') < 0) throw new Error('a hop with a reputation record should show it');
  if (h.indexOf('51.10.6.166') < 0 || h.indexOf('set aside') < 0 || h.indexOf('Said by') < 0) throw new Error('a rejected placement should be in the ruled-out table with what said it');
  if (h.indexOf('RIPE IPmap') < 0 || h.indexOf('21 positions known') < 0) throw new Error('IPmap progress should be shown');
  if (h.indexOf('FCC broadband map') < 0) throw new Error('FCC broadband map should be on the sources card');
  if (h.indexOf('Shodan') < 0 || h.indexOf('on click, no key (InternetDB only): 4 addresses on record') < 0) throw new Error('shodan should be on the sources card');
  if (h.indexOf('Look up on Shodan') < 0) throw new Error('a hop without a record should offer the lookup');
  if (h.indexOf('Open ports') < 0 || h.indexOf('53, 443') < 0) throw new Error('a hop with a record should show it');
  if (h.indexOf('Servers identifying themselves') < 0 || h.indexOf('13 anycast servers asked') < 0) throw new Error('self-identification should be on the sources card');
  if (h.indexOf('AI lookup') < 0 || h.indexOf('anthropic / claude-haiku-4-5: 9 hops answered') < 0) throw new Error('the assistant should be on the sources card');
  if (h.indexOf('Registry geofeeds') < 0 || h.indexOf('3 feeds named in registry objects') < 0) throw new Error('geofeeds should be on the sources card');
  if (h.indexOf('AbuseIPDB reputation') < 0 || h.indexOf('42 addresses known') < 0) throw new Error('reputation should be on the sources card');
  if (h.indexOf('Cloud provider ranges') < 0 || h.indexOf('AWS 8,000') < 0 || h.indexOf('Microsoft Azure: no link found') < 0) throw new Error('provider feeds should be on the sources card with their counts and errors');
  if (h.indexOf('OpenStreetMap telecom lines') < 0 || h.indexOf('1,234 lines from 3 of 16 regions, counted at 50%') < 0) throw new Error('OSM lines should be on the sources card with their weight');
  if (h.indexOf('709 cables loaded') < 0) throw new Error('cable count should be shown');
  // Traffic per endpoint, and a way to read the map by it.
  if (h.indexOf('data-rt="') < 0) throw new Error('endpoints need a traffic-scaled radius');
  if (h.indexOf('size endpoints by traffic') < 0) throw new Error('the key should offer sizing by traffic');
  if (h.indexOf('Received from it') < 0 || h.indexOf('700') < 0) throw new Error("an endpoint's card should show its traffic");
  if (h.indexOf('In / out (24h)') < 0) throw new Error('the destinations table should show traffic');
  // Two addresses at one hop is one circle, not two.
  // The world repeats east and west so a route crossing the antimeridian can
  // be shown whole, so every located node is plotted three times. The heavy
  // backdrop is referenced rather than repeated; the markers are real, because
  // a <use> copy cannot be clicked.
  var circles = (h.match(/class="hop /g) || []).length;
  if (circles !== 21) throw new Error('want 7 located nodes across 3 copies of the world, got ' + circles);
  if ((h.match(/href="#fs-world"/g) || []).length !== 3)
    throw new Error('the backdrop should be referenced three times, not redrawn');
  // The copies either side are marked so they can be taken away when the view
  // is wider than one world and there is nothing out there to show.
  if ((h.match(/<use class="worldcopy"/g) || []).length !== 2)
    throw new Error('both backdrop copies should be marked as copies');
  // Past one world the margin is emptied by clipping to the world, not by
  // hiding the copies: the copies are what carries a leg over the
  // antimeridian, and without them a wrapping route runs off into blank space.
  if (h.indexOf('id="fs-world-clip"') < 0) throw new Error('the world needs a clip for the zoomed-out margin');
  if (h.indexOf('class="stage"') < 0) throw new Error('the drawing needs a group to clip');
  if ((h.match(/<g class="worldcopy"/g) || []).length !== 2)
    throw new Error('both route copies should be marked as copies');
  if ((h.match(/<path class="land"/g) || []).length !== 1)
    throw new Error('the land outline must be drawn once and referenced, not tripled');
  // A <use> shadow copy is not reached by `.pathmap .land`, so the styling has
  // to travel with the element or the continents render solid black.
  var landTag = h.slice(h.indexOf('<path class="land"'), h.indexOf('d="', h.indexOf('<path class="land"')));
  if (landTag.indexOf('style=') < 0 || landTag.indexOf('fill:') < 0)
    throw new Error('land inside <defs> needs its paint inline, not from a descendant selector');
  if (landTag.indexOf('var(--') < 0) throw new Error('inline paint must still follow the theme');
  if (h.indexOf('transform="translate(-720,0)"') < 0 || h.indexOf('transform="translate(720,0)"') < 0)
    throw new Error('routes and markers need a copy a world either side');

  // A hop must carry its operator, not just a dot. Measured, resolved,
  // inferred and registered are four different kinds of claim and the card
  // has to keep them apart.
  if (h.indexOf('AS8075') < 0) throw new Error('the network running a hop should be named');
  if (h.indexOf('51.10.0.0/15') < 0) throw new Error('the announced prefix should be shown');
  if (h.indexOf('RIPENCC') < 0) throw new Error('the registry should be shown');
  if (h.indexOf('Equinix LA1') < 0) throw new Error('published buildings should be listed');
  if (h.indexOf('600 W 7th St') < 0) throw new Error('a building needs its street address');
  if (h.indexOf('head office, not this router') < 0)
    throw new Error('a registrant address must not be passed off as the router\'s location');
  if (h.indexOf('does not publish which rack') < 0)
    throw new Error('a building list must say what it does not prove');
  if (h.indexOf('Who runs it') < 0) throw new Error('registry detail needs its own heading');
  if (h.indexOf('Site, read from the router name') < 0)
    throw new Error('an inference from a hostname must be labelled as one');
  // The correction has to be visible and auditable, not silent.
  if (h.indexOf('class="corrected"') < 0) throw new Error('a corrected placement should be drawn');
  if (h.indexOf('class="ghost"') < 0) throw new Error('the abandoned position should be marked');
  if (h.indexOf('The database said') < 0) throw new Error('the card must say what it overruled');
  if (h.indexOf('London, England, GB') < 0) throw new Error('the overruled answer must be quoted');
  if (h.indexOf('the router\u2019s own name') < 0) throw new Error('the placement source should be named');
  // The map is the page. Everything else is a panel on top of it, adopted by
  // the panel manager by name, so the content is in the document at once.
  if (h.indexOf('class="mapcanvas"') < 0) throw new Error('the map should have the whole view as its canvas');
  if (h.indexOf('data-panel="hop"') < 0) throw new Error('there should be a panel for hop detail');
  var canvasAt = h.indexOf('class="mapcanvas"'), svgAt = h.indexOf('class="pathmap"'), panelAt = h.indexOf('data-panel="hop"');
  if (!(canvasAt < svgAt && svgAt < panelAt)) throw new Error('the panels should follow the map inside the canvas');
  if (h.indexOf('class="hpbody"') < 0) throw new Error('the panel needs its own scrolling body');
  // Every panel is dragged by its title and folds to it.
  if ((h.match(/class="fsph"/g) || []).length < 3) throw new Error('each panel needs a title bar to drag by');
  if (h.indexOf('class="fspfold"') < 0 || h.indexOf('aria-expanded') < 0) throw new Error('a fold control has to say whether it is open');
  if (h.indexOf('id="panels-menu"') < 0) throw new Error('closed panels need a way back');
  // None of the map's marks are self-evident, so there has to be a key, on the map.
  if (h.indexOf('data-panel="key"') < 0 || h.indexOf('class="legend"') < 0) throw new Error('the map needs a key panel');
  var lgd = h.indexOf('data-panel="key"'), svgEnd = h.indexOf('</svg>');
  if (!(canvasAt < svgEnd && svgEnd < lgd)) throw new Error('the key should be inside the canvas, over the map');
  if (h.indexOf('class="lgitems"') < 0) throw new Error('the key needs a body to fold');
  // The tables live in the data drawer, one tab each.
  if (h.indexOf('data-panel="data"') < 0 || h.indexOf('class="datatabs"') < 0) throw new Error('the data drawer needs tabs');
  ['overview', 'sources', 'location', 'physics', 'unplaced', 'destinations', 'route', 'about'].forEach(function (t) {
    if (h.indexOf('data-pane="' + t + '"') < 0) throw new Error('the drawer should have a ' + t + ' tab');
  });
  if (h.indexOf('id="hovercard"') < 0) throw new Error('hovering a hop should answer at the pointer');
  if (h.indexOf('id="z-in"') < 0 || h.indexOf('id="f-reset"') < 0) throw new Error('zoom and home belong on the map');
  ['a leg several destinations share', 'a leg used by one destination', 'submarine cable',
   'the latency rules this placement out'].forEach(function (k) {
    if (h.indexOf(k) < 0) throw new Error('the legend should explain: ' + k);
  });
  // Zooming shrinks the viewBox, which would scale the dots along with the
  // geography and bury the detail the zoom was for. Every circle has to carry
  // the size it was drawn at so the zoom can divide it back down.
  // Scoped to the map: the legend's swatches are circles too, and they must
  // NOT carry data-r, or zooming the map would shrink the key explaining it.
  var mapOnly = h.slice(h.indexOf('class="pathmap"'), h.indexOf('</svg>', h.indexOf('class="pathmap"')));
  var sized = (mapOnly.match(/data-r="/g) || []).length;
  var circles2 = (mapOnly.match(/<circle/g) || []).length;
  if (sized !== circles2) throw new Error('every circle on the map needs data-r, got ' + sized + ' of ' + circles2);
  if (/data-r=/.test(h.slice(h.indexOf('class="legend"')))) throw new Error('legend swatches must not be rescaled by the map zoom');
  if (h.indexOf('data-r="7"') < 0) throw new Error('the ruled-out ring should carry its base radius');
  if (h.indexOf('data-r="2.5"') < 0) throw new Error('the ghost should carry its base radius');
  // Scoped and unscoped facility lists are different claims.
  if (h.indexOf('Buildings this operator occupies in Los Angeles') < 0)
    throw new Error('a scoped building list should name the city it was narrowed to');
  // The device filter must be a picker of devices, not a box for typing an
  // address, and one entry per device however many addresses it holds.
  if (h.indexOf('<select id="f-dev"') < 0) throw new Error('the device filter should be a picker');
  // Choosing a filter applies it. An Apply button leaves a chosen filter
  // sitting there doing nothing while looking as though it is.
  if (h.indexOf('id="f-apply"') >= 0) throw new Error('there should be no Apply button');
  // Clicking a hop narrows the map to the routes through it, which hides most
  // of what was on screen -- so there has to be something saying so, and a
  // way out of it in one click.
  if (h.indexOf('id="mapfilter"') < 0) throw new Error('narrowing the map needs to announce itself');
  if (h.indexOf('id="mapfilter-off"') < 0) throw new Error('the narrowing must be closable');
  // A destination and a router it crossed on the way are different things and
  // must not be drawn alike.
  if (h.indexOf('class="endpoint"') < 0) throw new Error('endpoints need a mark of their own');
  if (h.indexOf('ENDPOINT') < 0) throw new Error('the hover should say it is an endpoint');
  if (h.indexOf('an endpoint: traffic was going here') < 0)
    throw new Error('the legend should explain the endpoint mark');
  // A hop placed by timing is a guess about where, and must not be drawn as a
  // hop that was actually located.
  if (h.indexOf('hop  guessed') < 0 && h.indexOf(' guessed"') < 0)
    throw new Error('a hop placed by timing needs a mark of its own');
  if (h.indexOf('PLACED BY TIMING') < 0) throw new Error('the hover should say it was inferred');
  if (h.indexOf('That is a guess about where, not about whether') < 0)
    throw new Error("the card should say what kind of claim it is");
  if (h.indexOf('answered but unplaceable') < 0)
    throw new Error('the legend should explain the inferred mark');
  if (h.indexOf('Traffic was going here; the hops before it are the way in') < 0)
    throw new Error("the endpoint's card should say what it is");
  // And the inference has to show its working, not just its answer.
  if (h.indexOf('Confidence') < 0) throw new Error('a reading of a name needs a confidence');
  if (h.indexOf('How it was settled') < 0) throw new Error('it should say what decided it');
  var chip = h.slice(h.indexOf('id="mapfilter"'), h.indexOf('id="mapfilter"') + 200);
  if (chip.indexOf('hidden') < 0) throw new Error('the chip should start hidden, before anything is narrowed');
  if (h.indexOf('>Apply<') >= 0) throw new Error('there should be no Apply button');
  if (h.indexOf('MacBookPro') < 0 || h.indexOf('roku-ultra') < 0) throw new Error('devices missing from the picker');
  if (h.indexOf('2 addresses') < 0) throw new Error('a multi-address device should say so');
  if (h.indexOf('every device') < 0) throw new Error('there must be a way back to everything');
  // The origin must be shown, settable, and detectable both ways.
  if (h.indexOf('Your location') < 0) throw new Error('the origin should be declarable on the page');
  if (h.indexOf("Use this browser's location") < 0) throw new Error('browser auto-detect missing');
  if (h.indexOf('Use the public address') < 0) throw new Error('address auto-detect missing');
  if (h.indexOf('Manhattan') < 0) throw new Error('what the public address suggests should be shown');
  // The origin's own public address belongs beside the coordinates: it is how
  // a reader checks the point the whole map is drawn from.
  if (h.indexOf('162.202.41.52') < 0) throw new Error('the public IPv4 address should be shown');
  if (h.indexOf('2600:1700:3ab0:f43f::1') < 0) throw new Error('the public IPv6 address should be shown');
  if (h.indexOf('used for the origin') < 0)
    throw new Error('with more than one address, say which one produced the coordinates');
  // A placement the latency rules out is circled on the map and explained.
  if (h.indexOf('class="ruledout"') < 0) throw new Error('an impossible placement must be marked on the map');
  if (h.indexOf('RULED OUT') < 0) throw new Error('the reason should be in the hover text');
  if (h.indexOf('Ruled out by latency') < 0) throw new Error('impossible placements need a count');
  // Disproved and merely doubted are different claims and get different marks.
  if (h.indexOf('class="doubtful"') < 0) throw new Error('a doubtful placement needs its own mark on the map');
  // A placed hop whose neighbours could not be placed must still be joined to
  // the route, and the join must read as the weaker claim it is.
  if (h.indexOf('gapleg') < 0) throw new Error('a leg across unplaced hops needs its own style');
  if (h.indexOf('through 3 hops with no known position') < 0)
    throw new Error('a bridging leg should say how much it is standing in for');
  if (h.indexOf('the route continues through hops with no known position') < 0)
    throw new Error('the legend should explain the bridging leg');
  if (h.indexOf('Placements too fast for any built route') < 0) throw new Error('doubtful placements need their own table');
  if (h.indexOf('just not provably') < 0) throw new Error('the doubtful table must say what it is not claiming');
  // Each verdict must be shown against the number that produced it. Sharing
  // one column set meant the doubtful table compared a hop to the
  // speed-of-light floor it had comfortably cleared, and called it too fast.
  if (h.indexOf('A built route needs') < 0)
    throw new Error('the doubtful table must compare against what a built route needs');
  if (h.indexOf('Short by') < 0) throw new Error('say how far short it fell');
  if (h.indexOf('Light alone needs') < 0)
    throw new Error('the impossible table should name the bound it used');
  if (h.indexOf('Over floor') >= 0)
    throw new Error('the old shared column measured the wrong thing and should be gone');
  if (h.indexOf('Being slow is never suspicious') < 0)
    throw new Error('the table must say that slowness is not what is being flagged');
  // Both numbers, kept apart: one is a proof, the other an expectation.
  if (h.indexOf('nothing can beat this') < 0) throw new Error('the physical floor should be labelled as a bound');
  if (h.indexOf('A built route needs') < 0) throw new Error('the realistic minimum should be shown beside it');
  if (h.indexOf('too fast for any built route') < 0) throw new Error('the legend should explain the doubtful mark');
  // Between continents the distance is along a cable, not across the map, and
  // the page has to say which measure it used or the arithmetic cannot be
  // checked.
  if (h.indexOf('along Southern Cross NEXT') < 0)
    throw new Error('a cable-measured distance should name its cable');
  // The crossing is drawn along the cable, not ruled straight through water
  // the cable does not go near.
  if (h.indexOf('drawn along Southern Cross NEXT') < 0)
    throw new Error('a sea crossing should say which cable it follows');
  var crossing = h.slice(h.indexOf('Southern Cross NEXT') - 1400, h.indexOf('Southern Cross NEXT'));
  var dAttr = crossing.lastIndexOf(' d="');
  var path = crossing.slice(dAttr + 4, crossing.indexOf('"', dAttr + 4));
  if ((path.match(/L/g) || []).length < 3)
    throw new Error('a cable route needs its bends, got: ' + path);
  // Every step must be a short one: a point that snapped back across the map
  // would leave a segment most of a world wide.
  var xs = path.replace('M','').split(/[ L]+/).map(function(p){ return parseFloat(p.split(',')[0]); });
  for (var q = 1; q < xs.length; q++) {
    if (Math.abs(xs[q] - xs[q-1]) > 360)
      throw new Error('a run over the antimeridian snapped back across the map: ' + xs.join(' '));
  }
  if (h.indexOf('straight line') < 0)
    throw new Error('a distance not measured along a cable should say so');
  if (h.indexOf('TOO FAST: ') < 0) throw new Error('hover text should distinguish doubtful from ruled out');
  // The counts must not be conflated.
  if ((h.match(/class="ruledout"/g) || []).length === (h.match(/class="doubtful"/g) || []).length &&
      h.indexOf('class="ruledout"') < 0) throw new Error('the two categories collapsed into one');
  // Cables are drawn behind the routes, and a run crossing the antimeridian
  // must break rather than stripe straight across the map.
  // Land, so the thing reads as a map rather than a grid with dots on it.
  if (h.indexOf('class="land"') < 0) throw new Error('the map has no land on it');
  if (!FS.landPath || FS.landPath.length < 10000) throw new Error('land outlines look truncated');
  if (h.indexOf('Natural Earth') < 0) throw new Error('the land source should be credited');
  // The notes are kept, but folded: read once, then in the way.
  if (h.indexOf('<details class="maphelp"') < 0) throw new Error('the map notes should fold');
  if (h.indexOf('About this map') < 0) throw new Error('the fold needs a label saying what is inside');
  var det = h.slice(h.indexOf('<details class="maphelp"'), h.indexOf('</details>'));
  if (det.indexOf(' open') >= 0) throw new Error('the notes should start folded');
  if (det.indexOf('Natural Earth') < 0) throw new Error('folding must keep the credit, not drop it');
  if (mapOnly.indexOf('class="cable"') < 0) throw new Error('cables are not drawn');
  if ((mapOnly.match(/class="cable"/g) || []).length !== 2) throw new Error('want one path per cable run');
  var pac = mapOnly.slice(mapOnly.indexOf('class="cable"', mapOnly.indexOf('class="cable"') + 1));
  if ((pac.slice(0, 200).match(/M/g) || []).length < 2) throw new Error('a run wrapping the antimeridian must break into two subpaths');
  if (h.indexOf('TeleGeography') < 0) throw new Error('the source should be credited on the page');
  if (h.indexOf('could have crossed') < 0) throw new Error('candidate cables should appear in the hover text');
  if (h.indexOf('Southern Cross NEXT') < 0) throw new Error('the candidate name is missing');
  print('Map page renders routes, cables, shared legs, unplaced hops, devices, the origin with both detectors, and placements the physics rules out');

  // With a route chosen, the page must show it as a trail that starts inside
  // the network and ends at the address that was reached.
  var el2 = mkEl();
  FS.pages.paths.render(el2, { params:{ dst:'1.1.1.1' } }).then(function(){
    var t = el2.innerHTML;
    if (t.indexOf('class="trail"') < 0) throw new Error('a chosen route should be drawn as a trail');
    // The route has a panel of its own on the canvas, ahead of the hop panel,
    // and the long trail lives in the data drawer's Route tab.
    var rp = t.indexOf('data-panel="route"'), pan = t.indexOf('data-panel="hop"'), tb = t.indexOf('class="trailbox"');
    if (!(rp >= 0 && rp < pan)) throw new Error('the route panel should come before the detail panel');
    if (!(tb > 0 && t.indexOf('data-pane="route"') < tb)) throw new Error('the trail should sit in the drawer\'s Route tab');
    // It begins inside, not at the first router that answered.
    if (t.indexOf('MacBookPro') < 0) throw new Error('the trail must start with the device on this network');
    // And the map has to show where that is. The first hops are private
    // addresses nothing can place, so without the origin the route appears to
    // start at whichever carrier router answered first.
    if (t.indexOf('class="home"') < 0) throw new Error('the origin should be drawn on the map');
    if (t.indexOf('You are here') < 0) throw new Error('the origin marker should say what it is');
    if (t.indexOf('class="leg local"') < 0) throw new Error('the route should reach the origin');
    if (t.indexOf('data-crumb="__origin"') < 0) throw new Error('the inside step should travel to the origin');
    if (t.indexOf('192.168.1.119') < 0) throw new Error('the internal address should be the first step');
    var insideAt = t.indexOf('MacBookPro'), gwAt = t.indexOf('192.168.1.254');
    if (!(insideAt >= 0 && gwAt > insideAt)) throw new Error('the internal address must come before the gateway');
    // Every link in between, in order, ending at the endpoint.
    if (t.indexOf('tpkaks') < 0) throw new Error('intermediate hops belong in the trail');
    if (t.indexOf('endpoint') < 0) throw new Error('the last step should be marked as the endpoint');
    var endAt = t.lastIndexOf('1.1.1.1');
    if (!(endAt > gwAt)) throw new Error('the endpoint must come last');
    // A hop that never answered still carried the traffic and keeps its place.
    if (t.indexOf('no answer') < 0) throw new Error('a silent hop should still occupy its step');
    // And picking it must say something. An empty panel reads as a fault
    // rather than as the answer it is.
    if (t.indexOf('data-for="s3"') < 0) throw new Error('a silent hop needs a card of its own');
    if (t.indexOf('Nothing replied at this position') < 0)
      throw new Error("the silent hop's card should say what silence means");
    if (t.indexOf('data-for="__origin"') < 0) throw new Error('the origin needs a card too');
    if (t.indexOf('Where every route on this map starts') < 0)
      throw new Error("the origin's card should say what it is");
    if (t.indexOf('crumb silent') < 0) throw new Error('a silent step should be marked as such');
    // An impossible placement stays flagged inside the trail.
    if (t.indexOf('bad') < 0) throw new Error('a ruled-out hop should be flagged in the trail');
    // Steps are tied to the map, and the rest of the map steps back.
    if (t.indexOf('data-crumb="h2"') < 0) throw new Error('steps must be addressable to light up their dot');
    if (t.indexOf('onroute') < 0) throw new Error('the chosen route should be lifted out on the map');
    if (t.indexOf('offroute') < 0) throw new Error('other routes should be dimmed, not removed');
    if (t.indexOf('Show every route') < 0) throw new Error('there must be a way back to all routes');
    // Each leg of the chosen route says which hop it arrives at and what it
    // cost; the milliseconds alone left a reader counting dots.
    var ms = t.match(/class="legms"[^>]*>#(\d+) \u00b7 ([\d.]+) ms</);
    if (!ms) throw new Error('legs of a chosen route should be labelled "#hop · N ms"');
    // Direction and the whole route, on the map itself.
    if (t.indexOf('class="arrow onroute"') < 0) throw new Error('the chosen route should carry direction arrows');
    if (t.indexOf('data-layer="arrows"') < 0) throw new Error('arrows should be a switch in the key');
    if (t.indexOf('class="rbrows"') < 0) throw new Error('the route should be tabled on the map');
    if (t.indexOf('id="mapfilter-next"') < 0) throw new Error('the chip should be able to offer the next route through a hop');
    // Who and what: the devices behind the route and their services.
    if (t.indexOf('Who and what') < 0) throw new Error('the trail should say who was talking');
    if (t.indexOf('QUIC \u00b7 one.one.one.one \u00b7 udp/443') < 0) throw new Error('services should read app · name · proto/port');
    // Both devices, in the trail's block and again in brief on the endpoint's card.
    if ((t.match(/class="talker"/g) || []).length < 2 || t.indexOf('pihole') < 0) throw new Error('both devices should be listed');
    if (t.indexOf('device=192.168.1.53') < 0) throw new Error('a device should link to the map narrowed to it');
    var rbRows = (t.match(/class="rb[ "]/g) || []).length;
    if (rbRows !== 5) throw new Error('route table should list inside + 4 hops, got ' + rbRows);
    if (!/class="rb[^"]*endpoint"/.test(t) || t.indexOf('class="rb inside"') < 0) throw new Error('route table should mark its ends');
    // The number is this route's step, not the step of whichever route first
    // defined the shared node: 1.1.1.1 is hop 4 on the map's node and hop 9
    // on this route.
    var all = t.match(/class="legms"[^>]*>#(\d+) \u00b7/g) || [];
    if (all.some(function(x){ return /#4 /.test(x); }) || !all.some(function(x){ return /#9 /.test(x); }))
      throw new Error('leg labels should use the chosen route\'s hop numbers: ' + all.join(' '));
    print('Map page renders the chosen route as a trail from the inside address to the endpoint');
  }).catch(fail);
}).catch(fail);
if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;

// A learned correction is shown as such, and a set-aside database placement
// says why the hop is not drawn.
(function(){
  var el3 = mkEl();
  FS.pages.paths.render(el3, { params: {} }).then(function(){
  var h = el3.innerHTML;
  ['a learned correction', 'Learned from', 'ae10.r02.rio01.icn', 'every address of the prefix now follows it',
   'registrant&#39;s address for AS20940', 'not believed', '3 prefixes placed by their own routers', '1 registrant addresses set aside'
  ].forEach(function(t){ if (h.indexOf(t) < 0 && h.indexOf(t.replace('&#39;', "'")) < 0) throw new Error('corrections: missing ' + t); });
  print('learned corrections shown OK');
  });
})();
if (typeof drainMicrotasks === 'function') drainMicrotasks();

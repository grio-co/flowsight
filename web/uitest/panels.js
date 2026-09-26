// The panel manager's geometry, without a browser: where a saved state
// lands, how a dropped panel snaps, and that nothing leaves the canvas.
var window = this; window.addEventListener = function () {};
var document = { createElement: function () { return {}; } };
var localStorage = { getItem: function () { return null; }, setItem: function () {}, removeItem: function () {} };
load('web/static/lib.js');
load('web/static/panels.js');
var P = FS.panels;
if (!P || !P.place || !P.snap) throw new Error('FS.panels is not defined');

// A right-anchored panel stays on the right whatever the width.
var s = P.normalise({ ax: 'r', ay: 't', x: 10, y: 52, w: 360, fill: true });
var a = P.place(s, 1200, 800), b = P.place(s, 1600, 900);
if (a.left !== 1200 - 10 - 360 || b.left !== 1600 - 10 - 360) throw new Error('right anchor drifted: ' + a.left + ' ' + b.left);
if (a.height !== 800 - 52 - 8 || b.height !== 900 - 52 - 8) throw new Error('a fill panel should reach the bottom margin');
// A panel remembered on a wide screen is still reachable on a narrow one.
var c = P.place(P.normalise({ ax: 'l', ay: 't', x: 1500, y: 700, w: 400, h: 300 }), 800, 600);
if (c.left + c.width > 800 || c.top + c.height > 600 || c.left < 0 || c.top < 0) throw new Error('panel left the canvas: ' + JSON.stringify(c));
// Dropped near the bottom-right corner it docks there; dropped mid-canvas it floats.
var d = P.snap(s, 1200 - 10 - 360 - 5, 800 - 300 - 4, 1200, 800, 360, 300);
if (d.ax !== 'r' || d.ay !== 'b' || d.x !== 8 || d.y !== 8) throw new Error('should have docked bottom-right: ' + JSON.stringify(d));
var e = P.snap(s, 300, 200, 1200, 800, 360, 300);
if (e.ax !== 'l' || e.ay !== 't' || e.x !== 300 || e.y !== 200) throw new Error('should float where dropped: ' + JSON.stringify(e));
// Homes win when nothing is saved; a saved field wins over its home.
var arr = P.arrangement('t', { hop: { ax: 'r', w: 360 }, key: { folded: true } });
if (arr.hop.ax !== 'r' || arr.hop.w !== 360 || arr.key.folded !== true) throw new Error('homes not applied');
if (arr.hop.w < 180 || arr.key.h < 80) throw new Error('minimum sizes not applied');
print('FS.panels places, snaps and clamps OK');

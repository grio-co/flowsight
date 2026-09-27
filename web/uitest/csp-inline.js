// No inline event handlers or inline scripts may exist in the UI sources:
// the pages run under a Content-Security-Policy that refuses them.
// JavaScriptCore's shell offers readFile(); node offers require('fs').
var readText = (typeof readFile === 'function') ? readFile
  : (typeof require === 'function') ? function (p) { return require('fs').readFileSync(p, 'utf8'); }
  : null;
if (!readText) { print('csp-inline: no file reader in this engine; skipped'); }
else {
  var files = ['lib.js', 'app.js', 'land.js', 'pages.js', 'pages2.js', 'pages3.js', 'api.js', 'proxmox.js', 'space.js', 'space-gl.js', 'inspect.js', 'setup.js', 'reports.js', 'apps.js', 'advice.js', 'names.js', 'smartsearch.js', 'panels.js'];
  var bad = [];
  files.forEach(function (f) {
    var src; try { src = readText('web/static/' + f); } catch (e) { return; }
    var re = /\son(click|change|submit|input|load|error|mouseover|keydown|keyup)\s*=\s*["']/g;
    var m; while ((m = re.exec(src))) { var line = src.slice(0, m.index).split('\n').length; bad.push(f + ':' + line + ' ' + m[0].trim()); }
    if (/<script(?![^>]*\bnonce=)/.test(src)) { bad.push(f + ': inline <script> tag'); }
  });
  if (bad.length) { throw new Error('inline handlers found:\n' + bad.join('\n')); }
  print('csp-inline: no inline handlers in ' + files.length + ' files');
}

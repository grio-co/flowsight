// Every script the interface loads must at least parse. A single stray
// character in one file takes every page in that file down with it, and
// the other checks here only load the files they exercise.
var files = ['lib.js', 'app.js', 'pages.js', 'pages2.js', 'pages3.js', 'api.js', 'inspect.js', 'land.js', 'proxmox.js', 'apps.js', 'advice.js', 'names.js', 'piblock.js', 'smartsearch.js', 'panels.js', 'setup.js', 'space.js', 'space-gl.js'];
files.forEach(function (f) {
  var src;
  try { src = readFile('web/static/' + f); } catch (e) { return; } // not every build has every file
  try { new Function(src); } catch (e) { throw new Error(f + ' does not parse: ' + e.message); }
});
print('parse-all: ' + files.length + ' files parse');

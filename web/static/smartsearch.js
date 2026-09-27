// SmartSearch: the box at the top of every page.
//
// Typing does two things at once. The page in view filters down to what
// matches, live: every table keeps only its matching rows (all of them, not
// just the rows on screen), every list keeps its matching items, and a panel
// with nothing matching folds away. A panel whose title matches, or a page
// that is itself about the thing searched for (the device page of the
// iPhone, when searching "iphone"), is shown whole. Meanwhile the dropdown
// answers "where else is this?": this page's matching panels first, then the
// devices, names, domains, applications, findings, policies, settings and
// pages across FlowSight, each with links to every page showing the same
// thing. The search stays on as you follow those links, so the next page
// opens already narrowed; Esc or Clear ends it.
(function () {
  const esc = (s) => FS.esc(s);
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const S = FS.smart = { q: '', terms: [], tables: new Map(), panels: [] };
  const ITEMS = '.barrow, .advice, .attn-row, .ph-row, li, .nm-addr, .hpitem';
  const KEY = 'fs.smart.q';

  S.active = () => S.terms.length > 0;
  S.match = (text) => { const t = String(text || '').toLowerCase(); return S.terms.every(x => t.includes(x)); };
  const strip = (html) => String(html == null ? '' : html).replace(/<[^>]*>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");

  // A table row's text: what its cells show, plus its raw values (an address
  // or hardware address a cell only links to still counts).
  const rowText = new WeakMap();
  S.rowText = (r, cols) => {
    if (r && typeof r === 'object' && rowText.has(r)) return rowText.get(r);
    let t = '';
    try { t = cols.map(c => c.f ? strip(c.f(r)) : (r[c.k] == null ? '' : r[c.k])).join(' '); } catch (e) { t = ''; }
    if (r && typeof r === 'object') t += ' ' + Object.values(r).filter(v => v != null && typeof v !== 'object').join(' ');
    if (r && typeof r === 'object') rowText.set(r, t);
    return t;
  };
  S.filterRows = (rows, cols) => rows.filter(r => S.match(S.rowText(r, cols)));

  // Tables built by FS.table register here, so typing re-filters their full
  // data without asking the server again.
  S.refilterTables = () => {
    S.tables.forEach((T, id) => {
      const wrap = document.getElementById(id);
      if (!wrap) { S.tables.delete(id); return; }
      T.refilter();
    });
  };

  const textOf = (el) => (el.textContent || '') + ' ' + $$('a[href],[title]', el).map(a => (a.getAttribute('href') || '') + ' ' + (a.getAttribute('title') || '')).join(' ');

  function unmark(root) {
    $$('mark.ss-hl', root).forEach(m => { const p = m.parentNode; if (!p) return; p.replaceChild(document.createTextNode(m.textContent), m); p.normalize(); });
  }
  function mark(root) {
    if (!S.active() || !window.NodeFilter) return;
    const terms = S.terms.filter(t => t.length >= 2).map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    if (!terms.length) return;
    const re = new RegExp('(' + terms.join('|') + ')', 'ig');
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: (n) => {
        const p = n.parentNode;
        if (!p || /^(SCRIPT|STYLE|TEXTAREA|INPUT|OPTION|SELECT|MARK)$/.test(p.nodeName) || p.closest('.ss-miss, .ss-hide, svg, .ss-banner')) return NodeFilter.FILTER_REJECT;
        re.lastIndex = 0;
        return re.test(n.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
      }
    });
    const nodes = []; let n; while ((n = walker.nextNode()) && nodes.length < 600) nodes.push(n);
    nodes.forEach(node => {
      const frag = document.createDocumentFragment();
      node.nodeValue.split(re).forEach((part, i) => {
        if (!part) return;
        if (i % 2) { const m = document.createElement('mark'); m.className = 'ss-hl'; m.textContent = part; frag.appendChild(m); }
        else frag.appendChild(document.createTextNode(part));
      });
      node.parentNode.replaceChild(frag, node);
    });
  }

  // Filters the panels of the page in view.
  S.applyDOM = (view) => {
    view = view || $('#view'); if (!view) return;
    $$('.ss-hide, .ss-miss', view).forEach(e => e.classList.remove('ss-hide', 'ss-miss'));
    unmark(view);
    const old = $('.ss-banner', view); if (old) old.remove();
    S.panels = [];
    if (!S.active() || view.classList.contains('fullbleed')) return;
    const title = ($('#title') || {}).textContent || '';
    const { arg } = FS.parseHash();
    const pageAbout = S.match(title + ' ' + (arg || ''));
    const cards = $$('.card', view).filter(c => !c.parentNode.closest('.card'));
    let hidden = 0, total = 0;
    cards.forEach(card => {
      const h = $(':scope > h3', card);
      // The title alone: not the panel's side note or its drag handle.
      const head = h ? Array.from(h.childNodes).filter(n => !(n.classList && (n.classList.contains('right') || n.classList.contains('grip')))).map(n => n.textContent).join('').replace(/[⠇☰⋮]/g, '').trim() : '';
      let n = 0, whole = false;
      if (pageAbout || (head && S.match(head))) { whole = true; n = 1; }
      else {
        const tables = $$('.tablewrap[data-ss-count]', card);
        tables.forEach(t => { n += Number(t.dataset.ssCount) || 0; });
        const items = $$(ITEMS, card).filter(i => !i.closest('table') && !i.parentNode.closest(ITEMS));
        items.forEach(i => { const ok = S.match(textOf(i)); i.classList.toggle('ss-miss', !ok); if (ok) n++; });
        if (!tables.length && !items.length) n = S.match(textOf(card)) ? 1 : 0;
      }
      card.classList.toggle('ss-hide', n === 0);
      if (n === 0) hidden++; else { total += whole ? 0 : n; S.panels.push({ card, title: head || 'Panel', n, whole }); }
    });
    // A wrapper left holding only hidden panels goes too.
    cards.filter(c => c.classList.contains('ss-hide')).forEach(c => {
      let p = c.parentNode;
      while (p && p !== view && !Array.from(p.children).some(x => !x.classList.contains('ss-hide') && x.offsetParent !== undefined && !x.classList.contains('ss-banner'))) { p.classList.add('ss-hide'); p = p.parentNode; }
    });
    mark(view);
    const b = document.createElement('div'); b.className = 'ss-banner';
    const q = esc(S.q);
    b.innerHTML = pageAbout
      ? `<span>This page is about “${q}”: showing everything, matches highlighted.</span><button class="btn small" data-ss-clear>Clear search</button>`
      : `<span>Showing only what matches “${q}”: <b>${S.panels.length}</b> panel${S.panels.length === 1 ? '' : 's'}${total ? `, ${FS.num(total)} matching row${total === 1 ? '' : 's'}` : ''}${hidden ? ` · ${hidden} hidden` : ''}.</span><button class="btn small" data-ss-clear>Clear search</button>`;
    view.insertBefore(b, view.firstChild);
    $('[data-ss-clear]', b).onclick = () => S.set('', true);
  };

  S.afterRender = (view) => { if (S.active()) S.applyDOM(view); drawDrop(); };

  // ------------------------------------------------------------ the box
  let input, drop, seq = 0, global = null, sel = -1, tPage = null, tGlobal = null;

  S.set = (q, clearBox) => {
    S.q = String(q || '').trim();
    S.terms = S.q.toLowerCase().split(/\s+/).filter(Boolean);
    try { if (S.q) sessionStorage.setItem(KEY, S.q); else sessionStorage.removeItem(KEY); } catch (e) { /* private window */ }
    if (clearBox && input) { input.value = S.q; }
    if (input) input.classList.toggle('ss-on', S.active());
    S.refilterTables();
    S.applyDOM();
    if (!S.active()) { global = null; hideDrop(); }
  };

  const fetchGlobal = () => {
    const q = S.q; const my = ++seq;
    if (q.length < 2) { global = null; drawDrop(); return; }
    global = { loading: true, groups: [] }; drawDrop();
    FS.get('/api/search?q=' + encodeURIComponent(q)).then(r => { if (my !== seq) return; global = r && !r.error ? r : { groups: [], error: r && r.error }; drawDrop(); });
  };

  function hideDrop() { if (drop) drop.hidden = true; sel = -1; }
  function drawDrop() {
    if (!drop || !input) return;
    if (!S.active() || document.activeElement !== input) { drop.hidden = true; return; }
    const here = S.panels.filter(p => !p.whole).slice(0, 8);
    const pageBit = here.length
      ? here.map((p, i) => `<a class="ss-item ss-panel" data-panel="${i}" href="#"><b>${esc(p.title)}</b><span class="muted small">${FS.num(p.n)} match${p.n === 1 ? '' : 'es'}</span></a>`).join('')
      : `<div class="muted small ss-note">${S.panels.length ? 'This page is about it: everything is shown.' : 'Nothing on this page matches.'}</div>`;
    let globalBit = '';
    if (global && global.loading && !(global.groups || []).length) globalBit = '<div class="muted small ss-note">Searching FlowSight…</div>';
    else if (global && (global.groups || []).length) globalBit = global.groups.map(g => `<div class="ss-group">${esc(g.title)}</div>` + g.results.map(r => `<div class="ss-result"><a class="ss-item" href="${esc(r.href)}"><b>${esc(r.title)}</b>${r.sub ? `<span class="muted small">${esc(r.sub)}</span>` : ''}</a>${(r.links || []).length > 1 ? `<div class="ss-links">${r.links.map(l => `<a href="${esc(l.href)}">${esc(l.label)}</a>`).join('')}</div>` : ''}</div>`).join('')).join('');
    else if (global && !global.loading) globalBit = `<div class="muted small ss-note">${global.error ? esc(global.error) : 'Nothing else in FlowSight matches.'}</div>`;
    drop.innerHTML = `<div class="ss-group">On this page</div>${pageBit}${S.q.length >= 2 ? `<div class="ss-sep"></div>${globalBit}` : ''}
      <div class="ss-foot muted small"><kbd>↑</kbd><kbd>↓</kbd> move · <kbd>Enter</kbd> open · <kbd>Esc</kbd> close, again to clear · <kbd>/</kbd> search</div>`;
    drop.hidden = false;
    $$('.ss-panel', drop).forEach(a => a.onmousedown = (e) => {
      e.preventDefault(); const p = here[Number(a.dataset.panel)]; if (!p) return;
      p.card.scrollIntoView({ behavior: 'smooth', block: 'start' }); p.card.classList.add('ss-flash'); setTimeout(() => p.card.classList.remove('ss-flash'), 1400); hideDrop();
    });
    $$('a[href^="#"]:not(.ss-panel)', drop).forEach(a => a.onmousedown = (e) => { e.preventDefault(); hideDrop(); input.blur(); FS.go(a.getAttribute('href')); });
    highlightSel();
  }
  function highlightSel() {
    const items = $$('.ss-item', drop);
    items.forEach((a, i) => a.classList.toggle('on', i === sel));
    if (items[sel]) items[sel].scrollIntoView({ block: 'nearest' });
  }

  S.init = () => {
    input = document.getElementById('search'); if (!input) return;
    input.placeholder = 'Search this page and FlowSight…  /';
    input.setAttribute('aria-label', 'SmartSearch: filter this page and search FlowSight');
    drop = document.createElement('div'); drop.id = 'ss-drop'; drop.hidden = true; drop.setAttribute('role', 'listbox');
    input.parentNode.insertBefore(drop, input.nextSibling);
    let saved = ''; try { saved = sessionStorage.getItem(KEY) || ''; } catch (e) { /* none */ }
    if (saved) { input.value = saved; S.q = saved; S.terms = saved.toLowerCase().split(/\s+/).filter(Boolean); input.classList.add('ss-on'); }
    input.addEventListener('input', () => {
      sel = -1;
      clearTimeout(tPage); tPage = setTimeout(() => { S.set(input.value); drawDrop(); }, 120);
      clearTimeout(tGlobal); tGlobal = setTimeout(fetchGlobal, 260);
    });
    input.addEventListener('focus', () => { if (S.active()) { if (!global) fetchGlobal(); drawDrop(); } });
    input.addEventListener('blur', () => setTimeout(hideDrop, 150));
    input.addEventListener('keydown', (e) => {
      const items = drop.hidden ? [] : $$('.ss-item', drop);
      if (e.key === 'ArrowDown' && items.length) { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); highlightSel(); return; }
      if (e.key === 'ArrowUp' && items.length) { e.preventDefault(); sel = Math.max(-1, sel - 1); highlightSel(); return; }
      if (e.key === 'Escape') {
        e.preventDefault();
        if (!drop.hidden) { hideDrop(); return; }
        input.value = ''; S.set(''); input.blur(); return;
      }
      if (e.key !== 'Enter') return;
      e.preventDefault();
      clearTimeout(tPage); S.set(input.value);
      if (items[sel]) { items[sel].dispatchEvent(new MouseEvent('mousedown', { bubbles: true })); return; }
      const q = S.q;
      if (/^\d+\.\d+\.\d+\.\d+$/.test(q) || (q.includes(':') && /^[0-9a-f:]+$/i.test(q) && !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(q))) { hideDrop(); input.blur(); FS.go('#host/' + encodeURIComponent(q)); return; }
      hideDrop();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return;
      const t = e.target; if (t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.nodeName) || t.isContentEditable)) return;
      e.preventDefault(); input.focus(); input.select();
    });
  };
})();

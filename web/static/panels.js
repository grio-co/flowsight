// Floating panels over a canvas.
//
// A page whose content is one big drawing (the map) keeps its furniture in
// panels that sit on top of it. Each panel is dragged by its title, folds to
// its title, closes, and comes back from a menu; a panel let go near an
// edge or corner snaps to it and stays anchored there when the window
// changes size. The arrangement is remembered in this browser, per page,
// and one action puts everything back where it started.
//
// The geometry is kept in plain functions (place, snap, clamp) so it can be
// tested without a browser: the DOM part only reads pointer events and
// writes left/top/width/height.
(function () {
  'use strict';
  const FS = window.FS = window.FS || {};
  const P = {};
  const MARGIN = 8;      // gap a docked panel keeps from the canvas edge
  const SNAP = 18;       // how near an edge counts as "meant to dock"
  const MIN_W = 180, MIN_H = 80;

  const store = (k, v) => { try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, JSON.stringify(v)); } catch (e) { } };
  const load = (k) => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : null; } catch (e) { return null; } };

  // A panel's state. x and y are offsets from the anchored side (ax: 'l' or
  // 'r', ay: 't' or 'b'), so a panel docked on the right stays on the right
  // when the canvas widens. fill: true means "as tall as the canvas allows
  // from where I sit", the shape a docked inspector wants until the reader
  // resizes it by hand.
  P.normalise = (s, d) => {
    const o = Object.assign({ ax: 'l', ay: 't', x: MARGIN, y: MARGIN, w: 300, h: 240, fill: false, gap: 0, wfill: 0, folded: false, hidden: false }, d || {}, s || {});
    o.w = Math.max(MIN_W, +o.w || MIN_W); o.h = Math.max(MIN_H, +o.h || MIN_H);
    o.x = Math.max(0, +o.x || 0); o.y = Math.max(0, +o.y || 0);
    return o;
  };

  // Where a state lands on a canvas of a given size, as left/top/width/height
  // in pixels, kept inside the canvas whatever the saved numbers say (a panel
  // remembered on a wide screen must still be reachable on a narrow one).
  // foldedH is how tall the panel is when folded to its title, so a folded
  // panel anchored to the bottom sits on the bottom rather than where its
  // open height would have put its top.
  // top0 is the height of whatever sits along the top of the canvas (the
  // toolbar); offsets from the top count from below it, so a panel homed
  // just under a one-row toolbar is still just under it when the toolbar
  // wraps to two rows on a narrow window.
  P.place = (s, W, H, foldedH, top0) => {
    top0 = top0 || 0;
    // wfill: the panel runs from its left offset to this many pixels short
    // of the right edge (room for a panel docked there), until resized.
    let w = s.wfill > 0 && s.ax !== 'r' ? Math.max(MIN_W, W - s.x - s.wfill) : Math.min(s.w, Math.max(MIN_W, W - 2 * MARGIN));
    let h = s.fill ? Math.max(MIN_H, H - s.y - MARGIN - (s.gap || 0)) : Math.min(s.h, Math.max(MIN_H, H - 2 * MARGIN));
    if (s.folded && foldedH > 0) h = foldedH;
    if (s.fill) h = Math.max(MIN_H, h - top0);
    let left = s.ax === 'r' ? W - s.x - w : s.x;
    let top = s.ay === 'b' ? H - s.y - h : s.y + top0;
    left = Math.max(0, Math.min(left, W - w));
    top = Math.max(0, Math.min(top, H - Math.min(h, H)));
    return { left, top, width: w, height: h };
  };

  // After a drag: a panel within SNAP of an edge is anchored to it at the
  // margin; otherwise it keeps a top-left offset. Anchors are decided per
  // axis, so a corner takes both.
  P.snap = (s, left, top, W, H, w, h, top0) => {
    top0 = top0 || 0;
    const n = Object.assign({}, s);
    const rightGap = W - (left + w), bottomGap = H - (top + h);
    if (left <= SNAP) { n.ax = 'l'; n.x = MARGIN; }
    else if (rightGap <= SNAP) { n.ax = 'r'; n.x = MARGIN; }
    else { n.ax = 'l'; n.x = Math.round(left); }
    if (top - top0 <= SNAP) { n.ay = 't'; n.y = MARGIN; }
    else if (bottomGap <= SNAP) { n.ay = 'b'; n.y = MARGIN; }
    else { n.ay = 't'; n.y = Math.round(top - top0); }
    return n;
  };

  // The whole saved arrangement for a page, merged over the built-in homes.
  P.arrangement = (key, homes) => {
    const saved = load('fs.panels.' + key) || {};
    const out = {};
    Object.keys(homes).forEach(id => { out[id] = P.normalise(saved[id], homes[id]); });
    return out;
  };

  // Mount panels into root. Each panel: { id, title, html, home:{...}, foldedTitle? }.
  // Returns a handle with reset(), show(id), menu().
  P.mount = (root, opts) => {
    if (!root || !root.appendChild) return null;
    const key = opts.key || 'page';
    const homes = {}; opts.panels.forEach(p => homes[p.id] = p.home || {});
    const state = P.arrangement(key, homes);
    const els = {};
    let zseq = 10;
    const size = () => {
      const r = root.getBoundingClientRect ? root.getBoundingClientRect() : { width: 1200, height: 800 };
      return [Math.max(320, r.width || 1200), Math.max(240, r.height || 800)];
    };
    const save = () => store('fs.panels.' + key, state);
    const top0 = () => (typeof opts.insetTop === 'function' ? (opts.insetTop() || 0) : (opts.insetTop || 0));
    const layout = (id) => {
      const s = state[id], el = els[id]; if (!el) return;
      el.hidden = !!s.hidden;
      el.classList.toggle('folded', !!s.folded);
      const fb = el.querySelector && el.querySelector('.fspfold');
      if (fb) fb.setAttribute('aria-expanded', s.folded ? 'false' : 'true');
      const [W, H] = size();
      const head = el.querySelector && el.querySelector('.fsph');
      const p = P.place(s, W, H, s.folded ? ((head && head.offsetHeight) || 30) : 0, top0());
      el.style.left = p.left + 'px'; el.style.top = p.top + 'px';
      el.style.width = s.folded ? '' : p.width + 'px';
      el.style.height = s.folded ? '' : p.height + 'px';
    };
    const layoutAll = () => Object.keys(state).forEach(layout);
    const raise = (el) => { el.style.zIndex = String(++zseq); };

    // A panel already in the page (rendered by the page's own template, so
    // its content is in the document from the first paint) is adopted by
    // its data-panel name; one that is not there is built from p.html, or
    // skipped when the page has nothing for it this time (a route panel
    // with no route chosen).
    const present = {};
    opts.panels.forEach(p => {
      let el = null;
      try { el = root.querySelector('.fspanel[data-panel="' + p.id + '"]'); } catch (e) { el = null; }
      if (!el || !el.classList || !el.classList.contains || !el.classList.contains('fspanel')) el = null;
      if (!el) {
        if (!p.html) { delete state[p.id]; return; }
        el = document.createElement('section');
        el.className = 'fspanel';
        el.setAttribute('data-panel', p.id);
        el.setAttribute('tabindex', '0');
        el.setAttribute('aria-label', p.title);
        el.innerHTML = `<header class="fsph"><span class="grip" aria-hidden="true">\u283f</span><span class="fspt">${FS.esc ? FS.esc(p.title) : p.title}</span>`
          + `<span class="fspa"><button type="button" class="fspfold" title="Fold to the title (Esc)" aria-expanded="true">\u2581</button>`
          + `<button type="button" class="fspclose" title="Close; bring it back from Panels" aria-label="Close ${FS.esc ? FS.esc(p.title) : p.title}">\u00d7</button></span></header>`
          + `<div class="fspb">${p.html}</div><i class="fspr" aria-hidden="true"></i>`;
        root.appendChild(el);
      }
      present[p.id] = true;
      els[p.id] = el;
      const s = state[p.id];
      const head = el.querySelector('.fsph');
      const fold = (v) => { s.folded = v == null ? !s.folded : v; layout(p.id); save(); };
      el.addEventListener('pointerdown', () => raise(el));
      const fb = el.querySelector('.fspfold'); if (fb) fb.onclick = (e) => { e.stopPropagation(); fold(); };
      const cb = el.querySelector('.fspclose'); if (cb) cb.onclick = (e) => { e.stopPropagation(); s.hidden = true; layout(p.id); save(); if (opts.onChange) opts.onChange('close', p.id); };
      if (head) {
        head.addEventListener('dblclick', (e) => {
          if (e.target.closest && e.target.closest('button')) return;
          Object.assign(s, P.normalise(null, homes[p.id])); layout(p.id); save();
        });
        // Drag by the title. Pointer capture keeps the drag alive when the
        // pointer outruns the header; the panel moves with the pointer and
        // snaps when released.
        head.addEventListener('pointerdown', (e) => {
          if (e.button !== 0 || (e.target.closest && e.target.closest('button'))) return;
          e.preventDefault();
          const [W, H] = size();
          const start = P.place(s, W, H, 0, top0());
          const ox = e.clientX - start.left, oy = e.clientY - start.top;
          const w = start.width, h = s.folded ? (el.offsetHeight || MIN_H) : start.height;
          el.classList.add('dragging'); raise(el);
          let last = { left: start.left, top: start.top };
          const move = (ev) => {
            last = { left: Math.max(0, Math.min(ev.clientX - ox, W - w)), top: Math.max(0, Math.min(ev.clientY - oy, H - Math.min(h, H))) };
            el.style.left = last.left + 'px'; el.style.top = last.top + 'px';
          };
          const up = () => {
            head.removeEventListener('pointermove', move); head.removeEventListener('pointerup', up); head.removeEventListener('pointercancel', up);
            el.classList.remove('dragging'); el.classList.add('snapping');
            Object.assign(s, P.snap(s, last.left, last.top, W, H, w, h, top0()));
            layout(p.id); save();
            setTimeout(() => el.classList.remove('snapping'), 160);
          };
          try { head.setPointerCapture(e.pointerId); } catch (x) { }
          head.addEventListener('pointermove', move); head.addEventListener('pointerup', up); head.addEventListener('pointercancel', up);
        });
      }
      // Resize from the corner. Resizing a "fill" panel makes its height its own.
      const rz = el.querySelector('.fspr');
      if (rz) rz.addEventListener('pointerdown', (e) => {
        if (e.button !== 0) return;
        e.preventDefault(); e.stopPropagation();
        const [W, H] = size();
        const start = P.place(s, W, H, 0, top0());
        const sx = e.clientX, sy = e.clientY;
        const move = (ev) => {
          s.w = Math.max(MIN_W, Math.min(start.width + (ev.clientX - sx), W - start.left));
          s.h = Math.max(MIN_H, Math.min(start.height + (ev.clientY - sy), H - start.top));
          s.fill = false; s.wfill = 0;
          // A right-anchored panel grows leftwards from its anchor; keep the
          // anchor where it is by not touching x.
          layout(p.id);
        };
        const up = () => { rz.removeEventListener('pointermove', move); rz.removeEventListener('pointerup', up); save(); };
        try { rz.setPointerCapture(e.pointerId); } catch (x) { }
        rz.addEventListener('pointermove', move); rz.addEventListener('pointerup', up);
      });
      // Keyboard: the panel itself takes focus; arrows move it, Esc folds it.
      el.addEventListener('keydown', (e) => {
        if (e.target !== el) return;
        const step = e.shiftKey ? 40 : 10;
        const [W, H] = size();
        const p0 = P.place(s, W, H, 0, top0());
        let left = p0.left, top = p0.top, handled = true;
        if (e.key === 'ArrowLeft') left -= step; else if (e.key === 'ArrowRight') left += step;
        else if (e.key === 'ArrowUp') top -= step; else if (e.key === 'ArrowDown') top += step;
        else if (e.key === 'Escape') { fold(); return; }
        else if (e.key === 'Enter') { fold(); return; }
        else handled = false;
        if (!handled) return;
        e.preventDefault();
        Object.assign(s, P.snap(s, left, top, W, H, p0.width, p0.height, top0())); layout(p.id); save();
      });
    });
    layoutAll();
    if (typeof ResizeObserver === 'function') {
      try { new ResizeObserver(() => layoutAll()).observe(root); } catch (e) { }
    }
    const handle = {
      state, els,
      layout: layoutAll,
      show: (id) => { if (state[id]) { state[id].hidden = false; state[id].folded = false; layout(id); raise(els[id]); save(); } },
      hide: (id) => { if (state[id]) { state[id].hidden = true; layout(id); save(); } },
      fold: (id, v) => { if (state[id]) { state[id].folded = v == null ? !state[id].folded : !!v; layout(id); save(); } },
      reset: () => { Object.keys(state).forEach(id => Object.assign(state[id], P.normalise(null, homes[id]))); store('fs.panels.' + key, null); layoutAll(); },
      // A menu listing every panel, to bring back a closed one or put them all home.
      menu: () => {
        if (!FS.modal) return;
        const rows = opts.panels.filter(p => present[p.id]).map(p => `<label class="fspm"><input type="checkbox" data-id="${p.id}" ${state[p.id].hidden ? '' : 'checked'}> ${FS.esc(p.title)}${state[p.id].folded && !state[p.id].hidden ? ' <span class="muted small">(folded)</span>' : ''}</label>`).join('');
        FS.modal(`<h2>Panels</h2><div class="fspmenu">${rows}</div>
          <div class="actions" style="margin-top:12px"><button type="button" class="btn" data-a="reset">Put every panel back</button><button type="button" class="btn" data-close>Close</button></div>
          <div class="help">Drag a panel by its title. Near an edge it docks and stays there when the window changes. Double-click a title to send that panel home; fold with the small button or Esc; arrow keys move a focused panel.</div>`, (b) => {
          FS.$$('input[data-id]', b).forEach(i => i.onchange = () => { if (i.checked) handle.show(i.dataset.id); else handle.hide(i.dataset.id); });
          const r = FS.$('[data-a="reset"]', b); if (r) r.onclick = () => { handle.reset(); FS.closeModal(); };
        });
      }
    };
    return handle;
  };

  FS.panels = P;
})();

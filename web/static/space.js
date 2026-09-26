/* FlowSight Space: physical space mapping and 3D device placement */
'use strict';

FS.registerPage('space', {
  title: 'Space', refresh: 60,
  async render(el) {
    const { card, kpi, pill, esc, num, table } = FS;
    const layout = await FS.get('/api/space/layout');
    const devices = await FS.get('/api/space/devices');
    const records = await FS.get('/api/space/records');

    if (layout.error) {
      el.innerHTML = FS.err('Failed to load space: ' + layout.error);
      return;
    }

    // Build HTML structure with three panes: Plan, 3D, Palette
    const placed = (devices.devices || []).filter(d => d.placed).length;
    const unplaced = (devices.devices || []).length - placed;

    el.innerHTML = `
      <div class="space-container">
        <div class="space-header">
          <div class="kv">
            <dt>Location</dt>
            <dd>${esc(records.geocode?.address || 'Not set')}</dd>
            <dt>Address</dt>
            <dd>${records.geocode?.lat ? `${num(records.geocode.lat, 3)}, ${num(records.geocode.lon, 3)}` : 'Geocoding...'}</dd>
            <dt>Elevation</dt>
            <dd>${records.elevation_m ? num(records.elevation_m, 1) + ' m' : '—'}</dd>
            <dt>Devices</dt>
            <dd>${num(placed)} placed · ${num(unplaced)} unplaced</dd>
          </div>
        </div>

        <div class="space-content">
          <!-- Tab buttons for mobile -->
          <div class="space-tabs">
            <button class="space-tab-btn active" data-tab="3d">3D Scan</button>
            <button class="space-tab-btn" data-tab="plan">Plan</button>
            <button class="space-tab-btn" data-tab="palette">Devices</button>
          </div>

          <!-- Plan pane (2D) -->
          <div id="space-plan" class="space-pane space-plan">
            <div class="space-toolbar">
              <button id="btn-plan-draw" class="btn-icon" title="Draw rooms (click points, double-click to close)">✏ Draw</button>
              <button id="btn-plan-undo" class="btn-icon" title="Undo last action">↶ Undo</button>
              <button id="btn-plan-redo" class="btn-icon" title="Redo last action">↷ Redo</button>
              <button id="btn-plan-import-osm" class="btn-icon" title="Import building footprint from OSM">🗺 Import OSM</button>
              <button id="btn-plan-set-scale" class="btn-icon" title="Set scale by two points">📏 Scale</button>
              <label>Floor: <select id="space-floor-select" style="margin:0 8px">
                <option value="0">Ground</option>
              </select></label>
              <button id="btn-plan-rename-room" class="btn-icon" title="Rename selected room" style="display:none">✎ Rename</button>
              <button id="btn-plan-delete-room" class="btn-icon" title="Delete selected room" style="display:none">🗑 Delete</button>
              <span id="space-unsaved-indicator" style="margin-left:8px;color:var(--text-muted);font-size:10px"></span>
              <button id="btn-plan-export" class="btn-icon" title="Export layout as JSON" style="margin-left:auto">⬇ Export</button>
            </div>
            <canvas id="space-canvas-plan" class="space-canvas"></canvas>
          </div>

          <!-- 3D pane (WebGL) -->
          <div id="space-3d" class="space-pane space-3d active">
            <div class="space-toolbar">
              <button id="btn-3d-upload-scan" class="btn-icon" title="Upload scan (GLB, OBJ, PLY, RoomPlan JSON)">⬆ Scan</button>
              <button id="btn-3d-level" class="btn-icon" title="Level the scan to floor (click 3 floor points)">📐 Level</button>
              <button id="btn-3d-align" class="btn-icon" title="Align scan to plan (2 pts in 3D → 2 pts on plan)">⚙ Align</button>
              <label>Floor: <select id="space-3d-floor-select" style="margin:0 8px">
                <option value="0">Ground</option>
              </select></label>
              <button id="btn-3d-fullscreen" class="btn-icon" title="Fullscreen">⛶</button>
            </div>
            <canvas id="space-canvas-3d" class="space-canvas"></canvas>
          </div>

          <!-- Palette pane (device list) -->
          <div id="space-palette" class="space-pane space-palette">
            <div class="space-toolbar">
              <input id="space-device-search" type="text" placeholder="Search devices..." class="space-search">
              <label><input id="space-filter-placed" type="checkbox"> Placed</label>
              <label><input id="space-filter-unplaced" type="checkbox" checked> Unplaced</label>
            </div>
            <div id="space-devices-list" class="space-devices-list"></div>
          </div>
        </div>
      </div>

      <style>
        .space-container { display: grid; grid-template-rows: auto 1fr; height: 100vh; overflow: hidden; }
        .space-header { padding: 12px 16px; border-bottom: 1px solid var(--bg-alt); }
        .space-content { display: grid; grid-template-columns: 1fr 1fr 250px; gap: 0; overflow: hidden; }
        .space-pane { display: flex; flex-direction: column; border-right: 1px solid var(--bg-alt); overflow: auto; }
        .space-pane:last-child { border-right: none; }
        .space-toolbar { padding: 8px 12px; border-bottom: 1px solid var(--bg-alt); display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
        .space-canvas { flex: 1; display: block; background: var(--bg-subtle); }
        .btn-icon { padding: 6px 12px; border: 1px solid var(--bg-alt); background: transparent; cursor: pointer; font-size: 12px; white-space: nowrap; }
        .btn-icon:hover { background: var(--bg-alt); }
        .space-search { padding: 6px 8px; border: 1px solid var(--bg-alt); font-size: 12px; flex: 1; min-width: 150px; }
        .space-devices-list { flex: 1; overflow-y: auto; padding: 8px; }
        .space-device-item { padding: 8px; margin-bottom: 4px; background: var(--bg-subtle); border-radius: 4px; cursor: pointer; user-select: none; }
        .space-device-item:hover { background: var(--bg-alt); }
        .space-device-item.placed { opacity: 0.6; }
        .space-device-item-label { font-weight: 500; font-size: 12px; }
        .space-device-item-addr { font-size: 11px; color: var(--text-muted); }

        .space-toast { position: fixed; bottom: 20px; left: 20px; background: rgba(0,0,0,0.9); color: white; padding: 12px 16px; border-radius: 4px; z-index: 1000; font-size: 12px; max-width: 300px; }
        .space-toast.error { background: rgba(200,0,0,0.9); }
        .space-tabs { display: none; padding: 0 12px; border-bottom: 1px solid var(--bg-alt); gap: 0; }
        .space-tab-btn { padding: 8px 12px; border: none; background: transparent; cursor: pointer; font-size: 12px; border-bottom: 2px solid transparent; }
        .space-tab-btn.active { border-bottom-color: var(--accent-base); }

        @media (max-width: 768px) {
          .space-content { grid-template-columns: 1fr; }
          .space-pane { display: none; }
          .space-pane.active { display: flex; }
          .space-pane { border-right: none; border-bottom: none; }
          .space-tabs { display: flex; }
        }
      </style>
    `;

    // Initialize the three panes
    const planCanvas = el.querySelector('#space-canvas-plan');
    const canvas3d = el.querySelector('#space-canvas-3d');
    const devicesList = el.querySelector('#space-devices-list');

    // Plan pane: 2D editor
    initPlanPane(el, planCanvas, layout);

    // 3D pane: WebGL viewer
    init3DPane(el, canvas3d, layout);

    // Upload scan modal
    initUploadScan(el);

    // Palette pane: device list
    initPalettePane(devicesList, devices, layout);

    // Mobile tab switching
    const tabBtns = el.querySelectorAll('.space-tab-btn');
    const panes = el.querySelectorAll('.space-pane');

    tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const tabName = btn.dataset.tab;

        // Hide all panes
        panes.forEach(p => p.classList.remove('active'));

        // Show selected pane
        let selectedPane;
        if (tabName === '3d') {
          selectedPane = el.querySelector('#space-3d');
        } else if (tabName === 'plan') {
          selectedPane = el.querySelector('#space-plan');
        } else if (tabName === 'palette') {
          selectedPane = el.querySelector('#space-palette');
        }

        if (selectedPane) {
          selectedPane.classList.add('active');
        }

        // Update active tab button
        tabBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      });
    });

    // Show toast for network errors
    const originalGet = FS.get;
    FS.get = async function(...args) {
      try {
        return await originalGet(...args);
      } catch (e) {
        showToast(`Network error: ${e.message}`, 'error');
        throw e;
      }
    };

    // Store in FS for subsequent interactions, keeping the pure functions
    // that were attached to FS.space when the script loaded.
    FS.space = Object.assign(FS.space || {}, {
      layout,
      devices,
      records,
      planCanvas,
      canvas3d,
      showToast: showToast
    });
  }
});

// Toast notification system
function showToast(msg, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `space-toast ${type}`;
  toast.textContent = msg;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// === Plan Pane (2D Canvas) ===

function initPlanPane(el, canvas, layout) {
  const ctx = canvas.getContext('2d');
  const GRID_SIZE = 1; // metres
  const SNAP_DIST = 0.1; // metres
  const VERTEX_HIT_RADIUS = 8; // pixels

  let viewState = {
    scale: 20, // pixels per metre
    panX: 0,
    panY: 0,
    zoom: 1
  };

  let editorState = {
    mode: 'view', // 'view', 'draw', 'scale', 'level'
    currentFloor: layout.floors?.[0]?.id || '0',
    drawPath: [],
    scalePoints: [],
    levelPoints: [],
    draggingVertex: null, // { roomId, vertexIndex }
    draggingPlacement: null, // { mac }
    selectedRoom: null, // roomId
    undoStack: [],
    redoStack: [],
    lastSavedLayout: JSON.stringify(layout)
  };

  let currentLayout = JSON.parse(JSON.stringify(layout));

  // Resize canvas to fit parent
  function resizeCanvas() {
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
    draw();
  }

  // Screen to world coordinates
  function screenToWorld(sx, sy) {
    const x = (sx - viewState.panX) / (viewState.scale * viewState.zoom);
    const y = (sy - viewState.panY) / (viewState.scale * viewState.zoom);
    return [x, y];
  }

  // World to screen coordinates
  function worldToScreen(wx, wy) {
    const sx = wx * viewState.scale * viewState.zoom + viewState.panX;
    const sy = wy * viewState.scale * viewState.zoom + viewState.panY;
    return [sx, sy];
  }

  // Snap to grid
  function snap(v) {
    return Math.round(v / SNAP_DIST) * SNAP_DIST;
  }

  // Draw the plan
  function draw() {
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--bg-base').trim();
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw grid
    ctx.lineWidth = 0.5;
    ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-muted').trim();
    const gridPixels = GRID_SIZE * viewState.scale * viewState.zoom;

    for (let x = viewState.panX % gridPixels; x < canvas.width; x += gridPixels) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }

    for (let y = viewState.panY % gridPixels; y < canvas.height; y += gridPixels) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }

    // Draw rooms for current floor
    const floorRooms = currentLayout.rooms?.filter(r => r.floor === editorState.currentFloor) || [];
    floorRooms.forEach(room => {
      if (!room.polygon || room.polygon.length < 2) return;

      const isSelected = editorState.selectedRoom === room.id;

      ctx.fillStyle = isSelected ? 'rgba(150, 200, 255, 0.2)' : 'rgba(200, 200, 200, 0.1)';
      ctx.strokeStyle = isSelected ? 'rgba(50, 100, 200, 0.8)' : 'rgba(100, 100, 100, 0.5)';
      ctx.lineWidth = isSelected ? 3 / viewState.zoom : 2 / viewState.zoom;

      ctx.beginPath();
      const [sx0, sy0] = worldToScreen(room.polygon[0][0], room.polygon[0][1]);
      ctx.moveTo(sx0, sy0);

      for (let i = 1; i < room.polygon.length; i++) {
        const [sx, sy] = worldToScreen(room.polygon[i][0], room.polygon[i][1]);
        ctx.lineTo(sx, sy);
      }

      ctx.closePath();
      ctx.fill();
      ctx.stroke();

      // Room vertices
      room.polygon.forEach((pt, i) => {
        const [sx, sy] = worldToScreen(pt[0], pt[1]);
        ctx.fillStyle = isSelected ? 'rgba(50, 100, 200, 1)' : 'rgba(100, 100, 100, 0.7)';
        ctx.beginPath();
        ctx.arc(sx, sy, isSelected ? 5 : 4, 0, Math.PI * 2);
        ctx.fill();
      });

      // Room label
      if (room.polygon.length > 0) {
        const [sx, sy] = worldToScreen(room.polygon[0][0], room.polygon[0][1]);
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-base').trim();
        ctx.font = isSelected ? 'bold 12px sans-serif' : '12px sans-serif';
        ctx.fillText(room.name, sx + 8, sy + 16);
      }
    });

    // Draw placements as draggable dots
    if (currentLayout.placements) {
      currentLayout.placements.forEach(p => {
        if (p.floor !== editorState.currentFloor) return;

        const [sx, sy] = worldToScreen(p.x, p.y);
        ctx.fillStyle = 'rgba(255, 100, 100, 0.7)';
        ctx.beginPath();
        ctx.arc(sx, sy, 4, 0, Math.PI * 2);
        ctx.fill();

        // Label
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-base').trim();
        ctx.font = '10px sans-serif';
        ctx.fillText(p.label || p.mac.substr(0, 8), sx + 6, sy + 3);
      });
    }

    // Draw in-progress path
    if (editorState.drawPath.length > 0) {
      ctx.strokeStyle = 'rgba(100, 150, 255, 0.8)';
      ctx.lineWidth = 2 / viewState.zoom;
      ctx.beginPath();
      const [sx0, sy0] = worldToScreen(editorState.drawPath[0][0], editorState.drawPath[0][1]);
      ctx.moveTo(sx0, sy0);

      for (let i = 1; i < editorState.drawPath.length; i++) {
        const [sx, sy] = worldToScreen(editorState.drawPath[i][0], editorState.drawPath[i][1]);
        ctx.lineTo(sx, sy);
      }

      ctx.stroke();

      // Draw points
      editorState.drawPath.forEach((pt, i) => {
        const [sx, sy] = worldToScreen(pt[0], pt[1]);
        ctx.fillStyle = i === editorState.drawPath.length - 1 ? 'rgba(255, 100, 100, 1)' : 'rgba(100, 200, 100, 1)';
        ctx.beginPath();
        ctx.arc(sx, sy, 4, 0, Math.PI * 2);
        ctx.fill();
      });

      // Show distance label for scale mode
      if (editorState.mode === 'scale' && editorState.scalePoints.length > 0) {
        const p1 = editorState.scalePoints[0];
        const [sx, sy] = worldToScreen(p1[0], p1[1]);
        ctx.fillStyle = 'rgba(0, 150, 255, 1)';
        ctx.font = '12px sans-serif';
        ctx.fillText('Click second point', sx + 8, sy - 8);
      }
    }
  }

  // Helper: find which room vertex is clicked
  function findVertexAtScreen(screenX, screenY) {
    const floorRooms = currentLayout.rooms?.filter(r => r.floor === editorState.currentFloor) || [];
    for (const room of floorRooms) {
      if (!room.polygon) continue;
      for (let i = 0; i < room.polygon.length; i++) {
        const [sx, sy] = worldToScreen(room.polygon[i][0], room.polygon[i][1]);
        const dist = Math.hypot(sx - screenX, sy - screenY);
        if (dist < VERTEX_HIT_RADIUS) {
          return { roomId: room.id, vertexIndex: i };
        }
      }
    }
    return null;
  }

  // Helper: find which placement is clicked
  function findPlacementAtScreen(screenX, screenY) {
    if (!currentLayout.placements) return null;
    for (const p of currentLayout.placements) {
      if (p.floor !== editorState.currentFloor) continue;
      const [sx, sy] = worldToScreen(p.x, p.y);
      const dist = Math.hypot(sx - screenX, sy - screenY);
      if (dist < VERTEX_HIT_RADIUS) {
        return p.mac;
      }
    }
    return null;
  }

  // Helper: find which room polygon is clicked (interior)
  function findRoomAtWorld(wx, wy) {
    const floorRooms = currentLayout.rooms?.filter(r => r.floor === editorState.currentFloor) || [];
    for (const room of floorRooms) {
      if (FS.space3D?.pointInPolygon && room.polygon) {
        if (FS.space3D.pointInPolygon([wx, wy], room.polygon)) {
          return room.id;
        }
      }
    }
    return null;
  }

  // Canvas mouse/touch events
  canvas.addEventListener('click', (e) => {
    const rect = canvas.getBoundingClientRect();
    const screenX = e.clientX - rect.left;
    const screenY = e.clientY - rect.top;
    const [wx, wy] = screenToWorld(screenX, screenY);

    if (editorState.mode === 'draw') {
      const snapped = [snap(wx), snap(wy)];

      // Check if clicking first point to close
      if (editorState.drawPath.length >= 3) {
        const first = editorState.drawPath[0];
        if (Math.abs(first[0] - snapped[0]) < 0.2 && Math.abs(first[1] - snapped[1]) < 0.2) {
          finalizeRoom();
          return;
        }
      }

      editorState.drawPath.push(snapped);
      draw();
    } else if (editorState.mode === 'scale') {
      const snapped = [snap(wx), snap(wy)];

      editorState.scalePoints.push(snapped);
      if (editorState.scalePoints.length === 2) {
        showScaleDialog();
      }
      draw();
    } else if (editorState.mode === 'view') {
      // Click on room interior to select
      const roomId = findRoomAtWorld(wx, wy);
      if (roomId) {
        editorState.selectedRoom = roomId;
        draw();
      } else {
        editorState.selectedRoom = null;
        draw();
      }
    }
  });

  canvas.addEventListener('dblclick', () => {
    if (editorState.mode === 'draw' && editorState.drawPath.length >= 3) {
      finalizeRoom();
    }
  });

  // Vertex and placement dragging
  canvas.addEventListener('mousedown', (e) => {
    const rect = canvas.getBoundingClientRect();
    const screenX = e.clientX - rect.left;
    const screenY = e.clientY - rect.top;

    if (e.button === 0 && editorState.mode === 'view') {
      // Check for vertex drag
      const vertex = findVertexAtScreen(screenX, screenY);
      if (vertex) {
        editorState.draggingVertex = vertex;
        return;
      }

      // Check for placement drag
      const mac = findPlacementAtScreen(screenX, screenY);
      if (mac) {
        editorState.draggingPlacement = { mac };
        return;
      }
    }

    // Pan/zoom
    if (e.button === 2 || (e.button === 0 && e.shiftKey)) {
      panStart = { x: e.clientX, y: e.clientY };
    }
  });

  let panStart = null;

  canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    const screenX = e.clientX - rect.left;
    const screenY = e.clientY - rect.top;
    const [wx, wy] = screenToWorld(screenX, screenY);

    // Vertex dragging
    if (editorState.draggingVertex) {
      const { roomId, vertexIndex } = editorState.draggingVertex;
      const room = currentLayout.rooms?.find(r => r.id === roomId);
      if (room && room.polygon) {
        room.polygon[vertexIndex] = [snap(wx), snap(wy)];
        saveLayout();
        draw();
      }
      return;
    }

    // Placement dragging
    if (editorState.draggingPlacement) {
      const placement = currentLayout.placements?.find(p => p.mac === editorState.draggingPlacement.mac);
      if (placement && placement.floor === editorState.currentFloor) {
        placement.x = wx;
        placement.y = wy;
        saveLayout();
        draw();
      }
      return;
    }

    // Pan
    if (panStart) {
      viewState.panX += e.clientX - panStart.x;
      viewState.panY += e.clientY - panStart.y;
      panStart = { x: e.clientX, y: e.clientY };
      draw();
    }
  });

  canvas.addEventListener('mouseup', () => {
    if (editorState.draggingVertex) {
      editorState.draggingVertex = null;
      draw();
    }
    if (editorState.draggingPlacement) {
      editorState.draggingPlacement = null;
      draw();
    }
    panStart = null;
  });

  canvas.addEventListener('contextmenu', (e) => e.preventDefault());

  canvas.addEventListener('wheel', (e) => {
    e.preventDefault();
    const factor = 1 - e.deltaY * 0.001;
    viewState.zoom *= factor;
    viewState.zoom = Math.max(0.1, Math.min(5, viewState.zoom));
    draw();
  });

  // Update unsaved indicator
  function updateUnsavedIndicator() {
    const indicator = el.querySelector('#space-unsaved-indicator');
    const currentStr = JSON.stringify(currentLayout);
    const isUnsaved = currentStr !== editorState.lastSavedLayout;
    indicator.textContent = isUnsaved ? '● Unsaved' : '';

    // Show/hide room operation buttons
    const renameBtn = el.querySelector('#btn-plan-rename-room');
    const deleteBtn = el.querySelector('#btn-plan-delete-room');
    if (editorState.selectedRoom) {
      renameBtn.style.display = 'inline-block';
      deleteBtn.style.display = 'inline-block';
    } else {
      renameBtn.style.display = 'none';
      deleteBtn.style.display = 'none';
    }
  }

  // Toolbar events
  el.querySelector('#btn-plan-draw').addEventListener('click', () => {
    editorState.mode = editorState.mode === 'draw' ? 'view' : 'draw';
    editorState.drawPath = [];
    el.querySelector('#btn-plan-draw').style.background = editorState.mode === 'draw' ? 'var(--bg-alt)' : '';
    draw();
  });

  el.querySelector('#btn-plan-undo').addEventListener('click', () => {
    if (editorState.undoStack.length > 0) {
      const prev = editorState.undoStack.pop();
      editorState.redoStack.push(JSON.stringify(currentLayout));
      currentLayout = JSON.parse(prev);
      editorState.selectedRoom = null;
      editorState.drawPath = [];
      editorState.mode = 'view';
      updateUnsavedIndicator();
      saveLayout();
      draw();
    }
  });

  el.querySelector('#btn-plan-redo').addEventListener('click', () => {
    if (editorState.redoStack.length > 0) {
      const next = editorState.redoStack.pop();
      editorState.undoStack.push(JSON.stringify(currentLayout));
      currentLayout = JSON.parse(next);
      editorState.selectedRoom = null;
      editorState.drawPath = [];
      editorState.mode = 'view';
      updateUnsavedIndicator();
      saveLayout();
      draw();
    }
  });

  el.querySelector('#btn-plan-import-osm').addEventListener('click', async () => {
    try {
      const resp = await FS.get('/api/space/records');
      if (resp.building_footprints?.length > 0) {
        const fp = resp.building_footprints[0];
        if (fp.polygon) {
          // Create a new room from the footprint
          editorState.undoStack.push(JSON.stringify(currentLayout));
          editorState.redoStack = [];
          currentLayout = FS.space.reduce(currentLayout, {
            type: 'ADD_ROOM',
            name: fp.name || 'Building',
            floor: editorState.currentFloor,
            polygon: fp.polygon
          });
          updateUnsavedIndicator();
          saveLayout();
          draw();
        }
      }
    } catch (e) {
      console.error('Failed to import OSM:', e);
    }
  });

  el.querySelector('#btn-plan-set-scale').addEventListener('click', () => {
    editorState.mode = editorState.mode === 'scale' ? 'view' : 'scale';
    editorState.scalePoints = [];
    draw();
  });

  el.querySelector('#btn-plan-rename-room').addEventListener('click', () => {
    if (!editorState.selectedRoom) return;

    const room = currentLayout.rooms?.find(r => r.id === editorState.selectedRoom);
    if (!room) return;

    const newName = prompt('Room name:', room.name);
    if (newName && newName !== room.name) {
      editorState.undoStack.push(JSON.stringify(currentLayout));
      editorState.redoStack = [];
      room.name = newName;
      updateUnsavedIndicator();
      saveLayout();
      draw();
    }
  });

  el.querySelector('#btn-plan-delete-room').addEventListener('click', () => {
    if (!editorState.selectedRoom) return;

    const room = currentLayout.rooms?.find(r => r.id === editorState.selectedRoom);
    if (!room) return;

    if (confirm(`Delete room "${room.name}"?`)) {
      editorState.undoStack.push(JSON.stringify(currentLayout));
      editorState.redoStack = [];
      currentLayout.rooms = currentLayout.rooms.filter(r => r.id !== editorState.selectedRoom);
      editorState.selectedRoom = null;
      updateUnsavedIndicator();
      saveLayout();
      draw();
    }
  });

  el.querySelector('#space-floor-select').addEventListener('change', (e) => {
    editorState.currentFloor = e.target.value;
    editorState.drawPath = [];
    editorState.mode = 'view';
    editorState.selectedRoom = null;
    draw();
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey) {
      if (e.key === 'z') {
        e.preventDefault();
        if (editorState.undoStack.length > 0) {
          const prev = editorState.undoStack.pop();
          editorState.redoStack.push(currentLayout);
          currentLayout = prev;
          saveLayout();
          draw();
        }
      } else if (e.key === 'y') {
        e.preventDefault();
        if (editorState.redoStack.length > 0) {
          const next = editorState.redoStack.pop();
          editorState.undoStack.push(currentLayout);
          currentLayout = next;
          saveLayout();
          draw();
        }
      }
    }
  });

  // Save layout with debounce
  let saveTimeout;
  function saveLayout() {
    clearTimeout(saveTimeout);
    saveTimeout = setTimeout(async () => {
      try {
        await fetch('/api/space/layout', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(currentLayout)
        });
      } catch (e) {
        console.error('Failed to save layout:', e);
      }
    }, 800);
  }

  function finalizeRoom() {
    const polygon = editorState.drawPath.map(pt => [snap(pt[0]), snap(pt[1])]);
    editorState.mode = 'view';
    editorState.drawPath = [];

    FS.modal(`
      <h2>New Room</h2>
      <input type="text" id="room-name" placeholder="Room name" style="display:block;width:100%;margin:8px 0;padding:6px">
      <label>Ceiling height (m): <input type="number" id="ceiling-m" value="2.6" style="width:60px"></label>
      <div class="actions">
        <button class="btn primary" id="ok-btn">Create</button>
        <button class="btn" id="cancel-btn">Cancel</button>
      </div>
    `, (body) => {
      const nameInput = body.querySelector('#room-name');
      const ceilingInput = body.querySelector('#ceiling-m');
      const okBtn = body.querySelector('#ok-btn');
      const cancelBtn = body.querySelector('#cancel-btn');

      nameInput.focus();

      okBtn.addEventListener('click', () => {
        const name = nameInput.value || 'Room';
        const ceiling = parseFloat(ceilingInput.value) || 2.6;

        // Push undo before modifying
        editorState.undoStack.push(JSON.stringify(currentLayout));
        editorState.redoStack = [];

        currentLayout = FS.space.reduce(currentLayout, {
          type: 'ADD_ROOM',
          name,
          floor: editorState.currentFloor,
          polygon,
          ceiling_m: ceiling
        });

        updateUnsavedIndicator();
        saveLayout();
        FS.closeModal();
        draw();
      });

      cancelBtn.addEventListener('click', () => {
        FS.closeModal();
        draw();
      });
    });
  }

  function showScaleDialog() {
    const p1 = editorState.scalePoints[0];
    const p2 = editorState.scalePoints[1];
    const pixelDist = Math.sqrt((p2[0] - p1[0]) ** 2 + (p2[1] - p1[1]) ** 2);

    FS.modal(`
      <h2>Set Scale</h2>
      <p>Pixel distance: ${pixelDist.toFixed(2)} m</p>
      <label>Real distance (m): <input type="number" id="real-dist" placeholder="e.g. 5" style="width:100px"></label>
      <div class="actions">
        <button class="btn primary" id="scale-ok">Apply</button>
        <button class="btn" id="scale-cancel">Cancel</button>
      </div>
    `, (body) => {
      const input = body.querySelector('#real-dist');
      const okBtn = body.querySelector('#scale-ok');
      const cancelBtn = body.querySelector('#scale-cancel');

      input.focus();

      okBtn.addEventListener('click', () => {
        const realDist = parseFloat(input.value);
        if (realDist > 0) {
          const factor = realDist / pixelDist;
          editorState.undoStack.push(JSON.stringify(currentLayout));
          editorState.redoStack = [];
          currentLayout = FS.space.reduce(currentLayout, {
            type: 'SCALE_COORDINATES',
            factor
          });
          updateUnsavedIndicator();
          saveLayout();
        }

        editorState.mode = 'view';
        editorState.scalePoints = [];
        FS.closeModal();
        draw();
      });

      cancelBtn.addEventListener('click', () => {
        editorState.mode = 'view';
        editorState.scalePoints = [];
        FS.closeModal();
        draw();
      });
    });
  }

  // Initial draw
  window.addEventListener('resize', resizeCanvas);
  resizeCanvas();
}

// === 3D Pane (WebGL Viewer) ===

async function init3DPane(el, canvas, layout) {
  if (!FS.space3D) {
    console.error('WebGL viewer not available');
    return;
  }

  const viewer = new FS.space3D.Viewer(canvas);
  viewer.layout = layout;
  viewer.markerMeshes = new Map(); // mac -> mesh for interaction

  // Create grid and axes
  viewer.createGrid(10, 1);
  viewer.createAxes(1);

  // Helper to apply transform to geometry
  function applyTransform(geometry, transform) {
    if (!transform || !geometry.positions) return geometry;

    const scale = transform.scale || 1;
    const rotDeg = transform.rotation_deg || 0;
    const offset = transform.offset || [0, 0, 0];
    const upAxis = transform.up_axis || 'z';

    // Create a copy
    const pos = new Float32Array(geometry.positions);

    // Apply scale
    for (let i = 0; i < pos.length; i++) {
      pos[i] *= scale;
    }

    // Convert Y-up to Z-up if needed
    if (upAxis === 'y') {
      for (let i = 0; i < pos.length; i += 3) {
        const tmp = pos[i + 1];
        pos[i + 1] = pos[i + 2];
        pos[i + 2] = tmp;
      }
    }

    // Apply rotation about Z (up) axis
    const rad = (rotDeg * Math.PI) / 180;
    const cos = Math.cos(rad);
    const sin = Math.sin(rad);
    for (let i = 0; i < pos.length; i += 3) {
      const x = pos[i];
      const y = pos[i + 1];
      pos[i] = x * cos - y * sin;
      pos[i + 1] = x * sin + y * cos;
    }

    // Apply offset
    for (let i = 0; i < pos.length; i += 3) {
      pos[i] += offset[0];
      pos[i + 1] += offset[1];
      pos[i + 2] += offset[2];
    }

    return { ...geometry, positions: pos };
  }

  // Load scan if available
  if (layout.scan?.file) {
    try {
      const showProgress = () => {
        const progress = document.createElement('div');
        progress.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:rgba(0,0,0,0.8);color:white;padding:20px;border-radius:8px;z-index:100';
        progress.innerHTML = '<div>Loading scan...</div><div id="progress-bar" style="width:200px;height:4px;background:rgba(255,255,255,0.3);margin-top:10px;overflow:hidden"><div id="progress-fill" style="height:100%;background:white;width:0%"></div></div>';
        canvas.parentElement.insertAdjacentElement('afterbegin', progress);
        return progress;
      };

      const progressEl = showProgress();
      const updateProgress = (percent) => {
        const fill = progressEl.querySelector('#progress-fill');
        if (fill) fill.style.width = (percent * 100) + '%';
      };

      // Fetch scan data in chunks for progress
      const resp = await fetch('/api/space/scan');
      if (!resp.ok) throw new Error('Failed to load scan');
      const buffer = await resp.arrayBuffer();

      // Parse based on format
      let geometry = null;
      const format = layout.scan.format;

      if (format === 'glb') {
        geometry = await parseWithProgress(buffer, 'glb', updateProgress);
      } else if (format === 'obj') {
        const text = new TextDecoder().decode(new Uint8Array(buffer));
        geometry = FS.space.parseOBJ(text);
      } else if (format === 'ply') {
        geometry = FS.space.parsePLY(buffer);
      } else if (format === 'roomplan') {
        const json = JSON.parse(new TextDecoder().decode(new Uint8Array(buffer)));
        geometry = FS.space.parseRoomPlan(json);
      }

      if (geometry) {
        // Apply transform
        geometry = applyTransform(geometry, layout.scan.transform);

        // Add to viewer
        viewer.addMesh(geometry, [0.8, 0.85, 0.9, 0.9], 'Scan');

        // Fit camera
        viewer.fitToView();
      }

      progressEl.remove();
    } catch (e) {
      console.error('Failed to load scan:', e);
      const err = document.createElement('div');
      err.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:rgba(255,0,0,0.8);color:white;padding:20px;border-radius:8px;z-index:100';
      err.innerHTML = 'Failed to load scan: ' + e.message;
      canvas.parentElement.insertAdjacentElement('afterbegin', err);
      setTimeout(() => err.remove(), 5000);
    }
  }

  // Add rooms as extruded boxes for all floors
  const currentFloorId = layout.floors?.[0]?.id || '0';
  const allRooms = layout.rooms || [];

  allRooms.forEach((room, idx) => {
    if (!room.polygon || room.polygon.length < 3) return;

    const floor = layout.floors?.find(f => f.id === room.floor);
    const isCurrent = room.floor === currentFloorId;

    // Create box geometry for room
    const positions = [];
    const indices = [];

    // Polygon vertices at floor
    const z0 = floor?.elevation_m || 0;
    const z1 = z0 + (room.ceiling_m || 2.6);

    // Bottom polygon
    room.polygon.forEach((pt, i) => {
      positions.push(pt[0], pt[1], z0);
    });

    // Top polygon
    room.polygon.forEach((pt, i) => {
      positions.push(pt[0], pt[1], z1);
    });

    const n = room.polygon.length;
    const base = 0;

    // Bottom face (reversed for outward normal)
    for (let i = 1; i < n - 1; i++) {
      indices.push(base, base + i + 1, base + i);
    }

    // Top face
    for (let i = 1; i < n - 1; i++) {
      indices.push(base + n, base + n + i, base + n + i + 1);
    }

    // Side faces
    for (let i = 0; i < n; i++) {
      const i1 = (i + 1) % n;
      indices.push(base + i, base + n + i, base + n + i1);
      indices.push(base + i, base + n + i1, base + i1);
    }

    if (indices.length > 0) {
      // Current floor rooms: opaque, other floors: faint
      const alpha = isCurrent ? 0.4 : 0.1;
      const color = isCurrent
        ? [0.6, 0.7, 0.9, alpha]
        : [0.7, 0.7, 0.8, alpha];

      viewer.addMesh(
        { positions: new Float32Array(positions), indices: new Uint32Array(indices), normals: null },
        color,
        'Room: ' + room.name + (isCurrent ? '' : ` (${floor?.name || 'Floor'})`)
      );
    }
  });

  // Place markers for existing placements
  if (layout.placements) {
    layout.placements.forEach(p => {
      // Simple marker as a small sphere or box
      const positions = [];
      const indices = [];
      const size = 0.1;

      // Cube marker
      const verts = [
        -size, -size, -size, size, -size, -size, size, size, -size, -size, size, -size,
        -size, -size, size, size, -size, size, size, size, size, -size, size, size,
      ];

      positions.push(...verts.map((v, i) => {
        if (i % 3 === 0) return v + p.x;
        if (i % 3 === 1) return v + p.y;
        return v + p.z;
      }));

      const cubeIndices = [
        0, 1, 2, 0, 2, 3, 4, 6, 5, 4, 7, 6,
        0, 4, 5, 0, 5, 1, 2, 6, 7, 2, 7, 3,
        0, 3, 7, 0, 7, 4, 1, 5, 6, 1, 6, 2
      ];

      indices.push(...cubeIndices);

      const mesh = viewer.addMesh(
        { positions: new Float32Array(positions), indices: new Uint32Array(indices), normals: null },
        [1, 0.2, 0.2, 1],
        'Device: ' + p.label
      );

      // Track mesh for interaction
      viewer.markerMeshes.set(p.mac, { mesh, placement: p });
    });
  }

  // Marker interaction: click to open popover, drag to move, wheel to adjust z
  setupMarkerInteraction(canvas, viewer, layout);

  // Level and align tool buttons
  setupCalibrationTools(el, canvas, viewer, layout);

  // Store viewer for later access
  if (!FS.space) FS.space = {};
  FS.space.viewer = viewer;
}

async function parseWithProgress(buffer, format, updateProgress) {
  return new Promise((resolve, reject) => {
    // Parse in chunks to allow progress updates
    let result;
    try {
      if (format === 'glb') {
        result = FS.space.parseGLB(buffer);
      } else {
        reject(new Error('Unknown format: ' + format));
      }
      updateProgress(1);
      setTimeout(() => resolve(result), 10);
    } catch (e) {
      reject(e);
    }
  });
}

// === Marker Interaction (3D) ===

function setupMarkerInteraction(canvas, viewer, layout) {
  let draggingMarker = null;
  let dragStartPos = null;

  // Find which marker (placement) a ray hits
  function findMarkerAtRay(screenX, screenY) {
    const ray = viewer.unproject(screenX, screenY);
    const hitRadius = 0.15; // metres
    let closest = null;
    let minDist = Infinity;

    for (const [mac, entry] of viewer.markerMeshes.entries()) {
      const p = entry.placement;
      const markerPos = [p.x, p.y, p.z];

      // Simple distance check from ray to point
      const rayToPoint = [
        markerPos[0] - ray.origin[0],
        markerPos[1] - ray.origin[1],
        markerPos[2] - ray.origin[2]
      ];

      const rayLen = Math.sqrt(ray.dir[0] * ray.dir[0] + ray.dir[1] * ray.dir[1] + ray.dir[2] * ray.dir[2]);
      const projLen = (rayToPoint[0] * ray.dir[0] + rayToPoint[1] * ray.dir[1] + rayToPoint[2] * ray.dir[2]) / (rayLen * rayLen);

      if (projLen < 0) continue; // Behind camera

      const proj = [
        ray.origin[0] + ray.dir[0] * projLen,
        ray.origin[1] + ray.dir[1] * projLen,
        ray.origin[2] + ray.dir[2] * projLen
      ];

      const dist = Math.sqrt(
        (markerPos[0] - proj[0]) ** 2 +
        (markerPos[1] - proj[1]) ** 2 +
        (markerPos[2] - proj[2]) ** 2
      );

      if (dist < hitRadius && dist < minDist) {
        closest = { mac, placement: p, dist };
        minDist = dist;
      }
    }

    return closest;
  }

  // Canvas mouse events
  canvas.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return; // Left click only

    const rect = canvas.getBoundingClientRect();
    const screenX = e.clientX - rect.left;
    const screenY = e.clientY - rect.top;

    const marker = findMarkerAtRay(screenX, screenY);
    if (marker) {
      draggingMarker = marker;
      dragStartPos = { x: marker.placement.x, y: marker.placement.y, z: marker.placement.z };
      e.preventDefault();
    }
  });

  let currentDragZ = 0;

  canvas.addEventListener('pointermove', (e) => {
    if (!draggingMarker) return;

    const rect = canvas.getBoundingClientRect();
    const screenX = e.clientX - rect.left;
    const screenY = e.clientY - rect.top;

    const hit = viewer.raycast(screenX, screenY);
    if (hit) {
      // Update placement position in viewer state (not saved yet)
      draggingMarker.placement.x = hit.x;
      draggingMarker.placement.y = hit.y;
      // z can be adjusted with wheel, so keep currentDragZ
      draggingMarker.placement.z = currentDragZ;
    }
  });

  canvas.addEventListener('pointerup', async (e) => {
    if (!draggingMarker) return;

    // Save placement
    try {
      const resp = await fetch('/api/space/place', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mac: draggingMarker.mac,
          x: draggingMarker.placement.x,
          y: draggingMarker.placement.y,
          z: draggingMarker.placement.z,
          floor: layout.floors?.[0]?.id || '0',
          room: pointInRoom(draggingMarker.placement.x, draggingMarker.placement.y, layout)
        })
      });

      if (!resp.ok) {
        console.error('Failed to save placement');
        // Restore original position
        draggingMarker.placement.x = dragStartPos.x;
        draggingMarker.placement.y = dragStartPos.y;
        draggingMarker.placement.z = dragStartPos.z;
      }
    } catch (err) {
      console.error('Failed to save placement:', err);
      draggingMarker.placement.x = dragStartPos.x;
      draggingMarker.placement.y = dragStartPos.y;
      draggingMarker.placement.z = dragStartPos.z;
    }

    draggingMarker = null;
    dragStartPos = null;
    currentDragZ = 0;
  });

  // Wheel while dragging adjusts z
  canvas.addEventListener('wheel', (e) => {
    if (!draggingMarker) return;
    e.preventDefault();

    const zDelta = -e.deltaY * 0.01;
    currentDragZ = Math.max(0, draggingMarker.placement.z + zDelta);
    draggingMarker.placement.z = currentDragZ;
  });

  // Click (not drag) on marker opens popover
  let clickStartPos = null;

  canvas.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return;

    const rect = canvas.getBoundingClientRect();
    clickStartPos = { x: e.clientX - rect.left, y: e.clientY - rect.top };
  });

  canvas.addEventListener('pointerup', async (e) => {
    if (!clickStartPos) return;

    const rect = canvas.getBoundingClientRect();
    const screenX = e.clientX - rect.left;
    const screenY = e.clientY - rect.top;

    const dist = Math.hypot(
      screenX - clickStartPos.x,
      screenY - clickStartPos.y
    );

    // Only treat as click if pointer didn't move much
    if (dist > 5) {
      clickStartPos = null;
      return;
    }

    const marker = findMarkerAtRay(screenX, screenY);
    if (marker) {
      showMarkerPopover(marker, layout);
    }

    clickStartPos = null;
  });
}

// Show marker popover with device info and visibility sparkline
async function showMarkerPopover(marker, layout) {
  const placement = marker.placement;

  // Fetch visibility data for sparkline
  let sparklineData = [];
  try {
    const visResp = await FS.get(`/api/visibility/host?ip=${encodeURIComponent(placement.ip || placement.mac)}&hours=1`);
    if (visResp && visResp.timeline) {
      sparklineData = visResp.timeline.slice(-60); // Last 60 points
    }
  } catch (e) {
    console.warn('Failed to load visibility:', e);
  }

  // Build sparkline SVG
  const sparklineSvg = sparklineData.length > 0
    ? `<svg width="100%" height="20" style="margin:4px 0" viewBox="0 0 ${sparklineData.length} 1">
        ${sparklineData.map((v, i) => {
          const y = 1 - (v || 0);
          return `<rect x="${i}" y="${y * 0.8}" width="1" height="${Math.min(0.8, (v || 0) * 0.8)}" fill="var(--text-muted)" opacity="0.5"/>`;
        }).join('')}
      </svg>`
    : '<div style="font-size:11px;color:var(--text-muted)">No visibility data</div>';

  const roomName = layout.rooms?.find(r => r.id === placement.room)?.name || placement.room || 'Unknown';

  const html = `
    <h3>${esc(placement.label || placement.mac)}</h3>
    <div style="font-size:11px;color:var(--text-muted);margin:4px 0">
      <div><strong>MAC:</strong> ${esc(placement.mac)}</div>
      <div><strong>Position:</strong> ${FS.num(placement.x, 2)}, ${FS.num(placement.y, 2)}, ${FS.num(placement.z, 2)} m</div>
      <div><strong>Floor:</strong> ${esc(placement.floor)}</div>
      <div><strong>Room:</strong> ${esc(roomName)}</div>
      <div><strong>Placed:</strong> ${new Date(placement.placed_since || Date.now()).toLocaleDateString()}</div>
    </div>
    <div style="margin:8px 0">
      <div style="font-size:10px;font-weight:500;margin:4px 0">Visibility (1h)</div>
      ${sparklineSvg}
    </div>
    <div class="actions" style="margin-top:8px;display:flex;gap:4px">
      <button class="btn" id="pop-host-link">Host Details</button>
      <button class="btn" id="pop-devices-link">Devices</button>
      <button class="btn destructive" id="pop-unplace">Unplace</button>
    </div>
  `;

  FS.modal(html, (body) => {
    const hostLink = body.querySelector('#pop-host-link');
    const devicesLink = body.querySelector('#pop-devices-link');
    const unplaceBtn = body.querySelector('#pop-unplace');

    if (hostLink && placement.ip) {
      hostLink.addEventListener('click', () => {
        FS.closeModal();
        window.location.hash = `#host/${encodeURIComponent(placement.ip)}`;
      });
    }

    if (devicesLink) {
      devicesLink.addEventListener('click', () => {
        FS.closeModal();
        window.location.hash = '#devices';
      });
    }

    if (unplaceBtn) {
      unplaceBtn.addEventListener('click', async () => {
        try {
          const resp = await fetch(`/api/space/place/${encodeURIComponent(marker.mac)}`, {
            method: 'DELETE'
          });

          if (resp.ok) {
            FS.closeModal();
            location.reload();
          } else {
            alert('Failed to unplace device');
          }
        } catch (err) {
          alert('Error: ' + err.message);
        }
      });
    }
  });
}

// Palette: highlight a device and fly camera to its marker
function highlightMarkerInPalette(mac, viewer) {
  const entry = viewer.markerMeshes?.get(mac);
  if (!entry) return;

  const p = entry.placement;
  const targetPos = [p.x, p.y, p.z];

  // Animate camera to marker over ~600 ms
  const startEye = [...viewer.camera.eye];
  const startCenter = [...viewer.camera.center];
  const startTime = Date.now();
  const duration = 600;

  const animateCamera = () => {
    const elapsed = Date.now() - startTime;
    const t = Math.min(1, elapsed / duration);

    // Ease out cubic
    const easeT = 1 - Math.pow(1 - t, 3);

    viewer.camera.eye = [
      startEye[0] + (targetPos[0] - startEye[0]) * easeT,
      startEye[1] + (targetPos[1] - startEye[1]) * easeT,
      startEye[2] + (targetPos[2] - startEye[2]) * easeT
    ];

    viewer.camera.center = [
      startCenter[0] + (targetPos[0] - startCenter[0]) * easeT,
      startCenter[1] + (targetPos[1] - startCenter[1]) * easeT,
      startCenter[2] + (targetPos[2] - startCenter[2]) * easeT
    ];

    if (t < 1) {
      requestAnimationFrame(animateCamera);
    }
  };

  animateCamera();
}

// === Calibration Tools (Level & Align) ===

function setupCalibrationTools(el, canvas, viewer, layout) {
  const levelBtn = el.querySelector('#btn-3d-level');
  const alignBtn = el.querySelector('#btn-3d-align');

  if (levelBtn) {
    levelBtn.addEventListener('click', () => {
      startLevelTool(canvas, viewer, layout);
    });
  }

  if (alignBtn) {
    alignBtn.addEventListener('click', () => {
      startAlignTool(canvas, viewer, layout);
    });
  }
}

// Level tool: collect 3 points on floor, fit plane, store transform
function startLevelTool(canvas, viewer, layout) {
  const points = [];
  const pointMarkers = [];

  const showStatus = (msg) => {
    let status = document.querySelector('#level-status');
    if (!status) {
      status = document.createElement('div');
      status.id = 'level-status';
      status.style.cssText = 'position:absolute;top:10px;left:10px;background:rgba(0,0,0,0.8);color:white;padding:10px;border-radius:4px;z-index:100;font-size:12px';
      canvas.parentElement.appendChild(status);
    }
    status.innerHTML = msg;
  };

  const cleanupStatus = () => {
    const status = document.querySelector('#level-status');
    if (status) status.remove();
  };

  const cleanupMarkers = () => {
    pointMarkers.forEach(m => m.remove());
    pointMarkers.length = 0;
  };

  const handleClick = (e) => {
    const rect = canvas.getBoundingClientRect();
    const screenX = e.clientX - rect.left;
    const screenY = e.clientY - rect.top;

    const hit = viewer.raycast(screenX, screenY);
    if (!hit) {
      showStatus('Click on the floor to add a point');
      return;
    }

    points.push([hit.x, hit.y, hit.z]);

    // Visual marker
    const marker = document.createElement('div');
    marker.style.cssText = `position:absolute;width:8px;height:8px;background:red;border-radius:50%;left:${screenX - 4}px;top:${screenY - 4}px;pointer-events:none`;
    canvas.parentElement.appendChild(marker);
    pointMarkers.push(marker);

    showStatus(`Floor point ${points.length} of 3. Click ${points.length < 3 ? 'the next point.' : 'to confirm.'}`);

    if (points.length === 3) {
      canvas.removeEventListener('click', handleClick);

      // Fit plane
      const plane = FS.space.planeFromPoints(points[0], points[1], points[2]);

      // Compute rotation to align normal with Z axis (up)
      const normal = plane.normal;

      // The current up axis is [0, 0, 1] in world space
      // We need to rotate normal to align with [0, 0, 1]
      let rotationDeg = 0;

      // If the normal is already roughly vertical, no rotation needed
      if (Math.abs(normal[2]) < 0.99) {
        // Use atan2 to get rotation about Z axis
        const angle = Math.atan2(normal[1], normal[0]);
        rotationDeg = angle * 180 / Math.PI;
      }

      // Compute Z offset as the plane's z value at origin
      const zOffset = plane.origin[2];

      // Save to layout
      const newLayout = FS.space.reduce(layout, {
        type: 'UPDATE_TRANSFORM',
        data: {
          rotation_deg: rotationDeg,
          offset: [0, 0, zOffset]
        }
      });

      // Save to server
      fetch('/api/space/layout', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newLayout)
      }).catch(e => console.error('Failed to save layout:', e));

      cleanupMarkers();
      cleanupStatus();

      showStatus('Floor leveled! Transform saved.');
      setTimeout(() => cleanupStatus(), 2000);
    }
  };

  showStatus('Level Tool: Click 3 points on the floor');
  canvas.addEventListener('click', handleClick);

  // Cancel on Escape
  const handleEscape = (e) => {
    if (e.key === 'Escape') {
      canvas.removeEventListener('click', handleClick);
      document.removeEventListener('keydown', handleEscape);
      cleanupMarkers();
      cleanupStatus();
    }
  };

  document.addEventListener('keydown', handleEscape);
}

// Align tool: collect 2 points in 3D, then 2 on plan, compute transform
function startAlignTool(canvas, viewer, layout) {
  const points3d = [];
  const pointsPlan = [];
  const markers = [];

  let step = 'points3d'; // 'points3d' -> 'points_plan' -> 'confirm'

  const showStatus = (msg) => {
    let status = document.querySelector('#align-status');
    if (!status) {
      status = document.createElement('div');
      status.id = 'align-status';
      status.style.cssText = 'position:absolute;top:10px;left:10px;background:rgba(0,0,0,0.8);color:white;padding:10px;border-radius:4px;z-index:100;font-size:12px';
      canvas.parentElement.appendChild(status);
    }
    status.innerHTML = msg;
  };

  const cleanupStatus = () => {
    const status = document.querySelector('#align-status');
    if (status) status.remove();
  };

  const cleanupMarkers = () => {
    markers.forEach(m => m.remove());
    markers.length = 0;
  };

  const handleClick3D = (e) => {
    const rect = canvas.getBoundingClientRect();
    const screenX = e.clientX - rect.left;
    const screenY = e.clientY - rect.top;

    const hit = viewer.raycast(screenX, screenY);
    if (!hit) return;

    points3d.push([hit.x, hit.y, hit.z]);

    const marker = document.createElement('div');
    marker.style.cssText = `position:absolute;width:8px;height:8px;background:blue;border-radius:50%;left:${screenX - 4}px;top:${screenY - 4}px;pointer-events:none`;
    canvas.parentElement.appendChild(marker);
    markers.push(marker);

    if (points3d.length === 2) {
      canvas.removeEventListener('click', handleClick3D);
      step = 'points_plan';
      showStatus('Now click the corresponding 2 points on the plan');
      // Switch to plan pane would happen here in a full implementation
      // For now, just show a message
    } else {
      showStatus(`3D point ${points3d.length} of 2. Click the next point.`);
    }
  };

  showStatus('Align Tool: Click 2 points in the 3D scan');
  canvas.addEventListener('click', handleClick3D);

  const handleEscape = (e) => {
    if (e.key === 'Escape') {
      canvas.removeEventListener('click', handleClick3D);
      document.removeEventListener('keydown', handleEscape);
      cleanupMarkers();
      cleanupStatus();
    }
  };

  document.addEventListener('keydown', handleEscape);
}


// === Palette Pane (Device List) ===

function initPalettePane(listEl, devices, layout) {
  const search = document.querySelector('#space-device-search');
  const filterPlaced = document.querySelector('#space-filter-placed');
  const filterUnplaced = document.querySelector('#space-filter-unplaced');
  const canvas3d = document.querySelector('#space-canvas-3d');

  let draggedDevice = null;

  function renderDevices() {
    const query = (search?.value || '').toLowerCase();
    const showPlaced = !filterPlaced?.checked;
    const showUnplaced = !filterUnplaced?.checked;

    const filtered = (devices.devices || []).filter(d => {
      const matches = d.label?.toLowerCase().includes(query) ||
                       d.mac?.includes(query) ||
                       d.vendor?.includes(query);
      return matches && (
        (d.placed && showPlaced) ||
        (!d.placed && showUnplaced)
      );
    });

    listEl.innerHTML = filtered.map(d => `
      <div class="space-device-item ${d.placed ? 'placed' : ''}" draggable="true"
           data-mac="${esc(d.mac)}" data-label="${esc(d.label || d.mac)}">
        <div class="space-device-item-label">${esc(d.label || d.mac)}</div>
        <div class="space-device-item-addr">${esc(d.vendor || '—')}</div>
        ${d.placed ? `<div class="space-device-item-addr">📍 ${esc(d.placement?.room || 'Unknown')}</div>` : ''}
      </div>
    `).join('');

    // Add drag and click handlers
    listEl.querySelectorAll('.space-device-item').forEach(item => {
      item.addEventListener('dragstart', (e) => {
        const mac = item.dataset.mac;
        const label = item.dataset.label;
        draggedDevice = { mac, label };
        e.dataTransfer.effectAllowed = 'move';
      });

      item.addEventListener('dragend', () => {
        draggedDevice = null;
      });

      // Click to highlight marker in 3D and fly camera
      item.addEventListener('click', () => {
        const mac = item.dataset.mac;
        if (FS.space?.viewer) {
          highlightMarkerInPalette(mac, FS.space.viewer);
        }
      });
    });
  }

  // Canvas drop handlers
  canvas3d.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    canvas3d.style.opacity = '0.8';
  });

  canvas3d.addEventListener('dragleave', () => {
    canvas3d.style.opacity = '1';
  });

  canvas3d.addEventListener('drop', async (e) => {
    e.preventDefault();
    canvas3d.style.opacity = '1';

    if (!draggedDevice) return;

    const rect = canvas3d.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    // Ray-cast from screen coordinates
    if (FS.space?.viewer?.raycast) {
      const hit = FS.space.viewer.raycast(x, y);
      if (hit) {
        // Place device
        try {
          const roomId = pointInRoom(hit.x, hit.y, layout);
          const resp = await fetch('/api/space/place', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              mac: draggedDevice.mac,
              x: hit.x,
              y: hit.y,
              z: hit.z,
              floor: layout.floors?.[0]?.id || '0',
              room: roomId
            })
          });

          if (resp.ok) {
            // Reload page to refresh placement
            location.reload();
          } else {
            const err = await resp.text();
            console.error('Failed to place device:', err);
          }
        } catch (err) {
          console.error('Failed to place device:', err);
        }
      }
    }
  });

  search?.addEventListener('input', renderDevices);
  filterPlaced?.addEventListener('change', renderDevices);
  filterUnplaced?.addEventListener('change', renderDevices);

  renderDevices();
}

// === Upload Scan ===

function initUploadScan(el) {
  const btn = el.querySelector('#btn-3d-upload-scan');
  if (!btn) return;

  btn.addEventListener('click', () => {
    const html = `
      <h2>Upload Scan</h2>
      <p>Supported formats: GLB (recommended), OBJ, PLY, RoomPlan JSON</p>
      <input type="file" id="scan-file" accept=".glb,.obj,.ply,.json" style="display:block;margin:12px 0">
      <div id="scan-size" style="font-size:11px;color:var(--text-muted);margin:8px 0"></div>
      <div class="actions">
        <button class="btn primary" id="upload-btn">Upload</button>
        <button class="btn" id="cancel-btn">Cancel</button>
      </div>
    `;

    FS.modal(html, (body) => {
      const fileInput = body.querySelector('#scan-file');
      const sizeDiv = body.querySelector('#scan-size');
      const uploadBtn = body.querySelector('#upload-btn');
      const cancelBtn = body.querySelector('#cancel-btn');

      fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
          const file = fileInput.files[0];
          const sizeMB = (file.size / 1024 / 1024).toFixed(1);
          sizeDiv.textContent = `File: ${file.name} (${sizeMB} MB)`;

          if (file.size > 50 * 1024 * 1024) {
            sizeDiv.textContent += ' ⚠ Max 50 MB';
          }

          // Check format
          const ext = file.name.split('.').pop().toLowerCase();
          if (!['glb', 'obj', 'ply', 'json'].includes(ext)) {
            sizeDiv.textContent += ' ⚠ Unsupported format';
          }

          if (ext === 'usdz') {
            sizeDiv.innerHTML += '<br><strong>USDZ not supported.</strong> Export your scan as GLB or OBJ from your app (see docs).';
          }
        }
      });

      uploadBtn.addEventListener('click', async () => {
        const file = fileInput.files[0];
        if (!file) return;

        uploadBtn.disabled = true;
        uploadBtn.textContent = 'Uploading...';

        try {
          const formData = new FormData();
          formData.append('file', file);

          const resp = await fetch(`/api/space/scan?name=${encodeURIComponent(file.name.split('.')[0])}`, {
            method: 'POST',
            body: formData
          });

          if (resp.ok) {
            FS.closeModal();
            uploadBtn.textContent = 'Upload';
            uploadBtn.disabled = false;

            // Reload to show the new scan
            setTimeout(() => location.reload(), 500);
          } else {
            const err = await resp.text();
            sizeDiv.innerHTML = `<strong style="color:red">Upload failed: ${err}</strong>`;
            uploadBtn.disabled = false;
            uploadBtn.textContent = 'Upload';
          }
        } catch (e) {
          sizeDiv.innerHTML = `<strong style="color:red">Error: ${e.message}</strong>`;
          uploadBtn.disabled = false;
          uploadBtn.textContent = 'Upload';
        }
      });

      cancelBtn.addEventListener('click', () => {
        FS.closeModal();
      });

      fileInput.focus();
    });
  });
}

// === Pure Functions for Calibration ===

if (!FS.space) FS.space = {};

// Fit a plane through three points and return the normal vector
FS.space.planeFromPoints = function(p1, p2, p3) {
  // Vectors in the plane
  const v1 = [p2[0] - p1[0], p2[1] - p1[1], p2[2] - p1[2]];
  const v2 = [p3[0] - p1[0], p3[1] - p1[1], p3[2] - p1[2]];

  // Normal = v1 × v2
  const normal = [
    v1[1] * v2[2] - v1[2] * v2[1],
    v1[2] * v2[0] - v1[0] * v2[2],
    v1[0] * v2[1] - v1[1] * v2[0]
  ];

  // Normalize
  const len = Math.sqrt(normal[0] * normal[0] + normal[1] * normal[1] + normal[2] * normal[2]);
  if (len > 0) {
    normal[0] /= len;
    normal[1] /= len;
    normal[2] /= len;
  }

  return { normal, origin: p1 };
};

// Compute transform (scale, rotation about z, offset) from two point pairs
// p1_3d, p2_3d: two points in 3D space (from the scan)
// p1_plan, p2_plan: corresponding two points on the plan (2D: [x, y])
// Returns: { scale, rotation_deg, offset: [x, y, z] }
FS.space.alignTransform = function(p1_3d, p2_3d, p1_plan, p2_plan) {
  // Distance in 3D
  const d3d = Math.sqrt(
    (p2_3d[0] - p1_3d[0]) ** 2 +
    (p2_3d[1] - p1_3d[1]) ** 2 +
    (p2_3d[2] - p1_3d[2]) ** 2
  );

  // Distance on plan (2D)
  const dplan = Math.sqrt(
    (p2_plan[0] - p1_plan[0]) ** 2 +
    (p2_plan[1] - p1_plan[1]) ** 2
  );

  const scale = dplan > 0.001 ? dplan / d3d : 1;

  // Direction vectors
  const dir3d = [
    (p2_3d[0] - p1_3d[0]) / d3d,
    (p2_3d[1] - p1_3d[1]) / d3d
  ];

  const dirplan = [
    (p2_plan[0] - p1_plan[0]) / dplan,
    (p2_plan[1] - p1_plan[1]) / dplan
  ];

  // Rotation angle (in Z plane, X-Y plane)
  const angle3d = Math.atan2(dir3d[1], dir3d[0]);
  const angleplan = Math.atan2(dirplan[1], dirplan[0]);
  const rotation = angleplan - angle3d;
  const rotation_deg = rotation * 180 / Math.PI;

  // Offset: plan point minus transformed 3D point
  const cos_r = Math.cos(rotation);
  const sin_r = Math.sin(rotation);
  const p1_transformed = [
    (p1_3d[0] * cos_r - p1_3d[1] * sin_r) * scale,
    (p1_3d[0] * sin_r + p1_3d[1] * cos_r) * scale,
    p1_3d[2]
  ];

  const offset = [
    p1_plan[0] - p1_transformed[0],
    p1_plan[1] - p1_transformed[1],
    0 // z offset can be set separately
  ];

  return { scale, rotation_deg, offset };
};

// === Helpers ===

function esc(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Find which room contains a point
function pointInRoom(x, y, layout) {
  const currentFloor = layout.floors?.[0]?.id || '0';
  const rooms = layout.rooms?.filter(r => r.floor === currentFloor) || [];

  for (const room of rooms) {
    if (FS.space3D?.pointInPolygon && room.polygon) {
      if (FS.space3D.pointInPolygon([x, y], room.polygon)) {
        return room.id;
      }
    }
  }

  return 'unknown';
}

// === State Reducer ===

// Pure reducer function for layout state transitions
function spaceReduce(layout, action) {
  if (!layout) layout = { floors: [], rooms: [], placements: [], scale: 1, origin: [0, 0], updated_at: 0 };

  switch (action.type) {
    case 'ADD_ROOM': {
      const newRoom = {
        id: action.roomId || 'room-' + Date.now(),
        name: action.name || 'New Room',
        floor: action.floor || '0',
        polygon: action.polygon || [],
        ceiling_m: action.ceiling_m || 2.6
      };
      return { ...layout, rooms: [...layout.rooms, newRoom], updated_at: Date.now() / 1000 };
    }

    case 'UPDATE_ROOM': {
      return {
        ...layout,
        rooms: layout.rooms.map(r => r.id === action.roomId ? { ...r, ...action.data } : r),
        updated_at: Date.now() / 1000
      };
    }

    case 'DELETE_ROOM': {
      return { ...layout, rooms: layout.rooms.filter(r => r.id !== action.roomId), updated_at: Date.now() / 1000 };
    }

    case 'ADD_FLOOR': {
      const newFloor = {
        id: action.floorId || 'floor-' + Date.now(),
        name: action.name || 'New Floor',
        elevation_m: action.elevation_m || 0
      };
      return { ...layout, floors: [...layout.floors, newFloor], updated_at: Date.now() / 1000 };
    }

    case 'UPDATE_FLOOR': {
      return {
        ...layout,
        floors: layout.floors.map(f => f.id === action.floorId ? { ...f, ...action.data } : f),
        updated_at: Date.now() / 1000
      };
    }

    case 'DELETE_FLOOR': {
      return {
        ...layout,
        floors: layout.floors.filter(f => f.id !== action.floorId),
        rooms: layout.rooms.filter(r => r.floor !== action.floorId),
        updated_at: Date.now() / 1000
      };
    }

    case 'UPDATE_TRANSFORM': {
      return {
        ...layout,
        scan: { ...layout.scan, transform: { ...layout.scan?.transform, ...action.data } },
        updated_at: Date.now() / 1000
      };
    }

    case 'SCALE_COORDINATES': {
      const factor = action.factor || 1;
      return {
        ...layout,
        rooms: layout.rooms.map(r => ({
          ...r,
          polygon: r.polygon.map(pt => [pt[0] * factor, pt[1] * factor])
        })),
        updated_at: Date.now() / 1000
      };
    }

    default:
      return layout;
  }
}

// Export FS.space and add format parsers
if (!FS.space) {
  FS.space = {};
}

// Export the reducer
FS.space.reduce = spaceReduce;

// GLB parser: handles glTF 2.0 binary format
FS.space.parseGLB = function(arrayBuffer) {
  const view = new DataView(arrayBuffer);

  // Read header (20 bytes)
  const magic = view.getUint32(0, true);
  if (magic !== 0x46546c67) { // 'glTF'
    throw new Error('Invalid GLB magic');
  }

  const version = view.getUint32(4, true);
  if (version !== 2) {
    throw new Error('Unsupported GLB version: ' + version);
  }

  const totalLength = view.getUint32(8, true);

  // Parse chunks
  let offset = 12;
  let jsonData = null;
  let binData = null;

  while (offset < totalLength) {
    const chunkLength = view.getUint32(offset, true);
    const chunkType = view.getUint32(offset + 4, true);
    const chunkStart = offset + 8;

    if (chunkType === 0x4e4f534a) { // 'JSON'
      const jsonBytes = new Uint8Array(arrayBuffer, chunkStart, chunkLength);
      const jsonStr = new TextDecoder().decode(jsonBytes);
      jsonData = JSON.parse(jsonStr);
    } else if (chunkType === 0x004e4942) { // 'BIN\0'
      binData = new ArrayBuffer(chunkLength);
      const binView = new Uint8Array(binData);
      const srcView = new Uint8Array(arrayBuffer, chunkStart, chunkLength);
      binView.set(srcView);
    }

    offset += 8 + chunkLength;
  }

  if (!jsonData || !binData) {
    throw new Error('Missing JSON or BIN chunk');
  }

  // Parse the glTF structure
  return parseGltfData(jsonData, binData);
};

function parseGltfData(json, binData) {
  const result = {
    vertices: 0,
    triangles: 0,
    positions: [],
    normals: [],
    indices: [],
    meshes: [],
    materials: json.materials || [],
    texture: null
  };

  // Helper: read accessor data
  function getAccessor(accessorIdx) {
    if (!json.accessors || !json.accessors[accessorIdx]) return null;
    const acc = json.accessors[accessorIdx];
    const bufView = json.bufferViews[acc.bufferView];
    const offset = (bufView.byteOffset || 0) + (acc.byteOffset || 0);

    const TypedArray = {
      5120: Int8Array,    // BYTE
      5121: Uint8Array,   // UNSIGNED_BYTE
      5122: Int16Array,   // SHORT
      5123: Uint16Array,  // UNSIGNED_SHORT
      5125: Uint32Array,  // UNSIGNED_INT
      5126: Float32Array  // FLOAT
    }[acc.componentType];

    const componentCount = { SCALAR: 1, VEC2: 2, VEC3: 3, VEC4: 4, MAT2: 4, MAT3: 9, MAT4: 16 }[acc.type];
    const count = acc.count;
    const data = new TypedArray(binData, offset, count * componentCount);

    return { data, count, componentCount };
  }

  // Parse meshes
  if (json.meshes) {
    json.meshes.forEach((mesh, meshIdx) => {
      const meshData = {
        primitives: [],
        positions: new Float32Array(0),
        normals: new Float32Array(0),
        indices: new Uint32Array(0),
        triangles: 0
      };

      if (mesh.primitives) {
        mesh.primitives.forEach(prim => {
          const posAccessor = getAccessor(prim.attributes.POSITION);
          const posData = posAccessor.data;

          let normals = null;
          if (prim.attributes.NORMAL !== undefined) {
            const normAccessor = getAccessor(prim.attributes.NORMAL);
            normals = normAccessor.data;
          }

          let indices = null;
          let indexCount = 0;
          if (prim.indices !== undefined) {
            const idxAccessor = getAccessor(prim.indices);
            indices = new Uint32Array(idxAccessor.data);
            indexCount = idxAccessor.count;
          } else {
            indexCount = posAccessor.count;
          }

          meshData.primitives.push({
            positions: posData,
            normals: normals,
            indices: indices,
            indexCount: indexCount
          });

          result.vertices += posAccessor.count;
          result.triangles += Math.floor(indexCount / 3);
          meshData.triangles += Math.floor(indexCount / 3);
        });
      }

      result.meshes.push(meshData);
    });
  }

  return result;
}

// OBJ parser
FS.space.parseOBJ = function(text) {
  const lines = text.split('\n');
  const positions = [];
  const normals = [];
  const indices = [];
  const vertices = new Map(); // "x,y,z" -> index
  let vertexCount = 0;

  lines.forEach(line => {
    const parts = line.trim().split(/\s+/);
    if (parts.length === 0 || parts[0].startsWith('#')) return;

    if (parts[0] === 'v') {
      positions.push(parseFloat(parts[1]), parseFloat(parts[2]), parseFloat(parts[3]));
    } else if (parts[0] === 'vn') {
      normals.push(parseFloat(parts[1]), parseFloat(parts[2]), parseFloat(parts[3]));
    } else if (parts[0] === 'f') {
      // Parse face (triangulate quads)
      const faceIndices = [];
      for (let i = 1; i < parts.length; i++) {
        const vertexStr = parts[i];
        const refs = vertexStr.split('/');
        const posIdx = parseInt(refs[0]) - 1; // OBJ uses 1-based indexing

        const key = posIdx.toString();
        let outIdx = vertices.get(key);
        if (outIdx === undefined) {
          outIdx = vertexCount++;
          vertices.set(key, outIdx);
        }
        faceIndices.push(outIdx);
      }

      // Triangulate if needed
      for (let i = 1; i < faceIndices.length - 1; i++) {
        indices.push(faceIndices[0], faceIndices[i], faceIndices[i + 1]);
      }
    }
  });

  return {
    vertices: vertexCount,
    triangles: Math.floor(indices.length / 3),
    positions: new Float32Array(positions),
    normals: normals.length > 0 ? new Float32Array(normals) : null,
    indices: new Uint32Array(indices)
  };
};

// PLY parser (ASCII and binary little-endian)
FS.space.parsePLY = function(data) {
  let text = data;
  if (data instanceof ArrayBuffer) {
    text = new TextDecoder().decode(new Uint8Array(data));
  }

  const lines = text.split('\n');
  let headerEnd = 0;
  let format = 'ascii';
  let vertexCount = 0;
  let vertexProps = [];

  // Parse header
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === 'end_header') {
      headerEnd = i + 1;
      break;
    }
    if (line.startsWith('format ')) {
      format = line.split(/\s+/)[1];
    } else if (line.startsWith('element vertex ')) {
      vertexCount = parseInt(line.split(/\s+/)[2]);
    } else if (line.startsWith('property ')) {
      const parts = line.split(/\s+/);
      vertexProps.push({ type: parts[1], name: parts[2] });
    }
  }

  if (format === 'ascii' || format.startsWith('binary_little_endian')) {
    return parsePLYAscii(lines.slice(headerEnd), vertexCount, vertexProps);
  } else {
    throw new Error('Unsupported PLY format: ' + format);
  }
};

function parsePLYAscii(dataLines, vertexCount, vertexProps) {
  const positions = [];
  const normals = [];

  for (let i = 0; i < vertexCount && i < dataLines.length; i++) {
    const parts = dataLines[i].trim().split(/\s+/);

    if (vertexProps.length >= 3) {
      // Assume first 3 are x, y, z
      positions.push(parseFloat(parts[0]), parseFloat(parts[1]), parseFloat(parts[2]));

      // Look for normals
      if (vertexProps.length >= 6 && vertexProps[3].name === 'nx') {
        normals.push(parseFloat(parts[3]), parseFloat(parts[4]), parseFloat(parts[5]));
      }
    }
  }

  return {
    vertices: Math.floor(positions.length / 3),
    triangles: 0,
    positions: new Float32Array(positions),
    normals: normals.length > 0 ? new Float32Array(normals) : null,
    indices: new Uint32Array([])
  };
}

// RoomPlan JSON parser: convert to extruded boxes
FS.space.parseRoomPlan = function(json) {
  if (typeof json === 'string') {
    json = JSON.parse(json);
  }

  const positions = [];
  const indices = [];
  let vertexCount = 0;

  // Create extruded boxes for each object
  if (json.objects && Array.isArray(json.objects)) {
    json.objects.forEach(obj => {
      const w = (obj.dimensions?.width || 1000) / 1000;
      const d = (obj.dimensions?.depth || 1000) / 1000;
      const h = (obj.dimensions?.height || 2000) / 1000;
      const x = (obj.center?.x || 0) / 1000;
      const y = (obj.center?.y || 0) / 1000;
      const z = (obj.center?.z || 0) / 1000;

      const ox = x - w / 2, ox2 = x + w / 2;
      const oy = y - d / 2, oy2 = y + d / 2;
      const oz = z, oz2 = z + h;

      const boxVerts = [
        ox, oy, oz,   ox2, oy, oz,  ox2, oy2, oz, ox, oy2, oz,  // bottom
        ox, oy, oz2,  ox2, oy, oz2, ox2, oy2, oz2, ox, oy2, oz2 // top
      ];

      const base = vertexCount;
      positions.push(...boxVerts);
      vertexCount += 8;

      const boxIndices = [
        base, base+1, base+2, base, base+2, base+3,         // bottom
        base+4, base+6, base+5, base+4, base+7, base+6,     // top
        base, base+4, base+5, base, base+5, base+1,         // front
        base+2, base+6, base+7, base+2, base+7, base+3,     // back
        base+1, base+5, base+6, base+1, base+6, base+2,     // right
        base+3, base+7, base+4, base+3, base+4, base+0      // left
      ];

      indices.push(...boxIndices);
    });
  }

  return {
    vertices: vertexCount,
    triangles: Math.floor(indices.length / 3),
    positions: new Float32Array(positions),
    normals: null,
    indices: new Uint32Array(indices)
  };
};

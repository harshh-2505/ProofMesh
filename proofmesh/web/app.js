/* ProofMesh attack lab front end. No framework, no build step: the server's
   Content-Security-Policy only allows this file, so everything lives here. */
'use strict';

(() => {
  const SVGNS = 'http://www.w3.org/2000/svg';
  const $ = (sel, root = document) => root.querySelector(sel);
  const root = document.documentElement;

  const STATUS = {
    VERIFIED: { label: 'Verified', rank: 0 },
    TAINTED: { label: 'Tainted', rank: 1 },
    ERASED: { label: 'Erased', rank: 2 },
    TAMPERED: { label: 'Tampered', rank: 3 },
    INVALID: { label: 'Invalid', rank: 4 },
  };
  const ICON = {
    check: 'M5 12.5l4.5 4.5L19 7',
    cross: 'M6 6l12 12M18 6 6 18',
    arrow: 'M4 12h15M13 6l6 6-6 6',
    bang: 'M12 6v8M12 18h.01',
  };
  const PRESETS = {
    edit: ['edit'],
    'rewrite-manifest': ['rewrite-manifest'],
    'trust-root': ['trust-root'],
    'stolen-key': ['stolen-key'],
  };

  const state = {
    catalog: [],
    picked: new Map(),
    baseline: null,
    snap: null,
    sel: null,
    tab: 'merkle',
    proof: null,
    busy: false,
    vertical: null,
  };

  // ------------------------------------------------------------- helpers

  function setAttrs(node, attrs) {
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'text') node.textContent = v;
      else if (k === 'html') node.innerHTML = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else if (k === 'style' && typeof v === 'object') {
        for (const [p, val] of Object.entries(v)) node.style.setProperty(p, val);
      } else node.setAttribute(k, v === true ? '' : v);
    }
  }
  function add(node, kids) {
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      node.append(kid instanceof Node ? kid : String(kid));
    }
    return node;
  }
  const el = (tag, attrs, ...kids) => { const n = document.createElement(tag); setAttrs(n, attrs); return add(n, kids); };
  const sv = (tag, attrs, ...kids) => { const n = document.createElementNS(SVGNS, tag); setAttrs(n, attrs); return add(n, kids); };
  const icon = (name, cls) => sv('svg', { viewBox: '0 0 24 24', class: cls, 'aria-hidden': 'true' }, sv('path', { d: ICON[name] }));
  const short = (h, n = 12) => (h ? `${h.slice(0, n)}…` : '');
  const fmt = (n) => Number(n).toLocaleString('en-US');
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const worst = (nodes) => nodes.slice().sort((a, b) => STATUS[b.status].rank - STATUS[a.status].rank)[0];
  const shortName = (pid) => (pid || '').split('.').slice(1).join('.') || pid || '';
  const domainOf = (pid) => (pid || '').split('.')[0];

  async function api(path, opts) {
    const res = await fetch(path, opts);
    const type = res.headers.get('content-type') || '';
    const body = type.includes('json') ? await res.json() : await res.text();
    if (!res.ok) {
      const d = body && body.detail;
      throw new Error(typeof d === 'string' ? d : res.status === 413 ? 'That file is too large for the lab.' : `Request failed (${res.status})`);
    }
    return body;
  }

  let toastTimer;
  function toast(msg) {
    const t = $('#toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 4200);
  }

  // ---------------------------------------------------------------- theme

  function initTheme() {
    try {
      const saved = localStorage.getItem('pm-theme');
      if (saved === 'light' || saved === 'dark') root.dataset.theme = saved;
    } catch (e) { /* storage unavailable */ }
    $('#theme-toggle').addEventListener('click', () => {
      const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
      root.dataset.theme = dark ? 'light' : 'dark';
      try { localStorage.setItem('pm-theme', root.dataset.theme); } catch (e) { /* ignore */ }
    });
  }

  // ------------------------------------------------- guilloche engraving

  function guilloche() {
    const svg = sv('svg', { class: 'guilloche', viewBox: '-320 -320 640 640', 'aria-hidden': 'true' });
    const band = (base, amp, lobes, copies, wobble, steps) => {
      for (let i = 0; i < copies; i++) {
        const phase = (i / copies) * (Math.PI * 2) / lobes * 2;
        let d = '';
        for (let s = 0; s <= steps; s++) {
          const t = (s / steps) * Math.PI * 2;
          const r = base + amp * Math.sin(lobes * t + phase) + wobble * Math.sin(3 * t + i * 0.4);
          d += `${s ? 'L' : 'M'}${(r * Math.cos(t)).toFixed(1)} ${(r * Math.sin(t)).toFixed(1)}`;
        }
        svg.append(sv('path', { d: `${d}Z` }));
      }
    };
    band(262, 20, 36, 14, 4, 540);
    band(196, 26, 24, 12, 6, 480);
    band(128, 22, 15, 10, 3, 360);
    band(72, 26, 9, 8, 2, 240);
    $('.hero').prepend(svg);
  }

  // ------------------------------------------------------------ hashprints

  /** Draw a Merkle root as an engraved ring of 64 bars, one per hex digit. */
  function buildRing() {
    const ring = $('#hero-ring');
    ring.append(sv('circle', { class: 'rim', cx: 120, cy: 120, r: 118.5 }));
    ring.append(sv('circle', { class: 'tick', cx: 120, cy: 120, r: 111, 'stroke-dasharray': '1.2 4.6' }));
    for (let i = 0; i < 64; i++) {
      const angle = (i / 64) * 360;
      ring.append(sv('g', { transform: `rotate(${angle} 120 120)` },
        sv('rect', { class: 'bar', x: 118.4, y: 120 - 62 - 42, width: 3.2, height: 42, rx: 1.4, fill: 'var(--core)', style: { transform: 'scaleY(0.15)' } })));
    }
  }

  function paintRing(hex, compareTo) {
    const bars = document.querySelectorAll('#hero-ring .bar');
    bars.forEach((bar, i) => {
      const v = parseInt((hex || '0'.repeat(64))[i] || '0', 16);
      bar.style.transform = `scaleY(${(0.18 + (v / 15) * 0.82).toFixed(3)})`;
      const differs = compareTo && compareTo[i] !== hex[i];
      bar.setAttribute('fill', differs ? 'var(--tamper)' : 'var(--core)');
    });
  }

  /** A small colour hashprint: each hex digit becomes a bar whose hue and length encode its value. */
  function miniPrint(hex, status, label) {
    const svg = sv('svg', { viewBox: '0 0 100 100', class: `mini t-${status || 'ERASED'}`, role: 'img', 'aria-label': label || `Hashprint of ${hex || 'unknown root'}` });
    svg.append(sv('circle', { cx: 50, cy: 50, r: 48, fill: 'var(--panel-solid)', stroke: 'var(--line-strong)' }));
    const h = hex || '';
    for (let i = 0; i < 64; i++) {
      const v = parseInt(h[i] || '0', 16);
      const a = (i / 64) * Math.PI * 2 - Math.PI / 2;
      const r1 = 21;
      const r2 = r1 + 6 + (v / 15) * 19;
      svg.append(sv('line', {
        x1: (50 + r1 * Math.cos(a)).toFixed(2), y1: (50 + r1 * Math.sin(a)).toFixed(2),
        x2: (50 + r2 * Math.cos(a)).toFixed(2), y2: (50 + r2 * Math.sin(a)).toFixed(2),
        'stroke-width': 2.3, 'stroke-linecap': 'round',
        style: { stroke: h ? `hsl(${Math.round(v * 22.5)} 82% var(--hp-l, 55%))` : 'var(--line-strong)' },
      }));
    }
    svg.append(sv('circle', { cx: 50, cy: 50, r: 13, fill: 'currentColor' }));
    return svg;
  }

  // ----------------------------------------------------------------- hero

  function renderHero(snap) {
    const seal = $('#hero-seal');
    const nodes = snap.graph.nodes;
    const fin = nodes.find((n) => n.product_id === 'finance.transactions' && n.version === 1) || nodes[0];
    const bad = snap.ok ? null : worst(nodes);
    const target = bad && bad.status !== 'VERIFIED' ? bad : fin;
    const rep = snap.reports[target.id];
    const signed = (rep && rep.content && rep.content.expected_root) || target.merkle_root;
    const actual = (rep && rep.content && rep.content.actual_root) || signed;
    seal.dataset.state = 'loading';
    void seal.offsetWidth; // restart the crack and shake animations
    $('.seal-product', seal).textContent = `${target.product_id} v${target.version}`;
    if (snap.ok) {
      seal.dataset.state = 'ok';
      $('#hero-label').textContent = 'Seal intact';
      $('#hero-root').textContent = short(signed, 16);
      paintRing(signed);
      $('#hero-caption').textContent = `All ${nodes.length} products verified. The ring is finance.transactions' Merkle root drawn as a hashprint; any edit redraws it.`;
    } else {
      seal.dataset.state = 'broken';
      $('#hero-label').textContent = 'Seal broken';
      $('#hero-root').textContent = short(actual, 16);
      paintRing(actual, actual !== signed ? signed : null);
      $('#hero-caption').textContent = `${target.product_id}: ${target.summary.split(';')[0]}`;
    }
  }

  // ---------------------------------------------------------------- bench

  function renderBench() {
    const list = $('#attacks');
    list.replaceChildren();
    state.catalog.forEach((a) => {
      const cb = el('input', { type: 'checkbox', id: `atk-${a.id}`, 'aria-describedby': `atk-${a.id}-sum` });
      const params = a.params.length
        ? el('div', { class: 'params' },
          a.params.includes('txn') && el('label', {}, 'Transaction', el('input', { type: 'text', 'data-param': 'txn', placeholder: 'TX-001337', inputmode: 'text', maxlength: 12, spellcheck: 'false' })),
          a.params.includes('amount') && el('label', {}, 'New amount', el('input', { type: 'number', 'data-param': 'amount', placeholder: 'auto', step: '0.01' })))
        : null;
      const li = el('li', { class: 'attack', 'data-id': a.id },
        cb,
        el('span', { class: 'box', 'aria-hidden': 'true' }, icon('check')),
        el('label', { for: `atk-${a.id}`, class: 'attack-title' }, a.title, el('span', { class: 'attack-who' }, a.attacker)),
        el('p', { class: 'attack-sum', id: `atk-${a.id}-sum` }, a.summary),
        params);
      li.addEventListener('click', (ev) => {
        if (ev.target.closest('.params') || ev.target === cb) return;
        if (ev.target.closest('label.attack-title')) return; // the label toggles the checkbox itself
        cb.checked = !cb.checked;
        cb.dispatchEvent(new Event('change'));
      });
      cb.addEventListener('change', () => toggle(a.id, cb.checked));
      list.append(li);
    });
    syncBench();
  }

  function toggle(id, on) {
    if (on && state.picked.size >= 8) {
      toast('The lab runs at most 8 attacks at once.');
      $(`#atk-${id}`).checked = false;
      return;
    }
    if (on) state.picked.set(id, true); else state.picked.delete(id);
    syncBench();
  }

  function syncBench() {
    document.querySelectorAll('.attack').forEach((li) => {
      const on = state.picked.has(li.dataset.id);
      li.classList.toggle('on', on);
      $('input[type="checkbox"]', li).checked = on;
    });
    const n = state.picked.size;
    $('#bench-count').textContent = `${n} selected`;
    const btn = $('#run-btn');
    btn.disabled = n === 0 || state.busy;
    btn.textContent = state.busy ? 'Verifying…' : n > 1 ? `Run ${n} attacks` : 'Run attack';
    document.querySelectorAll('[data-preset]').forEach((b) => {
      const ids = PRESETS[b.dataset.preset];
      b.setAttribute('aria-pressed', String(n === ids.length && ids.every((i) => state.picked.has(i))));
    });
  }

  function attackSpecs() {
    return [...state.picked.keys()].map((id) => {
      const li = $(`.attack[data-id="${id}"]`);
      const params = {};
      li.querySelectorAll('[data-param]').forEach((inp) => { if (inp.value.trim()) params[inp.dataset.param] = inp.value.trim(); });
      return { id, params };
    });
  }

  async function run(specs) {
    if (state.busy) return;
    state.busy = true;
    syncBench();
    $('#run-btn').classList.add('running');
    $('#scan').classList.add('on');
    $('#verdict-title').textContent = specs.length ? 'Running attacks, then verifying every product…' : 'Verifying the mesh…';
    try {
      const [snap] = await Promise.all([
        api('/api/lab/run', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ attacks: specs }) }),
        sleep(specs.length ? 650 : 0),
      ]);
      if (!specs.length) state.baseline = snap;
      show(snap, true);
    } catch (err) {
      toast(err.message);
      $('#verdict-title').textContent = 'The lab could not run. Try again in a moment.';
    } finally {
      state.busy = false;
      $('#run-btn').classList.remove('running');
      $('#scan').classList.remove('on');
      syncBench();
    }
  }

  // ------------------------------------------------------------- verdict

  function show(snap, fresh) {
    state.snap = snap;
    state.proof = null;
    if (fresh) {
      const pick = snap.ok
        ? snap.graph.nodes.find((n) => n.product_id === 'finance.transactions') || snap.graph.nodes[0]
        : worst(snap.graph.nodes);
      state.sel = pick.id;
      state.tab = { TAMPERED: 'merkle', INVALID: 'checks', ERASED: 'checks', TAINTED: 'impact' }[pick.status] || 'merkle';
    }
    renderVerdict(snap);
    renderApplied(snap);
    renderGraph();
    renderInspector();
    renderHero(snap);
    renderLedger(snap);
  }

  function renderVerdict(snap) {
    const c = snap.counts;
    const total = Object.values(c).reduce((a, b) => a + b, 0);
    const bar = $('#verdict-bar');
    bar.dataset.ok = String(snap.ok);
    const title = $('#verdict-title');
    if (snap.ok) {
      title.textContent = snap.applied.length
        ? 'Nothing detected. Every product still verifies.'
        : `Mesh intact. All ${total} products verify against the pinned authority.`;
    } else {
      const parts = [];
      if (c.TAMPERED) parts.push(`${c.TAMPERED} tampered`);
      if (c.INVALID) parts.push(`${c.INVALID} invalid`);
      if (c.ERASED) parts.push(`${c.ERASED} erased`);
      if (c.TAINTED) parts.push(`${c.TAINTED} tainted downstream`);
      if (!snap.event_log.ok) parts.push('audit log broken');
      if (!snap.trust.ok) parts.push('trust root replaced');
      title.textContent = `Caught: ${parts.join(', ')}.`;
    }
    const sub = el('div', { class: 'verdict-sub' },
      `Verified in ${snap.elapsed_ms} ms with transformation replay on, against pinned authority key ${snap.trust.pinned_key_id || snap.trust.authority_key_id}.`);
    const pills = $('#counts');
    pills.replaceChildren(
      ...Object.keys(STATUS).filter((s) => c[s]).map((s) => el('span', { class: 'pill' }, el('i', { class: `dot ${s}` }), `${c[s]} ${STATUS[s].label.toLowerCase()}`)),
      el('span', { class: `pill ${snap.event_log.ok ? 'good' : 'bad'}` }, snap.event_log.ok ? `audit log intact, ${snap.event_log.entries} entries` : 'audit log broken'),
      el('span', { class: `pill ${snap.trust.ok ? 'good' : 'bad'}` }, snap.trust.ok ? 'trust anchor matches' : 'trust anchor mismatch'),
    );
    const old = $('.verdict-sub', bar);
    if (old) old.remove();
    title.after(sub);
  }

  function renderApplied(snap) {
    const list = $('#applied');
    list.hidden = !snap.applied.length;
    list.replaceChildren(...snap.applied.map((a, i) => el('li', { style: { 'animation-delay': `${i * 80}ms` } },
      el('span', { class: 'num' }, String(i + 1)),
      el('div', { class: 'eff' }, el('b', {}, `${a.title}. `), a.effect),
      el('div', { class: `caught${snap.ok ? ' missed' : ''}` }, icon(snap.ok ? 'cross' : 'check'),
        snap.ok ? 'Not detected' : `Caught by ${a.defence.charAt(0).toLowerCase()}${a.defence.slice(1)}`))));
  }

  // --------------------------------------------------------------- graph

  function layout(nodes, edges, vertical) {
    const byId = new Map(nodes.map((n) => [n.id, { ...n, parents: [] }]));
    const es = edges.filter((e) => byId.has(e.source) && byId.has(e.target));
    es.forEach((e) => byId.get(e.target).parents.push(e.source));
    const depth = new Map();
    const d = (id) => {
      if (depth.has(id)) return depth.get(id);
      depth.set(id, 0);
      const v = Math.max(0, ...byId.get(id).parents.map((p) => d(p) + 1));
      depth.set(id, v);
      return v;
    };
    const cols = [];
    for (const n of byId.values()) { n.depth = d(n.id); (cols[n.depth] = cols[n.depth] || []).push(n); }
    const order = new Map();
    cols.forEach((col, k) => {
      col.forEach((n) => {
        n.bc = k === 0 || !n.parents.length ? 0 : n.parents.reduce((s, p) => s + order.get(p), 0) / n.parents.length;
      });
      col.sort((a, b) => a.bc - b.bc || a.product_id.localeCompare(b.product_id) || a.version - b.version);
      col.forEach((n, i) => order.set(n.id, i));
    });
    const W = vertical ? 156 : 196;
    const H = vertical ? 76 : 82;
    const gapMain = vertical ? 58 : 64;
    const gapCross = vertical ? 12 : 22;
    const most = Math.max(...cols.map((c) => c.length));
    const span = most * (vertical ? W : H) + (most - 1) * gapCross;
    cols.forEach((col, k) => {
      const len = col.length * (vertical ? W : H) + (col.length - 1) * gapCross;
      const start = (span - len) / 2;
      col.forEach((n, i) => {
        const cross = start + i * ((vertical ? W : H) + gapCross);
        const main = k * ((vertical ? H : W) + gapMain);
        n.x = vertical ? cross : main;
        n.y = vertical ? main : cross;
      });
    });
    const width = vertical ? span : cols.length * W + (cols.length - 1) * gapMain;
    const height = vertical ? cols.length * H + (cols.length - 1) * gapMain : span;
    return { nodes: [...byId.values()], edges: es, byId, W, H, width, height };
  }

  function renderGraph() {
    const snap = state.snap;
    if (!snap) return;
    const wrap = $('#graph-wrap');
    const vertical = wrap.clientWidth < 600;
    state.vertical = vertical;
    wrap.classList.toggle('vertical', vertical);
    const L = layout(snap.graph.nodes, snap.graph.edges, vertical);
    const pad = 14;
    const svg = $('#graph');
    svg.setAttribute('viewBox', `${-pad} ${-pad} ${L.width + pad * 2} ${L.height + pad * 2}`);
    svg.replaceChildren();
    const edgeLayer = sv('g', {});
    const nodeLayer = sv('g', {});
    const hot = new Set(['TAMPERED', 'INVALID', 'TAINTED', 'ERASED']);
    for (const e of L.edges) {
      const a = L.byId.get(e.source);
      const b = L.byId.get(e.target);
      let x1, y1, x2, y2, dpath;
      if (vertical) {
        x1 = a.x + L.W / 2; y1 = a.y + L.H; x2 = b.x + L.W / 2; y2 = b.y;
        const m = (y2 - y1) / 2;
        dpath = `M${x1} ${y1} C${x1} ${y1 + m} ${x2} ${y2 - m} ${x2} ${y2}`;
      } else {
        x1 = a.x + L.W; y1 = a.y + L.H / 2; x2 = b.x; y2 = b.y + L.H / 2;
        const m = (x2 - x1) / 2;
        dpath = `M${x1} ${y1} C${x1 + m} ${y1} ${x2 - m} ${y2} ${x2} ${y2}`;
      }
      const cls = ['g-edge'];
      if (hot.has(a.status) && b.status !== 'VERIFIED') cls.push('hot');
      if (a.status === 'ERASED' || b.status === 'ERASED') cls.push('ghost');
      edgeLayer.append(sv('path', { d: dpath, class: cls.join(' ') },
        e.transformation ? sv('title', {}, `${e.transformation} for ${e.purpose}`) : null));
    }
    for (const n of L.nodes) {
      const g = sv('g', {
        class: `g-node ${n.status}${n.id === state.sel ? ' sel' : ''}`,
        transform: `translate(${n.x} ${n.y})`,
        tabindex: 0,
        role: 'button',
        'aria-label': `${n.product_id} version ${n.version}: ${STATUS[n.status].label}`,
        style: { '--d': n.depth },
      });
      const inner = sv('g', { class: 'reveal' });
      inner.append(
        sv('rect', { class: 'pulse', x: 0, y: 0, width: L.W, height: L.H, rx: 14 }),
        sv('rect', { class: 'halo', x: -5, y: -5, width: L.W + 10, height: L.H + 10, rx: 18 }),
        sv('rect', { class: 'card', x: 0, y: 0, width: L.W, height: L.H, rx: 14 }),
        sv('rect', { class: 'band', x: 0, y: 14, width: 4, height: L.H - 28, rx: 2 }),
      );
      const name = shortName(n.product_id);
      const maxChars = vertical ? 16 : 17;
      inner.append(
        sv('text', { class: 'title', x: 16, y: 26 }, name.length > maxChars ? `${name.slice(0, maxChars - 1)}…` : name),
        sv('text', { class: 'meta', x: 16, y: 44 }, `${domainOf(n.product_id)} · v${n.version}`),
        sv('text', { class: 'stat', x: 16, y: L.H - 14 }, STATUS[n.status].label.toUpperCase()),
      );
      if (!vertical) {
        const mp = miniPrint(n.merkle_root, n.status);
        setAttrs(mp, { x: L.W - 46, y: (L.H - 36) / 2, width: 36, height: 36 });
        inner.append(mp);
      }
      inner.append(sv('title', {}, `${n.product_id} v${n.version}: ${n.summary}`));
      g.append(inner);
      const pick = () => select(n.id, true);
      g.addEventListener('click', pick);
      g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pick(); } });
      nodeLayer.append(g);
    }
    svg.append(edgeLayer, nodeLayer);
  }

  function select(id, fromUser) {
    state.sel = id;
    state.proof = null;
    document.querySelectorAll('.g-node').forEach((g) => g.classList.remove('sel'));
    renderGraph();
    renderInspector();
    if (fromUser) {
      const box = $('#inspector').getBoundingClientRect();
      if (box.top > window.innerHeight - 160) $('#inspector').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  // ----------------------------------------------------------- inspector

  function renderInspector() {
    const snap = state.snap;
    const node = snap.graph.nodes.find((n) => n.id === state.sel);
    if (!node) return;
    const rep = snap.reports[node.id];
    const mf = snap.manifests[node.id];
    $('#insp-owner').textContent = `${node.owner_domain} · version ${node.version}${node.latest ? ' · latest' : ''}`;
    $('#insp-title').textContent = node.name || node.product_id;
    $('#insp-summary').textContent = `${node.product_id}: ${node.summary}`;
    const tag = $('#insp-status');
    tag.className = `status-tag ${node.status}`;
    tag.textContent = STATUS[node.status].label.toUpperCase();
    $('#insp-seal').replaceChildren(miniPrint(node.merkle_root, node.status));
    document.querySelectorAll('.tabs [role="tab"]').forEach((t) => {
      const on = t.id === `tab-${state.tab}`;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
    });
    const panels = { merkle: merklePanel, checks: checksPanel, impact: impactPanel, manifest: manifestPanel };
    for (const [key, fn] of Object.entries(panels)) {
      const p = $(`#panel-${key}`);
      p.hidden = key !== state.tab;
      if (!p.hidden) p.replaceChildren(...[fn(node, rep, mf)].flat());
    }
  }

  function initTabs() {
    const tabs = [...document.querySelectorAll('.tabs [role="tab"]')];
    tabs.forEach((t, i) => {
      t.addEventListener('click', () => { state.tab = t.id.slice(4); renderInspector(); });
      t.addEventListener('keydown', (ev) => {
        const step = ev.key === 'ArrowRight' ? 1 : ev.key === 'ArrowLeft' ? -1 : 0;
        if (!step) return;
        const next = tabs[(i + step + tabs.length) % tabs.length];
        state.tab = next.id.slice(4);
        renderInspector();
        next.focus();
      });
    });
  }

  const empty = (text) => el('p', { class: 'empty' }, text);

  // RFC 6962 tree shape: split at the largest power of two below n.
  function buildTree(lo, hi, depth) {
    if (hi - lo === 1) return { lo, hi, depth, leaf: true };
    let k = 1;
    while (k * 2 < hi - lo) k *= 2;
    return { lo, hi, depth, left: buildTree(lo, lo + k, depth + 1), right: buildTree(lo + k, hi, depth + 1) };
  }

  function hexDiff(a, b) {
    const span = el('span', { class: 'hex' });
    for (let i = 0; i < a.length; i++) span.append(b && a[i] !== b[i] ? el('span', { class: 'd' }, a[i]) : a[i]);
    return span;
  }

  function merklePanel(node, rep, mf) {
    if (!mf) {
      return [empty(`This version is gone from the registry, so there is no chunk list to rebuild its tree from. The audit log still holds the root it was published with: ${node.merkle_root || 'unknown'}.`)];
    }
    const chunks = mf.content.chunks;
    const n = chunks.length;
    const content = (rep && rep.content) || {};
    const changed = new Map((content.tampered_chunks || []).map((c) => [c.index, c]));
    const tree = buildTree(0, n, 0);
    const proof = state.proof && state.proof.id === node.id ? state.proof : null;
    let maxDepth = 0;
    const walk = (t, fn, parent) => { fn(t, parent); if (!t.leaf) { walk(t.left, fn, t); walk(t.right, fn, t); } };
    walk(tree, (t) => { maxDepth = Math.max(maxDepth, t.depth); });

    const leafW = Math.min(64, 1000 / n);
    const width = Math.max(leafW * n, 240);
    const offset = (width - leafW * n) / 2;
    const levelH = n > 1 ? 46 : 0;
    const top = 30;
    const leafY = top + (n > 1 ? maxDepth * levelH + 18 : 26);
    const leafH = 26;
    const isBad = (t) => { for (const i of changed.keys()) if (i >= t.lo && i < t.hi) return true; return false; };
    const pathTo = (t) => proof && proof.index >= t.lo && proof.index < t.hi;
    walk(tree, (t, parent) => {
      t.x = t.leaf ? offset + (t.lo + 0.5) * leafW : null;
      t.bad = isBad(t);
      t.checked = !t.bad && (!parent || parent.bad);
      t.onPath = pathTo(t);
      t.sib = !!(proof && parent && parent.onPath && !t.onPath);
    });
    const place = (t) => { if (t.leaf) return t.x; t.x = (place(t.left) + place(t.right)) / 2; return t.x; };
    place(tree);
    const yOf = (t) => (t.leaf ? leafY : top + t.depth * levelH);

    const svg = sv('svg', { class: 'merkle', viewBox: `0 0 ${width} ${leafY + leafH + 22}`, role: 'img', 'aria-label': `Merkle tree over ${n} chunks` });
    const links = sv('g', {});
    const dots = sv('g', {});
    walk(tree, (t, parent) => {
      if (parent) {
        const cls = t.bad ? 'm-link bad' : t.onPath || t.sib ? 'm-link path' : 'm-link';
        links.append(sv('line', { class: cls, x1: parent.x, y1: yOf(parent), x2: t.x, y2: yOf(t) }));
      }
      if (t.leaf) {
        const c = chunks[t.lo];
        const ch = changed.get(t.lo);
        let cls = 'm-leaf';
        if (ch) cls += ch.problem === 'missing' ? ' missing' : ' bad';
        else if (proof && t.onPath) cls += ' target';
        else if (t.sib) cls += ' sib';
        const rect = sv('rect', { class: cls, x: t.x - leafW / 2 + 1, y: leafY, width: Math.max(leafW - 2, 2), height: leafH, rx: Math.min(4, leafW / 4), tabindex: 0, role: 'button', 'aria-label': `Chunk ${t.lo}` },
          sv('title', {}, `Chunk #${t.lo}: ${fmt(c.size)} bytes at offset ${fmt(c.offset)}\n${c.id}${ch ? `\n${ch.problem.toUpperCase()}${ch.lines ? `, lines ${fmt(ch.lines[0])}–${fmt(ch.lines[1])}` : ''}` : '\nclick for its inclusion proof'}`));
        const ask = () => loadProof(node, t.lo);
        rect.addEventListener('click', ask);
        rect.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); ask(); } });
        dots.append(rect);
        if (leafW >= 16 || t.lo % 5 === 0) dots.append(sv('text', { class: 'm-idx', x: t.x, y: leafY + leafH + 13 }, String(t.lo)));
      } else {
        let cls = 'm-node';
        if (t.bad) cls += ' bad';
        else if (t.sib) cls += ' sib';
        else if (t.onPath) cls += ' path';
        else if (t.checked && changed.size) cls += ' checked';
        if (t.depth === 0) cls += ' root';
        dots.append(sv('circle', { class: cls, cx: t.x, cy: yOf(t), r: t.depth === 0 ? 8 : 5.5 }));
      }
    });
    const rootLabel = sv('text', { class: 'm-rootlabel', x: tree.x + 14, y: top + 4 }, `signed root ${short(content.expected_root || mf.content.merkle_root, 16)}`);
    svg.append(links, dots, rootLabel);

    const out = [el('div', { class: 'merkle-wrap' }, svg)];
    out.push(el('ul', { class: 'merkle-legend' },
      el('li', {}, el('i', { style: { background: 'color-mix(in oklab, var(--ok) 35%, var(--panel-solid))' } }), 'Chunk matches its signed hash'),
      el('li', {}, el('i', { style: { background: 'var(--tamper)' } }), 'Altered or missing chunk, and the path it breaks'),
      el('li', {}, el('i', { style: { border: '2px solid var(--ok)', background: 'transparent' } }), 'Subtree compared and pruned'),
      el('li', {}, el('i', { style: { background: 'var(--accent)' } }), 'Inclusion-proof siblings')));

    const loc = content.localization;
    if (changed.size && loc) {
      const first = [...changed.values()][0];
      out.push(el('p', { class: 'note' },
        el('strong', {}, `${changed.size} of ${n} chunks ${first.problem === 'missing' ? 'missing' : 'altered'}. `),
        `Walking down from the root and only descending where hashes disagree found ${changed.size === 1 ? 'it' : 'them'} in ${loc.comparisons} comparisons instead of ${n}.`,
        first.lines ? ` The damage sits in bytes ${fmt(first.offset)}–${fmt(first.offset + first.size - 1)}, lines ${fmt(first.lines[0])}–${fmt(first.lines[1])}.` : ''));
    } else {
      out.push(el('p', { class: 'note' }, `All ${n} chunk${n === 1 ? '' : 's'} re-hash to the values in the signed manifest. Click a chunk to fetch its inclusion proof.`));
    }
    if (content.expected_root) {
      const differs = content.actual_root !== content.expected_root;
      out.push(el('div', { class: 'roots' },
        el('div', { class: 'root-card' }, miniPrint(content.expected_root, 'VERIFIED', 'Signed root hashprint'),
          el('div', {}, el('h4', {}, 'Signed root'), el('span', { class: 'hex' }, content.expected_root))),
        el('div', { class: 'root-card' }, miniPrint(content.actual_root, differs ? 'TAMPERED' : 'VERIFIED', 'Recomputed root hashprint'),
          el('div', {}, el('h4', {}, differs ? 'Recomputed root: mismatch' : 'Recomputed root: match'), hexDiff(content.actual_root, differs ? content.expected_root : null)))));
    }
    if (proof) {
      const p = proof.data;
      out.push(el('div', { class: 'proof-box' },
        el('strong', {}, `Inclusion proof for chunk #${p.chunk.index} `), `(${fmt(p.chunk.size)} bytes). `,
        `Hashing the chunk with these ${p.proof.length} siblings, bottom to top, rebuilds the signed root. `,
        el('strong', { class: p.verified ? 't-VERIFIED' : 't-TAMPERED' }, p.verified ? 'Verified.' : 'Does not verify.'),
        el('ol', {}, ...p.proof.map((h) => el('li', {}, h)))));
    }
    return out;
  }

  async function loadProof(node, index) {
    try {
      const p = await api(`/api/lab/proof/${encodeURIComponent(node.product_id)}/${index}`);
      if (p.manifest_id !== node.id) {
        toast('Proofs come from the pristine published data, and this version only exists in your attacked sandbox.');
        return;
      }
      state.proof = { id: node.id, index, data: p };
      renderInspector();
    } catch (err) { toast(err.message); }
  }

  function checksPanel(node, rep) {
    if (!rep) {
      return [empty(`There is no manifest left to check. ${node.summary.charAt(0).toUpperCase()}${node.summary.slice(1)}, which is how ProofMesh knows it existed and which reports depended on it.`)];
    }
    return el('ul', { class: 'checks' }, ...rep.checks.map((c) => {
      const cls = c.ok ? '' : c.severity === 'warning' ? 'warn' : 'fail';
      return el('li', { class: cls },
        el('span', { class: 'ico' }, icon(c.ok ? 'check' : c.severity === 'warning' ? 'bang' : 'cross')),
        el('span', { class: 'name' }, c.name),
        el('span', { class: 'detail' }, c.detail));
    }));
  }

  function chain(path, srcFirst, via) {
    const hops = [];
    path.forEach((p, i) => {
      if (i) hops.push(icon('arrow', 'arrow'));
      hops.push(el('span', { class: `hop${(srcFirst ? i === 0 : i === path.length - 1) ? ' src' : ''}` }, p));
    });
    return el('div', { class: 'chain-path' }, ...hops, via ? el('span', { class: 'via' }, via) : null);
  }

  function impactPanel(node, rep) {
    const out = [];
    if (!rep) {
      const kids = state.snap.graph.edges.filter((e) => e.source === node.id).length;
      return [empty(`This report was erased, but the audit log still records it${kids ? ' and its inputs' : ''}. Restoring it from a backup and re-verifying would bring it back.`)];
    }
    const tc = (rep.content && rep.content.tampered_chunks) || [];
    if (tc.length) {
      out.push(el('section', { class: 'impact' }, el('h4', {}, 'What changed'),
        el('ul', { class: 'chunk-list' }, ...tc.map((c) => el('li', {},
          el('strong', {}, `Chunk #${c.index} ${c.problem}. `),
          `Bytes ${fmt(c.offset)}–${fmt(c.offset + c.size - 1)}`,
          c.lines ? `, lines ${fmt(c.lines[0])}–${fmt(c.lines[1])}` : '',
          c.actual_id ? `. Now hashes to ${short(c.actual_id, 16)} instead of ${short(c.id, 16)}.` : '.')))));
    }
    if (rep.affected_downstream.length) {
      out.push(el('section', { class: 'impact' },
        el('h4', {}, `Every product built on this one (${rep.affected_downstream.length})`),
        ...rep.affected_downstream.map((d) => chain(d.path, true, `${d.transformation || 'derived'} for ${d.purpose || 'unspecified purpose'}`))));
    }
    if (rep.compromised_ancestors.length) {
      out.push(el('section', { class: 'impact' },
        el('h4', {}, 'Compromised sources it inherited from'),
        ...rep.compromised_ancestors.map((a) => chain([`${node.product_id}@${node.version}`, ...a.path.slice(1)], false, `${a.product_id} is ${a.status.toLowerCase()}`))));
    }
    if (rep.newer_version) {
      out.push(el('p', { class: 'note' }, `A newer version exists: v${rep.newer_version.version || ''}.`));
    }
    if (!out.length) {
      out.push(empty(node.status === 'VERIFIED'
        ? (rep.affected_downstream.length ? '' : 'Nothing is wrong with this product and no compromised data flows into it.')
        : 'No downstream products depend on this version.'));
    }
    if (rep.affected_downstream.length && node.status === 'VERIFIED') {
      out.unshift(el('p', { class: 'note' }, 'This product verifies. If it ever stopped verifying, these are the products that would inherit the problem:'));
    }
    return out;
  }

  function highlightJSON(obj) {
    const esc = JSON.stringify(obj, null, 2).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return esc.replace(/("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g, (m) => {
      let cls = 'n';
      if (m[0] === '"') cls = m.trimEnd().endsWith(':') ? 'k' : 's';
      else if (/^(true|false|null)$/.test(m)) cls = 'b';
      return `<span class="${cls}">${m}</span>`;
    });
  }

  function manifestPanel(node, rep, mf) {
    if (!mf) return [empty('The manifest for this version was deleted from the registry.')];
    const c = mf.content;
    const t = mf.lineage.transformation;
    const fields = [
      ['Manifest id', short(mf.manifest_id, 24)],
      ['Signed by', `${mf.signer.domain}, key ${mf.signer.key_id}`],
      ['Signed at', mf.created_at],
      ['Log anchor', mf.log_anchor ? `entry #${mf.log_anchor.seq}, ${short(mf.log_anchor.entry_hash, 10)}` : 'none'],
      ['Merkle root', short(c.merkle_root, 24)],
      ['Content', `${fmt(c.size)} bytes in ${c.chunk_count} chunks`],
      ['Chunking', `${c.chunking.algorithm} ${c.chunking.min_size}/${c.chunking.avg_size}/${c.chunking.max_size}`],
      ['Permitted purposes', mf.contract.permitted_purposes.join(', ')],
      ['Readers', mf.contract.readers.join(', ')],
      ['Writers', mf.contract.writers.join(', ')],
    ];
    if (t) fields.push(['Transformation', `${t.name} by ${t.executed_by} for ${t.purpose}`], ['Code hash', short(t.code_hash, 24)]);
    if (mf.lineage.inputs.length) fields.push(['Inputs', mf.lineage.inputs.map((i) => `${i.product_id}@${i.version}`).join(', ')]);
    const view = JSON.parse(JSON.stringify(mf));
    const more = view.content.chunks.length - 4;
    if (more > 0) view.content.chunks = [...view.content.chunks.slice(0, 4), `… ${more} more chunks`];
    return [
      el('dl', { class: 'mf-grid' }, ...fields.map(([k, v]) => el('div', {}, el('dt', {}, k), el('dd', {}, v)))),
      el('pre', { class: 'json', tabindex: 0, 'aria-label': 'Manifest JSON', html: highlightJSON(view) }),
    ];
  }

  // -------------------------------------------------------------- ledger

  function renderLedger(snap) {
    const log = snap.event_log;
    const bad = new Set(log.bad_seqs);
    const cp = log.checkpoint || {};
    const list = $('#chain');
    const blocks = [];
    let prevBad = false;
    snap.events.forEach((e, i) => {
      const cls = ['block'];
      if (bad.has(e.seq)) cls.push('bad');
      else if (prevBad) cls.push('after-bad');
      if (cp.seq === e.seq) cls.push('cp');
      prevBad = bad.has(e.seq);
      const what = e.payload.product_id || e.payload.domain || e.payload.name || '';
      blocks.push(el('li', { class: cls.join(' '), style: { '--i': i } },
        el('div', { class: 'seq' }, el('span', {}, `#${e.seq}`), el('span', {}, bad.has(e.seq) ? 'BROKEN' : cp.seq === e.seq ? 'CHECKPOINT' : '')),
        el('div', { class: 'kind' }, e.kind, what ? el('span', { class: 'who' }, ` ${what}`) : null),
        el('div', { class: 'who' }, `by ${e.actor}, key ${(e.key_id || '').slice(0, 8)}`),
        el('div', { class: 'hash' }, short(e.entry_hash, 18))));
    });
    const last = snap.events.length ? snap.events[snap.events.length - 1].seq : 0;
    if (cp.seq && !cp.ok && last < cp.seq) {
      for (let s = last + 1; s <= cp.seq; s++) {
        blocks.push(el('li', { class: 'block ghost' },
          el('div', { class: 'seq' }, el('span', {}, `#${s}`), el('span', {}, 'MISSING')),
          el('div', { class: 'kind' }, 'deleted entry'),
          el('div', { class: 'who' }, `still covered by checkpoint #${cp.seq}`)));
      }
    }
    list.replaceChildren(...blocks);
    const status = $('#ledger-status');
    const old = $('.ledger-problems');
    if (old) old.remove();
    if (log.ok) {
      status.textContent = `Chain intact: ${log.entries} entries, each signed by the department that acted and committing to the one before it. Head ${short(log.head, 12)} still contains the authority-signed checkpoint #${cp.seq}.`;
    } else {
      status.textContent = `Chain broken. ${log.problems.length} problem${log.problems.length === 1 ? '' : 's'} found:`;
      status.after(el('ul', { class: 'ledger-problems' }, ...log.problems.slice(0, 6).map((p) => el('li', {}, p))));
      const firstBad = list.querySelector('.bad, .ghost');
      if (firstBad) {
        const wrap = $('.chain-wrap');
        wrap.scrollTo({ left: Math.max(0, firstBad.offsetLeft - 40), behavior: 'smooth' });
      }
    }
  }

  // --------------------------------------------------------------- tools

  function charDiff(a, b) {
    let s = 0;
    while (s < a.length && s < b.length && a[s] === b[s]) s++;
    let e = 0;
    while (e < a.length - s && e < b.length - s && a[a.length - 1 - e] === b[b.length - 1 - e]) e++;
    return el('span', {}, b.slice(0, s), el('mark', {}, b.slice(s, b.length - e) || ' '), b.slice(b.length - e));
  }

  function wireDrop(labelSel, inputSel, handler) {
    const label = $(labelSel);
    const input = $(inputSel);
    input.addEventListener('change', () => { if (input.files[0]) handler(input.files[0]); input.value = ''; });
    ['dragenter', 'dragover'].forEach((t) => label.addEventListener(t, (ev) => { ev.preventDefault(); label.classList.add('over'); }));
    ['dragleave', 'drop'].forEach((t) => label.addEventListener(t, () => label.classList.remove('over')));
    label.addEventListener('drop', (ev) => {
      ev.preventDefault();
      const f = ev.dataTransfer && ev.dataTransfer.files[0];
      if (f) handler(f);
    });
  }

  async function checkCopy(file) {
    const out = $('#copy-out');
    out.replaceChildren(el('div', { class: 'result' }, `Re-chunking ${file.name}…`));
    try {
      const r = await api('/api/lab/verify-copy/finance.transactions', { method: 'POST', headers: { 'content-type': 'text/csv' }, body: await file.arrayBuffer() });
      if (r.matches) {
        out.replaceChildren(el('div', { class: 'result good' },
          el('h4', {}, 'Identical to what Finance signed'),
          el('div', {}, `${fmt(r.size)} bytes re-chunked into exactly the signed chunks, reproducing root `, el('span', { class: 'mono' }, short(r.actual_root, 16)), '.')));
        return;
      }
      const lines = r.changed_lines || [];
      out.replaceChildren(el('div', { class: 'result bad' },
        el('h4', {}, 'This copy is not what Finance signed'),
        el('div', {}, 'Recomputed root ', el('span', { class: 'mono' }, short(r.actual_root, 12)), ' does not match the signed ', el('span', { class: 'mono' }, short(r.expected_root, 12)), '.'),
        el('ul', {},
          r.size !== r.expected_size ? el('li', {}, `Size is ${fmt(r.size)} bytes, the signed file has ${fmt(r.expected_size)}.`) : null,
          el('li', {}, `${r.unexpected_regions.length === 1 ? '1 region of your file never appears' : `${r.unexpected_regions.length} regions of your file never appear`} in the signed chunk set, and ${r.missing_chunks.length === 1 ? '1 signed chunk is' : `${r.missing_chunks.length} signed chunks are`} missing from it.`)),
        lines.length ? el('div', { class: 'diff' }, ...lines.slice(0, 5).map((l) => el('div', {},
          el('div', { class: 'ln' }, `line ${fmt(l.line)}`),
          el('div', { class: 'minus' }, `signed:   ${l.expected}`),
          el('div', { class: 'plus' }, 'received: ', charDiff(l.expected, l.received))))) : null));
    } catch (err) {
      out.replaceChildren(el('div', { class: 'result bad' }, err.message));
    }
  }

  async function checkBundle(file) {
    const out = $('#bundle-out');
    out.replaceChildren(el('div', { class: 'result' }, `Checking ${file.name}…`));
    try {
      const r = await api('/api/lab/verify-bundle', { method: 'POST', headers: { 'content-type': 'application/json' }, body: await file.text() });
      out.replaceChildren(el('div', { class: `result ${r.ok ? 'good' : 'bad'}` },
        el('h4', {}, r.ok ? 'Evidence verified offline' : `Evidence rejected: ${r.status.toLowerCase()}`),
        el('div', {}, `${r.manifests.length} signed manifest${r.manifests.length === 1 ? '' : 's'} checked against authority key ${r.authority_key_id}.`),
        el('ul', {}, ...r.manifests.map((m) => el('li', {},
          el('i', { class: `dot ${m.status}` }), ` ${m.product_id}@${m.version}: ${STATUS[m.status] ? STATUS[m.status].label.toLowerCase() : m.status}`,
          m.problems.length ? el('div', { class: 'detail' }, m.problems.join('; ')) : null)))));
    } catch (err) {
      out.replaceChildren(el('div', { class: 'result bad' }, err.message));
    }
  }

  function initTools() {
    wireDrop('#copy-drop', '#copy-file', checkCopy);
    wireDrop('#bundle-drop', '#bundle-file', checkBundle);
    $('#policy-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const consumer = $('#pol-consumer').value;
      const purpose = $('#pol-purpose').value;
      const out = $('#policy-out');
      try {
        const r = await api(`/api/lab/policy?${new URLSearchParams({ consumer, purpose })}`);
        out.replaceChildren(el('div', { class: `result ${r.allowed ? 'good' : 'bad'}` },
          el('h4', {}, r.allowed ? 'Allowed' : 'Refused'),
          r.allowed
            ? el('div', {}, `${consumer} may derive from ${r.source} for ${purpose}. The output inherits Finance's purposes: ${r.permitted_purposes.join(', ')}.`)
            : el('ul', {}, ...r.reasons.map((x) => el('li', {}, x)))));
      } catch (err) { toast(err.message); }
    });
  }

  function renderThreats() {
    $('#threat-table tbody').replaceChildren(...state.catalog.map((a) => el('tr', {},
      el('td', {}, a.title), el('td', {}, a.attacker), el('td', {}, a.defence))));
    $('#fact-attacks').textContent = `${state.catalog.length} / ${state.catalog.length}`;
  }

  // ---------------------------------------------------------------- boot

  async function boot() {
    initTheme();
    guilloche();
    buildRing();
    initTabs();
    initTools();
    $('#run-btn').addEventListener('click', () => run(attackSpecs()));
    $('#reset-btn').addEventListener('click', () => {
      state.picked.clear();
      syncBench();
      if (state.baseline) show(state.baseline, true); else run([]);
    });
    document.querySelectorAll('[data-preset]').forEach((b) => b.addEventListener('click', () => {
      state.picked = new Map(PRESETS[b.dataset.preset].map((id) => [id, true]));
      syncBench();
      run(attackSpecs());
    }));
    let resizeTimer;
    new ResizeObserver(() => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        const vertical = $('#graph-wrap').clientWidth < 600;
        if (state.snap && vertical !== state.vertical) renderGraph();
      }, 120);
    }).observe($('#graph-wrap'));

    try {
      const cat = await api('/api/lab/catalog');
      state.catalog = cat.attacks;
      renderBench();
      renderThreats();
    } catch (err) {
      toast(err.message);
    }
    await run([]);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();

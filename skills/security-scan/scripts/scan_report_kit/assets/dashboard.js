// scan-report-kit dashboard runtime. Reads the JSON payload written by
// report.render_dashboard (docs/format.md) and builds the page with DOM APIs
// only: report text is always set as textContent, never parsed as HTML.
(function () {
  'use strict';
  var D = JSON.parse(document.getElementById('data').textContent), L = D.labels, ALL = D.findings;
  var F = ALL.filter(function (f) { return !f.excluded; }), SEV = D.order.severity, ST = D.order.status;
  var expanded = new Set();
  var idOrder = new Intl.Collator(document.documentElement.lang || 'en', { numeric: true });

  function el(t, a, txt) {
    var e = document.createElement(t);
    if (a) Object.keys(a).forEach(function (k) { e.setAttribute(k, a[k]); });
    if (txt != null) e.textContent = txt;
    return e;
  }
  function byId(id) { return document.getElementById(id); }
  function fmt(text, values) {
    return text.replace(/\{(\w+)\}/g, function (token, key) {
      return Object.prototype.hasOwnProperty.call(values, key) ? values[key] : token;
    });
  }
  function badge(f) { return el('span', { 'class': 'badge ' + f.severity }, f.severity); }
  function statusText(f) { return f.status + (f.excluded ? ' · ' + L.excluded_short : ''); }
  function count(fs, key) {
    var c = Object.create(null);
    fs.forEach(function (f) { var k = f[key] || L.none; c[k] = (c[k] || 0) + 1; });
    return c;
  }
  function listInto(box, items, empty) {
    if (!items.length) { box.appendChild(el('p', { 'class': 'muted' }, empty)); return; }
    var ul = el('ul');
    items.forEach(function (x) { ul.appendChild(el('li', null, x)); });
    box.appendChild(ul);
  }
  function rank(f) { return [Number(f.status !== 'Open'), SEV.indexOf(f.severity)]; }
  function byPriority(a, b) { var x = rank(a), y = rank(b); return x[0] - y[0] || x[1] - y[1]; }

  document.title = L.dashboard_title + ' - ' + D.meta.project;
  byId('h').textContent = D.meta.project;
  byId('meta').textContent = [D.meta.date, D.meta.assessor].filter(Boolean).join(' · ');
  document.querySelectorAll('[data-l]').forEach(function (e) { e.textContent = L[e.getAttribute('data-l')]; });
  byId('theme').onclick = function () {
    var root = document.documentElement;
    var dark = root.dataset.theme ? root.dataset.theme === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
  };

  var summary = byId('summary');
  summary.appendChild(el('strong', null, D.headline));
  if (D.summary) summary.appendChild(el('p', null, D.summary));

  var open = F.filter(function (f) { return f.status === 'Open'; });
  var urgent = open.filter(function (f) { return f.severity === 'High' || f.severity === 'Medium'; }).length;
  var closed = F.length - open.length;
  [[L.urgent, urgent, urgent ? 'urgent' : '', L.open_total + ': ' + open.length],
   [L.open_total, open.length, '', L.included + ': ' + F.length],
   [L.closed_total, closed, '', ''],
   [L.excluded_count, ALL.length - F.length, '', '']].forEach(function (c) {
    var d = el('div', { 'class': 'card' + (c[2] ? ' ' + c[2] : '') });
    d.appendChild(el('span', { 'class': 'l' }, c[0]));
    d.appendChild(el('div', { 'class': 'n' }, String(c[1])));
    if (c[3]) d.appendChild(el('div', { 'class': 'sub' }, c[3]));
    byId('cards').appendChild(d);
  });

  var TOP = 6, queue = open.slice().sort(byPriority);
  queue.slice(0, TOP).forEach(function (f) {
    var item = el('article', { 'class': 'panel priority-item sev-' + f.severity }), top = el('div', { 'class': 'priority-top' });
    top.appendChild(badge(f));
    top.appendChild(el('span', { 'class': 'verdict' }, [f.confidence, f.verdict].filter(Boolean).join(' · ')));
    item.appendChild(top);
    var h = el('h3'), a = el('a', { href: '#' + f.anchor }, f.id + ' · ' + f.title);
    h.appendChild(a);
    item.appendChild(h);
    if (f.location) item.appendChild(el('span', { 'class': 'location' }, f.location));
    if (f.action) {
      var act = el('p', { 'class': 'action' });
      act.appendChild(el('span', { 'class': 'action-label' }, f.action.label));
      if (f.action.text) act.appendChild(document.createTextNode(' ' + f.action.text));
      item.appendChild(act);
    }
    byId('priority').appendChild(item);
  });
  if (!queue.length) byId('priority').appendChild(el('div', { 'class': 'panel muted' }, L.no_open));
  byId('queue-note').textContent = queue.length > TOP ? fmt(L.queue_more, { shown: TOP, total: queue.length }) : '';

  ['scope', 'method', 'commit'].forEach(function (k) {
    byId('scope-meta').appendChild(el('dt', null, L[k]));
    byId('scope-meta').appendChild(el('dd', null, D.meta[k] || L.not_recorded));
  });
  byId('coverage-count').textContent = L.limitations + ': ' + D.limitations.length;
  listInto(byId('limitations'), D.limitations, L.limitations_empty);
  if (!D.perspectives.length) byId('perspectives').appendChild(el('p', { 'class': 'muted' }, L.coverage_missing));
  D.perspectives.forEach(function (p) {
    var box = el('div', { 'class': 'perspective' });
    box.appendChild(el('strong', null, p.name));
    box.appendChild(el('p', null, p.result || L.not_recorded));
    if (p.note) box.appendChild(el('p', { 'class': 'muted' }, p.note));
    byId('perspectives').appendChild(box);
  });

  function bars(id, key, order, colored) {
    var c = count(F, key), keys = order || Object.keys(c).sort(function (a, b) { return c[b] - c[a] || a.localeCompare(b); });
    var max = keys.reduce(function (n, k) { return Math.max(n, c[k] || 0); }, 1);
    keys.forEach(function (k) {
      var row = el('div', { 'class': 'bar' }), track = el('div', { 'class': 'track' });
      var fill = el('div', { 'class': 'fill' + (colored ? ' ' + k : '') });
      fill.style.width = ((c[k] || 0) / max * 100) + '%';
      if (colored) fill.style.background = 'currentColor';
      track.appendChild(fill);
      row.appendChild(el('span', { 'class': 't' }, k));
      row.appendChild(track);
      row.appendChild(el('span', { 'class': 'v' }, String(c[k] || 0)));
      byId(id).appendChild(row);
    });
  }
  bars('c-sev', 'severity', SEV, true);
  bars('c-cat', 'category');
  bars('c-status', 'status', ST);

  function opts(id, vals, first) {
    var s = byId(id);
    if (first != null) s.appendChild(el('option', { value: '' }, first));
    vals.forEach(function (v) {
      var pair = Array.isArray(v) ? v : [v, v];
      s.appendChild(el('option', { value: pair[0] }, pair[1]));
    });
    s.onchange = draw;
  }
  opts('f-scope', [['included', L.included_set], ['excluded', L.excluded_set], ['all', L.all_records]]);
  opts('f-sev', SEV, L.all);
  opts('f-status', ST, L.all);
  opts('f-cat', Object.keys(count(ALL.filter(function (f) { return f.category; }), 'category')).sort(), L.all);
  opts('f-sort', [['priority', L.sort_priority], ['id', L.sort_id]]);
  // Large registers redraw once typing pauses instead of on every keystroke.
  var q = byId('f-q'), searchTimer = null;
  q.placeholder = L.search;
  q.oninput = function () { clearTimeout(searchTimer); if (ALL.length > 300) searchTimer = setTimeout(draw, 150); else draw(); };
  function v(id) { return byId(id).value; }
  function reset() {
    ['f-sev', 'f-status', 'f-cat'].forEach(function (id) { byId(id).value = ''; });
    byId('f-scope').value = 'included';
    byId('f-sort').value = 'priority';
    q.value = '';
  }
  byId('reset').onclick = function () { reset(); draw(); };

  // A code fence longer than any backtick run in the text it wraps.
  function fence(text) {
    var runs = String(text).match(/`+/g) || [];
    var n = runs.reduce(function (longest, run) { return Math.max(longest, run.length); }, 2) + 1;
    return Array(n + 1).join('`');
  }
  function oneLine(x) { return String(x).replace(/\s*[\r\n]+\s*/g, ' '); }
  function findingMarkdown(f) {
    var out = ['## ' + oneLine(f.id) + ' · ' + oneLine(f.title), ''];
    function p(label, value) { if (value) out.push('- ' + label + ': ' + oneLine(value)); }
    function block(label, value) { if (value) { var fc = fence(value); out.push('', '### ' + oneLine(label), fc + 'text', value, fc); } }
    p(L.severity, f.severity); p(L.status, statusText(f)); p(L.confidence, f.confidence); p(L.verdict, f.verdict);
    p(L.category, f.category); p(L.location, f.location);
    if (f.action && f.status === 'Open' && !f.excluded) block(f.action.label, f.action.text);
    (f.fields || []).forEach(function (x) { block(x.label, x.text); });
    if (f.snippet) {
      var lines = f.snippet.lines.map(function (text, i) {
        var n = f.snippet.start + i;
        return (n >= f.snippet.hit[0] && n <= f.snippet.hit[1] ? '>' : ' ') + String(n).padStart(5, ' ') + ' ' + text;
      }).join('\n');
      block(L.snippet, lines);
    }
    if ((f.references || []).length) {
      out.push('', '### ' + L.references);
      f.references.forEach(function (r) { out.push('- [' + oneLine(r.type || L.source) + '] ' + oneLine(r.title || r.url) + ' <' + r.url + '>'); });
    }
    return out.join('\n') + '\n';
  }
  // A denied or unavailable Clipboard API falls back to the selection copy.
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text).catch(function () { return copyFallback(text); });
    return copyFallback(text);
  }
  function copyFallback(text) {
    return new Promise(function (resolve, reject) {
      var prev = document.activeElement, t = el('textarea', { readonly: '', 'aria-hidden': 'true', style: 'position:fixed;top:0;left:-9999px' });
      t.value = text;
      document.body.appendChild(t);
      t.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(t);
      if (prev && prev.focus) prev.focus();
      if (ok) resolve(); else reject(new Error('copy'));
    });
  }
  function copyButton(f) {
    var b = el('button', { type: 'button', 'class': 'copy-finding', 'aria-live': 'polite' }, L.copy_llm), timer;
    b.onclick = function (e) {
      e.stopPropagation();
      function done(label) { b.textContent = label; clearTimeout(timer); timer = setTimeout(function () { b.textContent = L.copy_llm; }, 2000); }
      copyText(findingMarkdown(f)).then(function () { done(L.copied); }, function () { done(L.copy_failed); });
    };
    return b;
  }

  // Detail content is built on first expansion: a large register would
  // otherwise build every record's full detail tree on each redraw.
  function details(f) {
    var dt = el('tr', { 'class': 'detail', id: f.anchor + '-detail', role: 'row' });
    dt.hidden = !expanded.has(f.anchor);
    if (!dt.hidden) fillDetails(dt, f);
    return dt;
  }
  function fillDetails(dt, f) {
    if (dt.firstChild) return;
    var td = el('td', { colspan: 7, role: 'cell' }), dl = el('dl');
    var head = el('div', { 'class': 'detail-actions' }), links = el('span', { 'class': 'detail-links' });
    head.appendChild(el('strong', null, f.id + ' · ' + f.title));
    links.appendChild(copyButton(f));
    links.appendChild(el('a', { href: '#' + f.anchor }, L.link));
    head.appendChild(links);
    td.appendChild(head);
    if (f.action && f.status === 'Open' && !f.excluded) {
      var guidance = el('div', { 'class': 'action-guidance' });
      guidance.appendChild(el('strong', null, f.action.label));
      if (f.action.text) guidance.appendChild(el('p', null, f.action.text));
      td.appendChild(guidance);
    }
    function field(label, value) {
      dl.appendChild(el('dt', null, label));
      var dd = el('dd');
      if (value instanceof Node) dd.appendChild(value); else dd.textContent = value;
      dl.appendChild(dd);
    }
    field(L.location, f.location || L.not_recorded);
    (f.fields || []).forEach(function (x) { field(x.label, x.text || L.not_recorded); });
    if (f.snippet) {
      var pre = el('pre', { 'class': 'snippet' });
      f.snippet.lines.forEach(function (text, i) {
        var n = f.snippet.start + i, ln = el('span', { 'class': n >= f.snippet.hit[0] && n <= f.snippet.hit[1] ? 'hit' : '' });
        ln.appendChild(el('b', null, String(n).padStart(5, ' ') + ' '));
        ln.appendChild(document.createTextNode(text));
        pre.appendChild(ln);
      });
      field(L.snippet, pre);
    }
    if ((f.references || []).length) {
      var ul = el('ul', { 'class': 'refs' });
      f.references.forEach(function (r) {
        var li = el('li');
        li.appendChild(el('span', { 'class': 'rt' }, r.type || L.source));
        li.appendChild(el('a', { href: r.url, rel: 'noopener noreferrer' }, r.title || r.url));
        ul.appendChild(li);
      });
      field(L.references, ul);
    }
    td.appendChild(dl);
    dt.appendChild(td);
  }

  var searchCache = new Map();
  function searchText(f) {
    if (searchCache.has(f)) return searchCache.get(f);
    var parts = [f.id, f.title, f.location, f.category, statusText(f), f.severity, f.confidence, f.verdict];
    if (f.action) parts.push(f.action.label, f.action.text);
    (f.fields || []).forEach(function (x) { parts.push(x.label, x.text); });
    if (f.snippet) parts.push(f.snippet.lines.join('\n'));
    (f.references || []).forEach(function (r) { parts.push(r.type, r.title, r.url); });
    var text = parts.filter(Boolean).join('\n').toLowerCase();
    searchCache.set(f, text);
    return text;
  }
  function draw() {
    clearTimeout(searchTimer);
    var tb = byId('rows'), term = q.value.trim().toLowerCase(), scope = v('f-scope');
    tb.textContent = '';
    var pool = scope === 'all' ? ALL : ALL.filter(function (f) { return scope === 'excluded' ? f.excluded : !f.excluded; });
    var shown = pool.filter(function (f) {
      return (!v('f-sev') || f.severity === v('f-sev')) && (!v('f-status') || f.status === v('f-status'))
        && (!v('f-cat') || f.category === v('f-cat')) && (!term || searchText(f).indexOf(term) >= 0);
    });
    if (v('f-sort') === 'priority') shown.sort(byPriority);
    else shown.sort(function (a, b) { return idOrder.compare(a.id, b.id); });
    byId('result-count').textContent = fmt(L.showing, { shown: shown.length, total: pool.length });
    if (!shown.length) {
      var empty = el('tr', { role: 'row' });
      empty.appendChild(el('td', { colspan: 7, 'class': 'empty', role: 'cell' }, pool.length ? L.no_matches : L.no_records));
      tb.appendChild(empty);
      return;
    }
    shown.forEach(function (f) {
      var tr = el('tr', { 'class': 'row', id: f.anchor, role: 'row' }), dt = details(f), button;
      var labels = ['ID', L.severity, L.confidence, L.status, L.verdict, L.title_col, L.category];
      var values = [f.id, null, f.confidence || L.none, statusText(f), f.verdict || L.none, null, f.category || L.none];
      values.forEach(function (value, i) {
        var cell = el('td', { 'data-label': labels[i], role: 'cell' }, value);
        if (i === 1) cell.appendChild(badge(f));
        if (i === 5) {
          button = el('button', { type: 'button', 'class': 'finding-toggle', 'aria-expanded': String(!dt.hidden), 'aria-controls': f.anchor + '-detail' });
          button.appendChild(document.createTextNode(f.title));
          button.appendChild(el('span', { 'class': 'toggle-label' }, dt.hidden ? L.show_details : L.hide_details));
          cell.appendChild(button);
          if (f.location) cell.appendChild(el('span', { 'class': 'location' }, f.location));
        }
        tr.appendChild(cell);
      });
      function toggle() {
        if (dt.hidden) fillDetails(dt, f);
        dt.hidden = !dt.hidden;
        if (dt.hidden) expanded.delete(f.anchor); else expanded.add(f.anchor);
        button.setAttribute('aria-expanded', String(!dt.hidden));
        button.querySelector('.toggle-label').textContent = dt.hidden ? L.show_details : L.hide_details;
      }
      button.onclick = function (e) { e.stopPropagation(); toggle(); };
      tr.onclick = function (e) { if (!e.target.closest('a,button')) toggle(); };
      tb.appendChild(tr);
      tb.appendChild(dt);
    });
  }
  function openHash() {
    var anchor;
    try { anchor = decodeURIComponent(window.location.hash.slice(1)); } catch (e) { return; }
    var f = ALL.find(function (x) { return x.anchor === anchor; });
    if (!f) return;
    expanded.add(anchor);
    draw();
    if (!byId(anchor)) {
      reset();
      if (f.excluded) byId('f-scope').value = 'excluded';
      draw();
    }
    var row = byId(anchor);
    if (row) {
      row.querySelector('.finding-toggle').focus({ preventScroll: true });
      row.scrollIntoView();
    }
  }
  document.addEventListener('click', function (e) {
    var a = e.target.closest('a[href^="#finding-"]');
    if (a && a.getAttribute('href') === window.location.hash) { e.preventDefault(); openHash(); }
  });
  window.addEventListener('hashchange', openHash);
  draw();
  if (window.location.hash) openHash();

  ['decisions', 'next_steps', 'checked_ok'].forEach(function (k) {
    var p = el('section', { 'class': 'panel' });
    p.appendChild(el('h2', null, L[k]));
    listInto(p, D[k], L.not_recorded);
    byId('lists').appendChild(p);
  });
})();

/* Shared site behaviour: theme toggle and client-side search.
   Progressive enhancement only. Every page reads correctly with this file blocked. */
(function () {
  'use strict';

  /* ---------- theme ---------- */
  var KEY = 'src101-docs-theme';
  var root = document.documentElement;

  function label(mode) {
    return mode === 'dark' ? 'Light' : 'Dark';
  }

  function currentMode() {
    var set = root.getAttribute('data-theme');
    if (set === 'dark' || set === 'light') return set;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function wireTheme() {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.hidden = false;

    function paint() {
      var next = currentMode() === 'dark' ? 'light' : 'dark';
      btn.textContent = label(currentMode());
      btn.setAttribute('aria-label', 'Switch to ' + next + ' theme');
    }

    paint();
    btn.addEventListener('click', function () {
      var next = currentMode() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem(KEY, next); } catch (e) { /* storage unavailable */ }
      paint();
    });

    if (window.matchMedia) {
      var mq = window.matchMedia('(prefers-color-scheme: dark)');
      var onChange = function () { if (!root.getAttribute('data-theme')) paint(); };
      if (mq.addEventListener) mq.addEventListener('change', onChange);
      else if (mq.addListener) mq.addListener(onChange);
    }
  }

  /* ---------- search ---------- */
  var index = null;
  var loading = false;

  function base() {
    var el = document.querySelector('link[rel="search-index"]');
    return el ? el.getAttribute('href') : 'search-index.json';
  }

  function load() {
    if (index || loading) return Promise.resolve(index);
    loading = true;
    return fetch(base(), { credentials: 'omit' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error(String(r.status))); })
      .then(function (data) {
        index = Array.isArray(data.entries) ? data.entries : [];
        loading = false;
        return index;
      })
      .catch(function () { loading = false; index = []; return index; });
  }

  function norm(s) {
    return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  }

  /* Light stemming so "clamping" still finds "clamped", "encodings" finds
     "encoding", and so on. Only trims common English endings. */
  function stems(term) {
    var out = [term];
    var endings = ['ing', 'ed', 'es', 's'];
    for (var i = 0; i < endings.length; i++) {
      var e = endings[i];
      if (term.length > e.length + 2 && term.slice(-e.length) === e) {
        out.push(term.slice(0, -e.length));
      }
    }
    return out;
  }

  function firstHit(hay, variants) {
    for (var i = 0; i < variants.length; i++) {
      if (hay.indexOf(variants[i]) !== -1) return i;
    }
    return -1;
  }

  function score(entry, terms) {
    var hay = entry._hay || (entry._hay = norm(
      entry.title + ' ' + entry.page + ' ' + (entry.aliases || []).join(' ') + ' ' + entry.text
    ));
    var titleHay = entry._t || (entry._t = norm(entry.title + ' ' + (entry.aliases || []).join(' ')));
    var total = 0;
    for (var i = 0; i < terms.length; i++) {
      var variants = terms[i];
      var hit = firstHit(hay, variants);
      if (hit === -1) return 0;
      /* an exact match scores above a stemmed one */
      total += hit === 0 ? 2 : 1;
      if (firstHit(titleHay, variants) !== -1) total += 3;
      if (titleHay.indexOf(variants[0]) === 0) total += 2;
    }
    return total;
  }

  function render(list, results, query) {
    results.innerHTML = '';
    if (!query) return;

    if (!list.length) {
      var li = document.createElement('li');
      li.className = 'search-empty';
      li.textContent = 'No match for “' + query + '”. Try a field name (tick, root, tokenid, dua, idua), an operation (deploy, mint, transfer, renew, setrecord), or a term such as multisig, expiry, or reorg.';
      results.appendChild(li);
      return;
    }

    list.slice(0, 12).forEach(function (entry) {
      var li = document.createElement('li');
      var a = document.createElement('a');
      a.href = entry.url;

      var p = document.createElement('span');
      p.className = 'r-page';
      p.textContent = entry.page;

      var t = document.createElement('span');
      t.className = 'r-title';
      t.textContent = entry.title;

      var s = document.createElement('span');
      s.className = 'r-snip';
      s.textContent = entry.text.length > 130 ? entry.text.slice(0, 130).replace(/\s+\S*$/, '') + '…' : entry.text;

      a.appendChild(p);
      a.appendChild(t);
      a.appendChild(s);
      li.appendChild(a);
      results.appendChild(li);
    });
  }

  function wireSearch() {
    var form = document.getElementById('site-search');
    if (!form) return;
    var input = form.querySelector('.search-input');
    var results = document.getElementById('search-results');
    if (!input || !results) return;

    form.hidden = false;
    form.addEventListener('submit', function (e) { e.preventDefault(); });

    var run = function () {
      var q = input.value.trim();
      if (!q) { render([], results, ''); return; }
      load().then(function (entries) {
        /* each term becomes its list of variants, exact form first */
        var terms = norm(q).split(' ').filter(Boolean).map(stems);
        if (!terms.length) { render([], results, ''); return; }
        var scored = [];
        for (var i = 0; i < entries.length; i++) {
          var sc = score(entries[i], terms);
          if (sc > 0) scored.push({ e: entries[i], s: sc });
        }
        scored.sort(function (a, b) { return b.s - a.s; });
        render(scored.map(function (x) { return x.e; }), results, q);
      });
    };

    var timer = null;
    input.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(run, 110);
    });
    input.addEventListener('focus', load);

    document.addEventListener('keydown', function (e) {
      if (e.key === '/' && !e.metaKey && !e.ctrlKey && !e.altKey) {
        var tag = (e.target && e.target.tagName) || '';
        if (tag === 'INPUT' || tag === 'TEXTAREA' || (e.target && e.target.isContentEditable)) return;
        e.preventDefault();
        input.focus();
        input.select();
      }
      if (e.key === 'Escape' && document.activeElement === input) {
        input.value = '';
        render([], results, '');
        input.blur();
      }
    });

    document.addEventListener('click', function (e) {
      if (!form.contains(e.target)) render([], results, '');
    });
  }

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  ready(function () { wireTheme(); wireSearch(); });
})();

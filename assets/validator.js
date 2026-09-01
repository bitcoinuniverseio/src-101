/* SRC-101 payload validator.
   Reimplements the checks that the Bitcoin Stamps indexer applies to an SRC-101
   payload before it consults any chain state. Runs entirely in the browser:
   no request, no storage, no analytics.

   Grounded in btc_stamps 1.9.3:
     indexer/src/index_core/src101.py    key sets, field rules, handler checks
     indexer/src/index_core/util.py      base64, special characters, address helpers
     indexer/src/config.py               activation heights
*/
(function () {
  'use strict';

  /* ---------------------------------------------------------------- heights */
  var GENESIS = 870652;
  var IMG_OPTIONAL = 872200;
  var OLGA = 940000;

  /* -------------------------------------------------------------- key sets */
  var KEYSETS = {
    deploy: ['p', 'root', 'op', 'name', 'lim', 'owner', 'rec', 'tick', 'pri', 'desc',
             'mintstart', 'mintend', 'wla', 'imglp', 'imgf', 'idua'],
    transfer: ['p', 'op', 'hash', 'toaddress', 'tokenid'],
    setrecord: ['p', 'op', 'hash', 'tokenid', 'type', 'data', 'prim'],
    renew: ['p', 'op', 'hash', 'tokenid', 'dua'],
    mintOld: ['p', 'op', 'hash', 'toaddress', 'tokenid', 'dua', 'prim', 'sig', 'img', 'coef'],
    mintNew: ['p', 'op', 'hash', 'toaddress', 'tokenid', 'dua', 'prim', 'sig', 'coef']
  };

  var NUMERIC_FIELDS = ['lim', 'dua', 'idua', 'mintstart', 'mintend', 'coef'];
  var NUMERIC_PATTERN = /^[0-9]*(\.[0-9]*)?$/;
  var BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
  var HASH_PATTERN = /^[0-9a-fA-F]{64}$/;
  var PUBKEY_PATTERN = /^0[23][0-9a-fA-F]{64}$/;

  /* The indexer's special-character class, transcribed with escapes so that no
     literal em dash or full-width character appears in this source file. */
  var SPECIAL = new RegExp(
    '[`~!@#$%^\\-+&*()_=|{}":;\',\\\\\\[\\].<>/?' +
    '\\uFF1D\\u00B7\\uFF01\\uFFE5\\u2026\\uFF08\\uFF09\\u2014' +
    '\\u3010\\u3011\\u300A\\u300B\\uFF1B\\uFF1A' +
    '\\u201C\\u201D\\u2018\\u2019\\u3002\\uFF0C\\u3001\\uFF1F\\s]'
  );
  var ZS_CF = null;
  try { ZS_CF = new RegExp('[\\p{Zs}\\p{Cf}]', 'u'); } catch (e) { ZS_CF = null; }

  function containsSpecial(text) {
    if (typeof text !== 'string') return true;
    if (text.length === 0) return false;
    if (text.trim() === '') return true;
    if (SPECIAL.test(text)) return true;
    if (ZS_CF && ZS_CF.test(text)) return true;
    return false;
  }

  /* ---------------------------------------------------------------- sha-256 */
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function sha256(bytes) {
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var len = bytes.length;
    var withPad = new Uint8Array((((len + 8) >> 6) + 1) << 6);
    withPad.set(bytes);
    withPad[len] = 0x80;
    var bitLen = len * 8;
    var dv = new DataView(withPad.buffer);
    dv.setUint32(withPad.length - 4, bitLen >>> 0);
    dv.setUint32(withPad.length - 8, Math.floor(bitLen / 4294967296));

    var w = new Int32Array(64);
    for (var i = 0; i < withPad.length; i += 64) {
      var j;
      for (j = 0; j < 16; j++) w[j] = dv.getInt32(i + j * 4);
      for (j = 16; j < 64; j++) {
        var g0 = w[j - 15], g1 = w[j - 2];
        var s0 = ((g0 >>> 7) | (g0 << 25)) ^ ((g0 >>> 18) | (g0 << 14)) ^ (g0 >>> 3);
        var s1 = ((g1 >>> 17) | (g1 << 15)) ^ ((g1 >>> 19) | (g1 << 13)) ^ (g1 >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (j = 0; j < 64; j++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[j] + w[j]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }
    var out = new Uint8Array(32);
    var ov = new DataView(out.buffer);
    for (var k = 0; k < 8; k++) ov.setInt32(k * 4, h[k]);
    return out;
  }

  /* --------------------------------------------------------------- base58 */
  var B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  function base58CheckDecode(str) {
    if (!str.length) return null;
    var bytes = [0];
    for (var i = 0; i < str.length; i++) {
      var carry = B58.indexOf(str.charAt(i));
      if (carry < 0) return null;
      for (var j = 0; j < bytes.length; j++) {
        carry += bytes[j] * 58;
        bytes[j] = carry & 0xff;
        carry >>= 8;
      }
      while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
    }
    for (i = 0; i < str.length && str.charAt(i) === '1'; i++) bytes.push(0);
    bytes.reverse();
    if (bytes.length < 5) return null;
    var payload = new Uint8Array(bytes.slice(0, bytes.length - 4));
    var checksum = bytes.slice(bytes.length - 4);
    var digest = sha256(sha256(payload));
    for (i = 0; i < 4; i++) if (digest[i] !== checksum[i]) return null;
    return payload;
  }

  /* --------------------------------------------------------------- bech32 */
  var BECH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

  function bechPolymod(values) {
    var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var chk = 1;
    for (var p = 0; p < values.length; p++) {
      var top = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ values[p];
      for (var i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
    }
    return chk >>> 0;
  }

  function bechExpandHrp(hrp) {
    var out = [], i;
    for (i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >>> 5);
    out.push(0);
    for (i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
    return out;
  }

  function bech32Decode(addr) {
    if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) return null;
    var s = addr.toLowerCase();
    var pos = s.lastIndexOf('1');
    if (pos < 1 || pos + 7 > s.length || s.length > 90) return null;
    var hrp = s.slice(0, pos);
    var data = [];
    for (var i = pos + 1; i < s.length; i++) {
      var v = BECH.indexOf(s.charAt(i));
      if (v < 0) return null;
      data.push(v);
    }
    var chk = bechPolymod(bechExpandHrp(hrp).concat(data));
    var spec = chk === 1 ? 'bech32' : (chk === 0x2bc830a3 ? 'bech32m' : null);
    if (!spec) return null;
    var payload = data.slice(0, data.length - 6);
    if (!payload.length) return null;
    var version = payload[0];
    if (version > 16) return null;
    /* convert the remainder from 5-bit to 8-bit */
    var acc = 0, bits = 0, prog = [];
    for (i = 1; i < payload.length; i++) {
      acc = (acc << 5) | payload[i];
      bits += 5;
      while (bits >= 8) { bits -= 8; prog.push((acc >>> bits) & 0xff); }
    }
    if (bits >= 5 || ((acc << (8 - bits)) & 0xff) !== 0) return null;
    if (prog.length < 2 || prog.length > 40) return null;
    if (version === 0 && prog.length !== 20 && prog.length !== 32) return null;
    if (version === 0 && spec !== 'bech32') return null;
    if (version !== 0 && spec !== 'bech32m') return null;
    return { hrp: hrp, version: version, program: prog };
  }

  /* Mirrors check_valid_bitcoin_address: the bc1 / tb1 prefix selects the
     bech32 branch, and everything else goes to the base58 branch. */
  function addressCheck(addr) {
    if (typeof addr !== 'string' || !addr.length) {
      return { ok: false, note: 'not a string' };
    }
    if (addr.indexOf('bc1') === 0 || addr.indexOf('tb1') === 0) {
      var d = bech32Decode(addr);
      if (!d) return { ok: false, note: 'bech32 checksum, charset or witness program is invalid' };
      var kind = 'witness version ' + d.version + ', ' + d.program.length + '-byte program';
      if (d.hrp === 'tb') {
        return { ok: true, warn: true, note: 'valid testnet bech32 (' + kind + '). The indexer accepts the tb1 prefix, but SRC-101 is defined on mainnet only' };
      }
      return { ok: true, note: 'valid bech32 (' + kind + ')' };
    }
    var p = base58CheckDecode(addr);
    if (!p) return { ok: false, note: 'base58check checksum or alphabet is invalid' };
    var ver = p[0];
    if (ver === 0x00) return { ok: true, note: 'valid P2PKH' };
    if (ver === 0x05) return { ok: true, note: 'valid P2SH' };
    return { ok: true, warn: true, note: 'valid base58check with version byte 0x' + ver.toString(16) + ', which is not a Bitcoin mainnet address version' };
  }

  /* --------------------------------------------------------------- base64 */
  function b64Decode(str) {
    try {
      var bin = atob(str);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      if (typeof TextDecoder === 'function') {
        return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      }
      return decodeURIComponent(bin.split('').map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
    } catch (e) {
      return null;
    }
  }

  function tokenIdCheck(value) {
    if (typeof value !== 'string') return { ok: false, note: 'not a string' };
    if (!BASE64_PATTERN.test(value)) {
      return { ok: false, note: 'not standard base64. The accepted alphabet is A to Z, a to z, 0 to 9, plus and slash, with up to two padding characters. The URL-safe alphabet is rejected' };
    }
    if (value.length % 4 !== 0) {
      return { ok: false, note: 'length ' + value.length + ' is not a multiple of four' };
    }
    if (value.length > 128) {
      return { ok: false, note: 'encoded length ' + value.length + ' exceeds the 128 character cap' };
    }
    var text = b64Decode(value);
    if (text === null) return { ok: false, note: 'does not decode to valid UTF-8' };
    var lower = text.toLowerCase();
    if (containsSpecial(lower)) {
      return { ok: false, decoded: lower, note: 'the decoded name contains a character the indexer rejects: whitespace, a format character, or one of the punctuation characters in the special set' };
    }
    return { ok: true, decoded: lower, note: 'decodes to ' + JSON.stringify(lower) + ', length ' + lower.length };
  }

  /* Mirrors the numeric coercion, including the string versus number split. */
  function numericCheck(key, value) {
    var asText = String(value);
    if (!NUMERIC_PATTERN.test(asText)) {
      return { ok: false, note: 'NN. ' + JSON.stringify(value) + ' does not match the numeric pattern. Digits and at most one dot, no sign, no separators, no scientific notation' };
    }
    if (typeof value === 'number') {
      if (!isFinite(value)) return { ok: false, note: 'NN. not a finite number' };
      var truncated = Math.trunc(value);
      if (truncated < 0) return { ok: false, note: 'NN. must be at least zero' };
      if (truncated !== value) {
        return { ok: true, warn: true, value: truncated, note: 'accepted, but silently TRUNCATED from ' + value + ' to ' + truncated + '. A JSON number with a fraction is truncated; the same value written as a string would be rejected' };
      }
      return { ok: true, value: truncated, note: 'integer ' + truncated };
    }
    if (typeof value === 'string') {
      if (!/^[0-9]+$/.test(value)) {
        return { ok: false, note: 'NN. the string ' + JSON.stringify(value) + ' matches the pattern but does not convert to an integer. A string with a dot is rejected outright, unlike the equivalent JSON number' };
      }
      var n = parseInt(value, 10);
      if (!(n >= 0)) return { ok: false, note: 'NN. must be at least zero' };
      return { ok: true, value: n, note: 'integer ' + n };
    }
    return { ok: false, note: 'NN. must be a JSON string or a JSON number' };
  }

  /* ------------------------------------------------------------- the checks */
  function validate(text, height) {
    var checks = [];
    var notes = [];
    var res = { checks: checks, notes: notes, verdict: null, title: '', detail: '' };

    function add(state, field, msg) { checks.push({ state: state, field: field, msg: msg }); }
    function excluded(title, detail) {
      res.verdict = 'excluded'; res.title = title; res.detail = detail; return res;
    }
    function invalid(title, detail) {
      res.verdict = 'invalid'; res.title = title; res.detail = detail; return res;
    }

    /* --- parse --- */
    var raw;
    try {
      raw = JSON.parse(text);
    } catch (e) {
      add('bad', 'JSON', 'The payload does not parse: ' + e.message);
      return excluded('Not JSON', 'The carrier payload must parse as a JSON object. Nothing further can be checked.');
    }
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      add('bad', 'JSON', 'The payload parses but is not an object.');
      return excluded('Not a JSON object', 'An SRC-101 operation is a JSON object with named keys.');
    }
    add('ok', 'JSON', 'Parses as a JSON object.');

    /* --- key lowering --- */
    var d = {}, lowered = [];
    Object.keys(raw).forEach(function (k) {
      var lk = k.toLowerCase();
      if (lk !== k) lowered.push(k + ' becomes ' + lk);
      d[lk] = raw[k];
    });
    if (lowered.length) {
      add('info', 'key case', 'The indexer lower-cases every top-level key before anything else: ' + lowered.join(', ') + '.');
    }

    /* --- height --- */
    if (!(height >= GENESIS)) {
      add('bad', 'block height', 'Block ' + height + ' is below the SRC-101 genesis block ' + GENESIS + '. No SRC-101 payload has any meaning below that height.');
      return excluded('Below genesis', 'SRC-101 is valid from block ' + GENESIS + ' upward. There is no upper bound.');
    }
    add('ok', 'block height', 'Block ' + height + ' is at or above genesis ' + GENESIS + '. There is no end block for SRC-101.');

    /* --- protocol --- */
    if (typeof d.p !== 'string' || d.p.toLowerCase() !== 'src-101') {
      add('bad', 'p', 'Must be the string src-101, compared case-insensitively. Found ' + JSON.stringify(d.p) + '.');
      return excluded('Not an SRC-101 payload', 'The protocol field decides classification. Without it the carrier hands the payload to another sub-protocol or to none.');
    }
    add('ok', 'p', 'Recognised as SRC-101. The hyphen is required and the case is not.');

    /* --- operation --- */
    var op = typeof d.op === 'string' ? d.op.toLowerCase() : null;
    var known = ['deploy', 'mint', 'transfer', 'setrecord', 'renew'];
    if (!op || known.indexOf(op) === -1) {
      add('bad', 'op', 'Must be one of deploy, mint, transfer, setrecord or renew, compared case-insensitively. Found ' + JSON.stringify(d.op) + '.');
      return excluded('Unrecognised operation', 'An unknown operation is discarded during key matching. It never reaches dispatch, so it does not even produce the UO status.');
    }
    add('ok', 'op', 'Recognised as ' + op.toUpperCase() + '. Stored upper-cased.');

    /* --- key set --- */
    var setName = op === 'mint' ? (height < IMG_OPTIONAL ? 'mintOld' : 'mintNew') : op;
    var expected = KEYSETS[setName];
    var present = Object.keys(d);
    var missing = expected.filter(function (k) { return present.indexOf(k) === -1; });
    var extra = present.filter(function (k) { return expected.indexOf(k) === -1; });
    var superset = (op === 'mint' && height >= IMG_OPTIONAL);

    if (missing.length) {
      add('bad', 'key set', 'Missing required ' + (missing.length === 1 ? 'key' : 'keys') + ': ' + missing.join(', ') + '. The set for ' + op + ' at block ' + height + ' is: ' + expected.join(', ') + '.');
    } else {
      add('ok', 'key set', 'All ' + expected.length + ' required keys are present.');
    }
    if (extra.length) {
      if (superset) {
        add('info', 'extra keys', 'Extra ' + (extra.length === 1 ? 'key' : 'keys') + ' ' + extra.join(', ') + '. At block ' + IMG_OPTIONAL + ' and above, mint matching is a containment test, so extras are permitted and ignored.' + (extra.indexOf('img') !== -1 ? ' An img here is discarded and the derived value is written instead.' : ''));
      } else {
        add('bad', 'extra keys', 'Unexpected ' + (extra.length === 1 ? 'key' : 'keys') + ': ' + extra.join(', ') + '. Matching for ' + op + (op === 'mint' ? ' below block ' + IMG_OPTIONAL : '') + ' is an exact symmetric difference, so one extra key discards the payload.');
      }
    } else if (!superset) {
      add('ok', 'extra keys', 'No unexpected keys.');
    }
    if (missing.length || (extra.length && !superset)) {
      return excluded('Excluded by key matching',
        'The payload does not match the ' + op + ' key set for block ' + height + '. It is discarded before any handler runs: no row is written, no status code is assigned, and nothing about it is visible afterwards.');
    }

    /* --- field rules --- */
    var fieldFail = false;
    function fail(field, msg) { fieldFail = true; add('bad', field, msg); }

    /* empty string normalisation */
    var emptied = present.filter(function (k) { return d[k] === ''; });
    if (emptied.length) {
      add('info', 'empty strings', emptied.join(', ') + ' ' + (emptied.length === 1 ? 'is an empty string, which is' : 'are empty strings, which are') + ' normalised to null before any type rule runs. This is how a mandatory key can carry no value.');
    }

    NUMERIC_FIELDS.forEach(function (key) {
      if (!(key in d) || d[key] === '' || d[key] === null) return;
      var r = numericCheck(key, d[key]);
      if (!r.ok) fail(key, r.note);
      else add(r.warn ? 'info' : 'ok', key, r.note);
      d['_' + key] = r.value;
    });

    if ('hash' in d && d.hash !== '' && d.hash !== null) {
      if (typeof d.hash !== 'string' || !HASH_PATTERN.test(d.hash)) {
        fail('hash', 'IH. Must be exactly 64 hexadecimal characters. Found ' + (typeof d.hash === 'string' ? 'length ' + d.hash.length : typeof d.hash) + '.');
      } else {
        add('ok', 'hash', 'A well-formed 64-character namespace identifier. Whether it resolves to a deployed namespace cannot be checked here.');
      }
    }

    ['owner', 'toaddress'].forEach(function (key) {
      if (!(key in d) || d[key] === '' || d[key] === null) return;
      var r = addressCheck(d[key]);
      if (!r.ok) fail(key, 'IA. ' + r.note + '.');
      else add(r.warn ? 'info' : 'ok', key, r.note + '.');
    });

    if ('rec' in d && d.rec !== null) {
      if (!Array.isArray(d.rec)) {
        fail('rec', 'IAL. Must be a list of Bitcoin addresses.');
      } else if (!d.rec.length) {
        fail('rec', 'IAL. An empty recipient list means no mint or renew can ever pay this namespace.');
      } else {
        var bad = [];
        d.rec.forEach(function (a) { if (!addressCheck(a).ok) bad.push(String(a)); });
        if (bad.length) fail('rec', 'IAL. Not a valid Bitcoin address: ' + bad.join(', ') + '.');
        else add('ok', 'rec', d.rec.length + ' recipient ' + (d.rec.length === 1 ? 'address' : 'addresses'), 'ok');
      }
      if (Array.isArray(d.rec)) {
        var uniq = {}; var dupes = 0;
        d.rec.forEach(function (a) { if (uniq[a]) dupes++; uniq[a] = 1; });
        if (dupes) add('info', 'rec', 'The list is de-duplicated on storage, and its order is not preserved.');
      }
    }

    if ('wla' in d && d.wla !== '' && d.wla !== null) {
      if (typeof d.wla !== 'string' || !PUBKEY_PATTERN.test(d.wla)) {
        fail('wla', 'IWLA. Must be 66 hexadecimal characters beginning 02 or 03.');
      } else {
        add('info', 'wla', 'Well-formed as a compressed key. The indexer additionally requires it to be a valid point on secp256k1, which this tool does not compute.');
      }
    }

    if ('pri' in d && d.pri !== null) {
      if (typeof d.pri !== 'object' || Array.isArray(d.pri)) {
        fail('pri', 'IPC. Must be an object mapping name length to price.');
      } else {
        var keys = Object.keys(d.pri);
        var badKey = keys.filter(function (k) { return !/^-?[0-9]+$/.test(k); });
        var badVal = keys.filter(function (k) { return typeof d.pri[k] !== 'number' || !Number.isInteger(d.pri[k]); });
        if (badKey.length) fail('pri', 'IPC. Every key must parse as an integer. Offending: ' + badKey.join(', ') + '.');
        else if (badVal.length) fail('pri', 'IPC. Every value must be a JSON integer, not a string. Offending: ' + badVal.join(', ') + '.');
        else {
          var hasFallback = keys.indexOf('0') !== -1;
          add('ok', 'pri', keys.length + ' price ' + (keys.length === 1 ? 'entry' : 'entries') + ' by name length. ' +
            (hasFallback ? 'The 0 entry is the fallback for any length with no explicit price.' : 'There is no 0 entry, so any name whose length has no price fails with IRL.'));
        }
      }
    }

    if ('prim' in d && d.prim !== null) {
      if (d.prim !== 'true' && d.prim !== 'false') {
        fail('prim', 'IP. Must be the STRING "true" or the STRING "false". ' +
          (typeof d.prim === 'boolean' ? 'A JSON boolean is rejected: the comparison is textual.' : 'Found ' + JSON.stringify(d.prim) + '.'));
      } else {
        add('ok', 'prim', 'The string ' + JSON.stringify(d.prim) + ', which is the only accepted form.');
      }
    }

    ['imglp', 'imgf', 'sig'].forEach(function (key) {
      if (!(key in d) || d[key] === '' || d[key] === null) return;
      if (typeof d[key] !== 'string') fail(key, 'IIM. Must be a string.');
      else add('ok', key, 'A string, as required.');
    });

    if ('img' in d && d.img !== null && d.img !== '') {
      if (!Array.isArray(d.img) || !d.img.every(function (x) { return typeof x === 'string'; })) {
        fail('img', 'IIM. Must be a list of strings.');
      } else if (height >= IMG_OPTIONAL) {
        add('info', 'img', 'A well-formed list, but at block ' + IMG_OPTIONAL + ' and above the submitted value is discarded and the URL is derived from the namespace prefix and suffix.');
      } else {
        add('ok', 'img', 'A list of ' + d.img.length + ' string' + (d.img.length === 1 ? '' : 's') + '. Below block ' + IMG_OPTIONAL + ' each entry must equal the derived URL exactly, which needs the namespace and cannot be checked here.');
      }
    }

    ['root', 'name'].forEach(function (key) {
      if (!(key in d) || d[key] === '' || d[key] === null) return;
      if (typeof d[key] !== 'string' || containsSpecial(d[key])) {
        fail(key, 'IA. Must be a string with no whitespace, format character or special punctuation.');
      } else {
        add('ok', key, JSON.stringify(d[key]) + ', ' + d[key].length + ' characters.');
      }
    });

    var decodedNames = [];
    if ('tokenid' in d && d.tokenid !== null && d.tokenid !== '') {
      if (Array.isArray(d.tokenid)) {
        if (!d.tokenid.length) {
          fail('tokenid', 'IT. An empty list.');
        } else {
          var seen = {}, anyBad = false;
          d.tokenid.forEach(function (v, i) {
            var r = tokenIdCheck(v);
            if (!r.ok) { anyBad = true; add('bad', 'tokenid[' + i + ']', 'IT. ' + r.note + '.'); return; }
            if (seen[r.decoded]) { anyBad = true; add('bad', 'tokenid[' + i + ']', 'IT. ' + JSON.stringify(r.decoded) + ' is a duplicate within the list. Duplicates are compared after decoding.'); return; }
            seen[r.decoded] = 1;
            decodedNames.push(r.decoded);
            add('ok', 'tokenid[' + i + ']', r.note + '.');
          });
          if (anyBad) fieldFail = true;
        }
      } else {
        var rs = tokenIdCheck(d.tokenid);
        if (!rs.ok) fail('tokenid', 'IT. ' + rs.note + '.');
        else { decodedNames.push(rs.decoded); add('ok', 'tokenid', rs.note + '.'); }
      }
    }

    if ('type' in d && d.type !== null && d.type !== '') {
      if (typeof d.type !== 'string') {
        add('bad', 'type', 'Must be a string naming the record kind.');
        fieldFail = true;
      } else if (d.type === 'address' || d.type === 'txt') {
        add('ok', 'type', 'Recognised. The value of data is written to the field ' + d.type + '_data.');
      } else {
        add('info', 'type', JSON.stringify(d.type) + ' produces a field named ' + d.type + '_data, which no handler reads. The operation will fail with ID because neither an address record nor a text record is produced.');
      }
    }

    if (fieldFail) {
      return excluded('Excluded by field validation',
        'A field failed its rule. In SRC-101 that abandons the whole operation before dispatch: no handler runs, no operation-level status is assigned, and no usable record exists. This is the sharpest divergence from SRC-20.');
    }
    add('ok', 'field validation', 'Every field passed. In SRC-101 a single field failure would have discarded the operation entirely.');

    /* --- operation-level, payload-only --- */
    var status = null;
    var deadNamespace = null;
    if (op === 'deploy') {
      var lens = [['root', 32], ['name', 32], ['tick', 32], ['imgf', 32], ['imglp', 255]];
      lens.forEach(function (pair) {
        var k = pair[0], cap = pair[1];
        var v = d[k];
        if (typeof v !== 'string' || v.length >= cap) {
          if (!status) status = 'IDP';
          add('bad', k, 'IDP. Must be a string shorter than ' + cap + ' characters. A missing value also fails, because the length test substitutes an over-long placeholder.');
        }
      });
      if (d.pri && typeof d.pri === 'object' && Object.keys(d.pri).length >= 255) {
        if (!status) status = 'IDP';
        add('bad', 'pri', 'IDP. Must have fewer than 255 entries.');
      }
      if (!status) add('ok', 'deploy lengths', 'All six length limits are satisfied.');

      if (d._lim === 0) {
        deadNamespace = 'lim';
        add('bad', 'lim', 'A zero limit makes this namespace PERMANENTLY UNUSABLE. The namespace lookup treats a resolved limit of zero as "not found", so every later mint, transfer, renew and setrecord against this deploy fails with ND. The deploy itself is still recorded as valid.');
      } else if (typeof d._lim === 'number') {
        add('info', 'lim', 'Stored, but never enforced as a limit on anything. Its only functional role is as a presence sentinel for the namespace lookup.');
      }
      if (d._idua === 0) {
        deadNamespace = deadNamespace || 'idua';
        add('bad', 'idua', 'A zero granularity makes every mint and renew fail with ITID, because the term rounding divides by it.');
      }
      if (d._mintend === 0) {
        add('info', 'mintend', 'Zero is stored as 18446744073709551615, meaning the mint window never closes.');
      } else if (typeof d._mintend === 'number' && typeof d._mintstart === 'number' && d._mintend <= d._mintstart) {
        add('info', 'mintend', 'The mint window closes at or before it opens, so no mint can ever succeed: too early gives UT, and at or after the end gives OT.');
      }
    }

    if (op === 'mint') {
      if (!Array.isArray(d.tokenid)) {
        status = status || 'ITT';
        add('bad', 'tokenid', 'ITT. A mint requires the LIST form, even for a single name. The plain string form is rejected.');
      } else {
        add('ok', 'tokenid', 'A list of ' + d.tokenid.length + ' name' + (d.tokenid.length === 1 ? '' : 's') + ', as a mint requires.');
        if (d.tokenid.length > 1) {
          add('info', 'tokenid', 'Any of these names already held with a live expiry is quietly DROPPED and the rest are minted. The payment is computed over the full submitted list, so you pay for all ' + d.tokenid.length + '. Only if every one is taken does the mint fail, with DM.');
        }
      }
      if (!(typeof d._coef === 'number') || d._coef < 0 || d._coef > 1000) {
        status = status || 'ITC';
        add('bad', 'coef', 'ITC. Must be an integer between 0 and 1000 inclusive.');
      } else {
        var sigEmpty = !d.sig || d.sig === '';
        if (d._coef !== 1000 && sigEmpty) {
          add('info', 'coef', d._coef + ' requests a discount, but sig is empty. Without a signature the effective coefficient stays at 1000, so the FULL price is required and a short payment fails with IRV.');
        } else if (!sigEmpty) {
          add('info', 'coef', d._coef + ' parts per thousand, to be proved by sig against the namespace whitelist key. If neither accepted message form verifies, the mint fails with IRS rather than falling back to full price.');
        } else {
          add('ok', 'coef', '1000, meaning full price and no discount claimed.');
        }
      }
      if (!(typeof d._dua === 'number') || d._dua <= 0) {
        status = status || 'ITD';
        add('bad', 'dua', 'ITD. Must be an integer greater than zero.');
      } else {
        add('ok', 'dua', d._dua + ' year' + (d._dua === 1 ? '' : 's') + ' requested, before rounding up to a multiple of the namespace granularity. A year is exactly 31536000 seconds.');
      }
      if (height < IMG_OPTIONAL && !Array.isArray(d.img)) {
        status = status || 'ITI';
        add('bad', 'img', 'ITI. Below block ' + IMG_OPTIONAL + ' img must be a list.');
      }
      if (height < OLGA) {
        add('info', 'carrier', 'Below block ' + OLGA + ' the decoder reports a destination value of zero on the P2WSH branch, so a P2WSH-carried mint fails its payment check with IRV whatever you pay. Use bare multisig for a paid operation at this height.');
      }
    }

    if (op === 'renew') {
      if (!(typeof d._dua === 'number') || d._dua <= 0) {
        status = status || 'ITD';
        add('bad', 'dua', 'ITD. Must be an integer greater than zero.');
      } else {
        add('ok', 'dua', d._dua + ' year' + (d._dua === 1 ? '' : 's') + ' added to the EXISTING expiry, not to the current block time. Renewing early loses no time.');
      }
      if (Array.isArray(d.tokenid)) {
        add('info', 'tokenid', 'A renew looks the name up as a single decoded string. A list will not match any entry and the operation fails with NM.');
      }
      add('info', 'discount', 'A renew has no coef and no sig in its key set, so there is no discount. A holder who minted at a discount renews at full price.');
      if (height < OLGA) {
        add('info', 'carrier', 'Below block ' + OLGA + ' a P2WSH-carried renew fails its payment check with IRV, because the decoder reports a destination value of zero on that branch.');
      }
    }

    if (op === 'transfer') {
      if (Array.isArray(d.tokenid)) {
        add('info', 'tokenid', 'A transfer looks the name up as a single decoded string. A list will not match any entry and the operation fails with NM.');
      }
      add('info', 'expiry', 'A transfer carries the existing expiry over unchanged. It does not extend the term.');
      add('info', 'records', 'The row written by a transfer clears the resolved Bitcoin address, the resolved Ethereum address and the text record, and sets the primary flag to false. The new owner must issue a fresh setrecord.');
    }

    if (op === 'setrecord') {
      var hasAddress = d.type === 'address' && d.data && typeof d.data === 'object' && !Array.isArray(d.data);
      var hasTxt = d.type === 'txt' && d.data !== null && d.data !== '' && d.data !== undefined;
      if (!hasAddress && !hasTxt) {
        status = status || 'ID';
        add('bad', 'data', 'ID. Neither an address record nor a text record is produced. type must be "address" with an object of records, or "txt" with a value.');
      }
      if (hasAddress) {
        if ('btc' in d.data && d.data.btc) {
          var rb = addressCheck(d.data.btc);
          if (!rb.ok) { status = status || 'ID'; add('bad', 'data.btc', 'ID. ' + rb.note + '.'); }
          else add('ok', 'data.btc', rb.note + '.');
        }
        if ('eth' in d.data && d.data.eth) {
          if (typeof d.data.eth !== 'string' || !/^[0-9a-fA-F]+$/.test(d.data.eth)) {
            status = status || 'ID';
            add('bad', 'data.eth', 'ID. This member is NOT an Ethereum address. It is the hexadecimal signature of an Ethereum personal-sign message whose text is the hexadecimal, byte-reversed hash of the transaction spent by input 0.');
          } else {
            add('info', 'data.eth', 'Well-formed as hexadecimal. The indexer recovers the signer from this signature over the reversed previous transaction hash and stores the recovered address without its 0x prefix. Recovery cannot be checked here because it needs the transaction.');
          }
        }
        if (!('btc' in d.data) && !('eth' in d.data)) {
          status = status || 'ID';
          add('bad', 'data', 'ID. An address record must carry a btc member, an eth member, or both.');
        }
      }
      if (d.prim === 'true') {
        if (!hasAddress || !d.data || !d.data.btc) {
          status = status || 'IDB';
          add('bad', 'prim', 'IDB. Claiming the primary flag requires an address record whose btc member equals the address funding input 0.');
        } else {
          add('info', 'prim', 'Claiming the primary flag. The btc record must equal the address funding input 0, else IDB. Success clears the flag from every other name this address holds in the namespace.');
        }
      }
      add('info', 'records', 'Records merge rather than replace. Supplying only one kind leaves the other as it was.');
    }

    /* --- what cannot be known --- */
    notes.push('Whether the namespace hash resolves to a deployed namespace. An unresolved hash gives ND.');
    if (op !== 'deploy') {
      notes.push('The namespace price list, recipient set, whitelist key, mint window and term granularity, all of which the checks above depend on.');
    }
    if (op === 'mint' || op === 'renew') {
      notes.push('Whether output 0 pays a namespace recipient (else IR) and whether it pays enough (else IRV).');
      notes.push('The rounded term, since rounding depends on the namespace granularity.');
    }
    if (op === 'mint') {
      notes.push('Whether each name is free. Names already held with a live expiry are dropped from the list.');
      notes.push('Whether the block timestamp falls inside the mint window (else UT or OT).');
      notes.push('Whether a discount signature verifies against the namespace whitelist key (else IRS).');
    }
    if (op === 'transfer' || op === 'renew' || op === 'setrecord') {
      notes.push('Whether the name has ever been minted (else NM).');
      notes.push('Whether the address funding input 0 is the current owner (else NO).');
      notes.push('Whether the term is still running. There is no grace period, and an expired name gives OE.');
    }
    if (op === 'deploy') {
      notes.push('That a mint in this same block will fail with ND, because a namespace cannot be resolved from within the block that deployed it.');
    }
    notes.push('Whether the transaction satisfies the carrier: a keyburn of 1, a correctly framed payload, and the right output geometry.');

    if (status) {
      return invalid('Recorded as invalid, status ' + status,
        'The payload is a recognisable ' + op.toUpperCase() + ' and reaches its handler, but a check the handler applies to the payload alone fails. A row is written with this status and nothing in the register changes.');
    }

    return (function () {
      if (deadNamespace) {
        res.verdict = 'invalid';
        res.title = 'Well formed, but the namespace will be unusable';
        res.detail = 'This DEPLOY is recorded as VALID by the indexer. It is nonetheless a dead namespace: a zero ' + deadNamespace + ' means no mint, transfer, renew or setrecord against it can ever succeed. Nothing later can repair it, because a namespace cannot be redeployed under the same hash.';
        return res;
      }
      res.verdict = 'valid';
      res.title = 'Well formed as ' + op.toUpperCase();
      res.detail = 'Every check that can be made from the payload alone passes at block ' + height + '. Whether the operation succeeds now depends on chain state, listed below.';
      return res;
    })();
  }

  /* --------------------------------------------------------------- samples */
  var HASH = '3a7f1c8e0b45d29a6f13e874c05b9d2e6a8f04713bc9e25d8a06f1c34b7e9c19';
  var REC = 'bc1qs2x9wz22tasf8pfejlcc3e8yhnzhv9qs2kgwls';
  var WLA = '02bb9e14cd42f6487e94071cb25fe5bd6f42753de771be11d21c6a80b5f08cf4a4';

  var SAMPLES = {
    deploy: {
      p: 'src-101', op: 'DEPLOY', root: 'btc', name: 'bitnames', tick: 'bitname', lim: '1',
      owner: '14caKuhoxA2wCj7JYjVJhgsuxTsbu5rzch', rec: [REC],
      pri: { '0': 200000, '3': 2000000, '4': 800000 },
      desc: 'Bitcoin name registry', mintstart: '1732924800', mintend: '0',
      wla: WLA, imglp: 'https://names.example/i/', imgf: 'png', idua: '1'
    },
    mint: {
      p: 'src-101', op: 'MINT', hash: HASH, toaddress: REC,
      tokenid: ['c2F0b3NoaQ=='], dua: '2', prim: 'true', sig: '', coef: '1000'
    },
    multi: {
      p: 'src-101', op: 'MINT', hash: HASH, toaddress: REC,
      tokenid: ['c2F0b3NoaQ==', 'Yml0Y29pbg==', 'bGFwc2Vk'], dua: '1', prim: 'false', sig: '', coef: '1000'
    },
    transfer: {
      p: 'src-101', op: 'TRANSFER', hash: HASH, toaddress: REC, tokenid: 'c2F0b3NoaQ=='
    },
    renew: {
      p: 'src-101', op: 'RENEW', hash: HASH, tokenid: 'c2F0b3NoaQ==', dua: '1'
    },
    setrecord: {
      p: 'src-101', op: 'SETRECORD', hash: HASH, tokenid: 'c2F0b3NoaQ==',
      type: 'address', data: { btc: REC }, prim: 'true'
    },
    boolprim: {
      p: 'src-101', op: 'MINT', hash: HASH, toaddress: REC,
      tokenid: ['c2F0b3NoaQ=='], dua: '2', prim: true, sig: '', coef: '1000'
    },
    extra: {
      p: 'src-101', op: 'TRANSFER', hash: HASH, toaddress: REC,
      tokenid: 'c2F0b3NoaQ==', memo: 'a note for the recipient'
    },
    missing: {
      p: 'src-101', op: 'RENEW', hash: HASH, tokenid: 'c2F0b3NoaQ=='
    },
    fractional: {
      p: 'src-101', op: 'RENEW', hash: HASH, tokenid: 'c2F0b3NoaQ==', dua: '1.5'
    },
    zerolim: {
      p: 'src-101', op: 'DEPLOY', root: 'btc', name: 'deadspace', tick: 'deadspace', lim: '0',
      owner: '14caKuhoxA2wCj7JYjVJhgsuxTsbu5rzch', rec: [REC],
      pri: { '0': 200000 }, desc: 'A namespace nobody can use', mintstart: '1732924800',
      mintend: '0', wla: WLA, imglp: 'https://names.example/i/', imgf: 'png', idua: '1'
    },
    stringid: {
      p: 'src-101', op: 'MINT', hash: HASH, toaddress: REC,
      tokenid: 'c2F0b3NoaQ==', dua: '2', prim: 'false', sig: '', coef: '1000'
    },
    urlsafe: {
      p: 'src-101', op: 'TRANSFER', hash: HASH, toaddress: REC, tokenid: 'c2F0b3-oaQ=='
    },
    src20: {
      p: 'src-20', op: 'DEPLOY', tick: 'PLATE', max: '21000000', lim: '1000', dec: '8'
    }
  };

  /* --------------------------------------------------------------------- ui */
  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  ready(function () {
    var panel = document.getElementById('tool-panel');
    var noscript = document.getElementById('tool-noscript');
    var input = document.getElementById('payload');
    var heightInput = document.getElementById('height');
    var verdict = document.getElementById('verdict');
    var checksEl = document.getElementById('checks');
    var notesWrap = document.getElementById('notes-wrap');
    var notesEl = document.getElementById('notes');
    if (!panel || !input || !verdict || !checksEl) return;

    panel.hidden = false;
    if (noscript) noscript.hidden = true;

    function paint() {
      var height = parseInt(heightInput && heightInput.value, 10);
      if (!(height >= 0)) height = 900000;
      var r = validate(input.value, height);

      verdict.className = 'verdict verdict-' + r.verdict;
      verdict.innerHTML = '';
      var h = document.createElement('h3');
      h.textContent = r.title;
      var p = document.createElement('p');
      p.textContent = r.detail;
      verdict.appendChild(h);
      verdict.appendChild(p);

      checksEl.innerHTML = '';
      r.checks.forEach(function (c) {
        var li = document.createElement('li');
        li.className = c.state === 'ok' ? 'c-ok' : (c.state === 'bad' ? 'c-bad' : 'c-info');
        var f = document.createElement('span');
        f.className = 'c-field';
        f.textContent = c.field;
        var m = document.createElement('span');
        m.className = 'c-msg';
        m.textContent = c.msg;
        li.appendChild(f);
        li.appendChild(m);
        checksEl.appendChild(li);
      });

      notesEl.innerHTML = '';
      if (r.notes.length) {
        notesWrap.hidden = false;
        r.notes.forEach(function (n) {
          var li = document.createElement('li');
          li.textContent = n;
          notesEl.appendChild(li);
        });
      } else {
        notesWrap.hidden = true;
      }
    }

    var timer = null;
    input.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(paint, 140);
    });
    if (heightInput) heightInput.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(paint, 140);
    });

    Array.prototype.forEach.call(document.querySelectorAll('[data-sample]'), function (btn) {
      btn.addEventListener('click', function () {
        var key = btn.getAttribute('data-sample');
        if (!SAMPLES[key]) return;
        input.value = JSON.stringify(SAMPLES[key], null, 2);
        var h = btn.getAttribute('data-height');
        if (h && heightInput) heightInput.value = h;
        paint();
        input.focus();
      });
    });

    paint();
  });
})();

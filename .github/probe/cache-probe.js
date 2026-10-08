// Actions Cache service v2 (Twirp) scoping probe.
// Driven by a JSON plan in $PROBE_PLAN. Writes probe-results.json.
// NEVER prints the runtime token; only its decoded header/payload claims.
module.exports = async function probe(ctx) {
  const fs = require('fs');
  const core = ctx.core;
  const token = process.env.ACTIONS_RUNTIME_TOKEN || '';
  const base = process.env.ACTIONS_RESULTS_URL || '';
  const UA = 'cache-scoping-probe/1.0';

  function decodeJwt(t) {
    try {
      const p = t.split('.');
      return {
        header: JSON.parse(Buffer.from(p[0], 'base64url').toString('utf8')),
        payload: JSON.parse(Buffer.from(p[1], 'base64url').toString('utf8')),
        n_parts: p.length
      };
    } catch (e) { return { error: String(e) }; }
  }

  function redactUrl(u) {
    try {
      const x = new URL(u);
      const o = { origin: x.origin, pathname: x.pathname, params: {} };
      for (const [k, v] of x.searchParams.entries()) {
        o.params[k] = (k === 'sig' || k === 'sks') ? `<redacted len=${v.length}>` : v;
      }
      return o;
    } catch (e) { return { raw_len: (u || '').length }; }
  }
  function swapPath(u, p) { const x = new URL(u); x.pathname = p; return x.href; }
  function addQuery(u, extra) {
    const x = new URL(u);
    for (const kv of extra.split('&')) { const i = kv.indexOf('='); x.searchParams.set(kv.slice(0, i), kv.slice(i + 1)); }
    return x.href;
  }

  const envNames = Object.keys(process.env).filter(k => /^(ACTIONS|GITHUB|RUNNER)_/.test(k)).sort();
  const safeEnv = {};
  for (const k of envNames) {
    if (/TOKEN|SECRET|PASSWORD|KEY$/i.test(k)) { safeEnv[k] = `<present len=${(process.env[k] || '').length}>`; }
    else { safeEnv[k] = (process.env[k] || '').slice(0, 300); }
  }

  const out = {
    label: process.env.PROBE_LABEL || '',
    context: {
      repository: process.env.GITHUB_REPOSITORY,
      repository_id: process.env.GITHUB_REPOSITORY_ID,
      ref: process.env.GITHUB_REF,
      ref_name: process.env.GITHUB_REF_NAME,
      sha: process.env.GITHUB_SHA,
      run_id: process.env.GITHUB_RUN_ID,
      run_attempt: process.env.GITHUB_RUN_ATTEMPT,
      job: process.env.GITHUB_JOB,
      results_url: base,
      cache_url_v1: process.env.ACTIONS_CACHE_URL || null,
      cache_service_v2_flag: process.env.ACTIONS_CACHE_SERVICE_V2 || null,
      cache_mode: process.env.ACTIONS_CACHE_MODE || null
    },
    runtime_token_claims: decodeJwt(token),
    env_names: safeEnv,
    results: []
  };

  const state = {};

  async function twirp(method, body) {
    const url = new URL(`/twirp/github.actions.results.api.v1.CacheService/${method}`, base).href;
    const t0 = Date.now();
    let r, text;
    try {
      r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, 'User-Agent': UA },
        body: JSON.stringify(body)
      });
      text = await r.text();
    } catch (e) {
      return { transport_error: String(e), ms: Date.now() - t0 };
    }
    let json = null;
    try { json = JSON.parse(text); } catch (e) { /* keep raw */ }
    const res = { status: r.status, ms: Date.now() - t0 };
    if (json) {
      const j = { ...json };
      if (j.signed_upload_url) { j.signed_upload_url = redactUrl(j.signed_upload_url); }
      if (j.signed_download_url) { j.signed_download_url = redactUrl(j.signed_download_url); }
      res.body = j;
      res._raw = json;
    } else {
      res.raw_body = (text || '').slice(0, 800);
    }
    return res;
  }

  for (const step of JSON.parse(process.env.PROBE_PLAN || '[]')) {
    const rec = { name: step.name, op: step.op };
    try {
      if (step.op === 'create') {
        rec.request = step.req;
        const r = await twirp('CreateCacheEntry', step.req);
        rec.response = { status: r.status, body: r.body, raw_body: r.raw_body, transport_error: r.transport_error };
        if (r._raw && r._raw.signed_upload_url) { state[step.name] = r._raw.signed_upload_url; }
      } else if (step.op === 'finalize') {
        rec.request = step.req;
        const r = await twirp('FinalizeCacheEntryUpload', step.req);
        rec.response = { status: r.status, body: r.body, raw_body: r.raw_body, transport_error: r.transport_error };
      } else if (step.op === 'get') {
        rec.request = step.req;
        const r = await twirp('GetCacheEntryDownloadURL', step.req);
        rec.response = { status: r.status, body: r.body, raw_body: r.raw_body, transport_error: r.transport_error };
        if (r._raw && r._raw.signed_download_url) { state[step.name] = r._raw.signed_download_url; }
      } else if (step.op === 'put') {
        const url = state[step.from];
        if (!url) { rec.response = { error: `no stored url for ${step.from}` }; }
        else {
          const r = await fetch(url, {
            method: 'PUT',
            headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Type': 'application/octet-stream', 'User-Agent': UA },
            body: Buffer.from(step.content, 'utf8')
          });
          const t = await r.text();
          rec.response = { status: r.status, bytes_sent: Buffer.byteLength(step.content, 'utf8'), body_head: t.slice(0, 300) };
        }
      } else if (step.op === 'fetch') {
        const url = state[step.from];
        if (!url) { rec.response = { error: `no stored url for ${step.from}` }; }
        else {
          rec.url = redactUrl(url);
          const r = await fetch(url, { headers: { 'User-Agent': UA } });
          const buf = Buffer.from(await r.arrayBuffer());
          rec.response = {
            status: r.status,
            bytes: buf.length,
            content_type: r.headers.get('content-type'),
            head_utf8: buf.slice(0, 400).toString('utf8'),
            head_hex: buf.slice(0, 32).toString('hex')
          };
        }
      } else if (step.op === 'raw') {
        // arbitrary twirp method with arbitrary body (method discovery)
        rec.request = { method: step.method, req: step.req };
        const r = await twirp(step.method, step.req);
        rec.response = { status: r.status, body: r.body, raw_body: r.raw_body, transport_error: r.transport_error };
      } else if (step.op === 'sasprobe') {
        // reuse a stored blob SAS but point it at a DIFFERENT blob path in the same container
        const url = state[step.from];
        if (!url) { rec.response = { error: `no stored url for ${step.from}` }; }
        else {
          const target = step.path === '__self__' ? url : swapPath(url, step.path);
          rec.url = redactUrl(target);
          const r = await fetch(target, { method: step.method || 'GET', headers: { 'User-Agent': UA }, ...(step.content ? { body: Buffer.from(step.content, 'utf8'), headers: { 'User-Agent': UA, 'x-ms-blob-type': 'BlockBlob' } } : {}) });
          const buf = Buffer.from(await r.arrayBuffer());
          rec.response = { status: r.status, bytes: buf.length,
            azure_error: r.headers.get('x-ms-error-code'),
            head_utf8: buf.slice(0, 500).toString('utf8'), head_hex: buf.slice(0, 32).toString('hex') };
        }
      } else if (step.op === 'saslist') {
        const url = state[step.from];
        if (!url) { rec.response = { error: `no stored url for ${step.from}` }; }
        else {
          const target = addQuery(swapPath(url, step.path || '/actions-cache'), step.query || 'restype=container&comp=list&maxresults=5');
          rec.url = redactUrl(target);
          const r = await fetch(target, { headers: { 'User-Agent': UA } });
          const t = await r.text();
          rec.response = { status: r.status, azure_error: r.headers.get('x-ms-error-code'), head_utf8: t.slice(0, 900) };
        }
      } else if (step.op === 'v1') {
        const v1 = process.env.ACTIONS_CACHE_URL || '';
        if (!v1) { rec.response = { error: 'ACTIONS_CACHE_URL unset' }; }
        else {
          const target = new URL(step.path, v1).href;
          rec.url = { pathname: new URL(target).pathname.replace(/^\/[^/]+\//, '/<v1cap>/'), search: new URL(target).search };
          const hdr = { Authorization: `Bearer ${token}`, 'User-Agent': UA, Accept: 'application/json;api-version=6.0-preview.1' };
          const init = { method: step.method || 'GET', headers: hdr };
          if (step.json) { hdr['Content-Type'] = 'application/json'; init.body = JSON.stringify(step.json); }
          if (step.content) { init.body = Buffer.from(step.content, 'utf8'); if (step.content_range) { hdr['Content-Range'] = step.content_range; } hdr['Content-Type'] = 'application/octet-stream'; }
          const r = await fetch(target, init);
          const t = await r.text();
          let j = null; try { j = JSON.parse(t); } catch (e) {}
          if (j && j.archiveLocation) { state[step.name] = j.archiveLocation; j.archiveLocation = redactUrl(j.archiveLocation); }
          rec.response = { status: r.status, body: j, raw_body: j ? undefined : t.slice(0, 700) };
        }
      } else if (step.op === 'retryget') {
        // exact-key lookup with retries: the receiver's index is eventually consistent
        rec.request = step.req;
        let r = null;
        for (let i = 0; i < (step.tries || 6); i++) {
          r = await twirp('GetCacheEntryDownloadURL', step.req);
          if (r._raw && r._raw.ok) break;
          await new Promise(res => setTimeout(res, step.delay_ms || 5000));
        }
        rec.attempts = step.tries || 6;
        rec.response = { status: r.status, body: r.body, raw_body: r.raw_body, transport_error: r.transport_error };
        if (r._raw && r._raw.signed_download_url) { state[step.name] = r._raw.signed_download_url; }
      } else if (step.op === 'sleep') {
        await new Promise(res => setTimeout(res, step.ms || 1000));
        rec.response = { ok: true };
      } else {
        rec.response = { error: `unknown op ${step.op}` };
      }
    } catch (e) {
      rec.response = { thrown: String(e && e.stack ? e.stack.split('\n')[0] : e) };
    }
    out.results.push(rec);
    core.info(`[${step.name}] ${step.op} -> ${JSON.stringify(rec.response).slice(0, 500)}`);
  }

  fs.writeFileSync('probe-results.json', JSON.stringify(out, null, 2));
  core.info('claims: ' + JSON.stringify(out.runtime_token_claims));
};

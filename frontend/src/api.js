// Thin API client for the Reversing Lab backend.
//
// Every call funnels through `request`, which centralizes error handling: a non-2xx
// response is turned into an Error carrying the backend's structured detail message.

const BASE = import.meta.env.VITE_API_BASE || '/api';

async function request(path, options = {}) {
  const response = await fetch(`${BASE}${path}`, options);
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body.detail) detail = body.detail;
    } catch {
      /* response had no JSON body; keep the status text */
    }
    throw new Error(detail);
  }
  const contentType = response.headers.get('content-type') || '';
  return contentType.includes('application/json') ? response.json() : response;
}

export const api = {
  health: () => request('/health'),

  uploadBinary: (file) => {
    const form = new FormData();
    form.append('file', file);
    return request('/binaries', { method: 'POST', body: form });
  },
  listBinaries: () => request('/binaries'),
  info: (sha) => request(`/binaries/${sha}/info`),
  strings: (sha, minLength = 4, limit = 2000) =>
    request(`/binaries/${sha}/strings?min_length=${minLength}&limit=${limit}`),
  hex: (sha, offset = 0, length = 1024) =>
    request(`/binaries/${sha}/hex?offset=${offset}&length=${length}`),
  entropy: (sha) => request(`/binaries/${sha}/entropy`),
  packing: (sha) => request(`/binaries/${sha}/packing`),
  obfuscation: (sha) => request(`/binaries/${sha}/obfuscation`),
  findings: (sha) => request(`/binaries/${sha}/findings`),
  unpack: (sha) =>
    request(`/binaries/${sha}/unpack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ acknowledged: true }),
    }),
  artifacts: (sha) => request(`/binaries/${sha}/artifacts`),
  disassembly: (sha, count = 200) => request(`/binaries/${sha}/disassembly?count=${count}`),
  cfg: (sha) => request(`/binaries/${sha}/cfg`),
  functions: (sha, offset = 0, limit = 1000) =>
    request(`/binaries/${sha}/functions?offset=${offset}&limit=${limit}`),
  functionDetail: (sha, address) => request(`/binaries/${sha}/functions/${address}`),
  functionDisassembly: (sha, address) =>
    request(`/binaries/${sha}/functions/${address}/disassembly`),
  decompile: (sha, address, provider = 'auto') =>
    request(`/binaries/${sha}/functions/${address}/decompile?provider=${provider}`),
  callgraph: (sha, root = null, depth = 3) =>
    request(`/binaries/${sha}/callgraph?depth=${depth}${root == null ? '' : `&root=${root}`}`),
  flowSummary: (sha) => request(`/binaries/${sha}/flow-summary`),
  annotations: (sha) => request(`/binaries/${sha}/annotations`),
  saveAnnotation: (sha, address, kind, value) =>
    request(`/binaries/${sha}/annotations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address, kind, value }),
    }),
  bookmarks: (sha) => request(`/binaries/${sha}/bookmarks`),
  saveBookmark: (sha, address, label = '', note = '') =>
    request(`/binaries/${sha}/bookmarks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address, label, note }),
    }),
  runIntegration: (sha, name) =>
    request(`/binaries/${sha}/integrations/${name}`, { method: 'POST' }),

  listChallenges: () => request('/challenges'),
  submitChallenge: (slug, answer) =>
    request(`/challenges/${slug}/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ answer }),
    }),
  challengeArtifactUrl: (slug) => `${BASE}/challenges/${slug}/artifact`,

  listIntegrations: () => request('/integrations'),
  tooling: () => request('/tooling'),
  toolingDetail: (name) => request(`/tooling/${name}`),
  transform: (operation, input, parameters = {}) =>
    request('/tools/decode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ operation, input, parameters }),
    }),
  uploadMemoryDump: (file) => {
    const form = new FormData();
    form.append('file', file);
    return request('/memory-dumps', { method: 'POST', body: form });
  },
  memoryDump: (id) => request(`/memory-dumps/${id}`),
  startMemoryAnalysis: (id, useVolatility = true) =>
    request(`/memory-dumps/${id}/analysis`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ use_volatility: useVolatility }),
    }),
  memorySummary: (id) => request(`/memory-dumps/${id}/analysis`),
  memoryProcesses: (id) => request(`/memory-dumps/${id}/processes`),
  memoryRegions: (id) => request(`/memory-dumps/${id}/regions`),
  memoryFindings: (id) => request(`/memory-dumps/${id}/findings`),
  jobs: () => request('/jobs'),
  job: (id) => request(`/jobs/${id}`),
  cancelJob: (id) => request(`/jobs/${id}/cancel`, { method: 'POST' }),
  dynamicReadiness: (sha = null, acknowledged = false) =>
    request(`/dynamic-analysis/readiness?acknowledged=${acknowledged}${sha ? `&binary_sha256=${sha}` : ''}`),
  startDynamicAnalysis: (sha) =>
    request('/dynamic-analysis', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ binary_sha256: sha, acknowledged: true }),
    }),
  dynamicRun: (id) => request(`/dynamic-analysis/${id}`),
  cancelDynamicRun: (id) => request(`/dynamic-analysis/${id}/cancel`, { method: 'POST' }),
  dynamicEvents: (id, params = {}) => {
    const query = new URLSearchParams(params);
    return request(`/dynamic-analysis/${id}/events?${query}`);
  },
  dynamicArtifacts: (id) => request(`/dynamic-analysis/${id}/artifacts`),
};

// Format a JS number as 0x-prefixed hex (addresses come from the API as integers).
export const hex = (value) => `0x${Number(value).toString(16)}`;

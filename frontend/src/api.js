// Thin API client for the Reversing Lab backend.
//
// Every call funnels through `request`, which centralizes error handling: a non-2xx
// response is turned into an Error carrying the backend's structured detail message.

const BASE = import.meta.env.VITE_API_BASE || '/api';
let bearerKey = null;

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (bearerKey) headers.Authorization = `Bearer ${bearerKey}`;
  const requestOptions = Object.keys(headers).length
    ? { ...options, headers }
    : options;
  const response = await fetch(`${BASE}${path}`, requestOptions);
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body.detail) detail = body.detail;
    } catch {
      /* response had no JSON body; keep the status text */
    }
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  const contentType = response.headers.get('content-type') || '';
  return contentType.includes('application/json') ? response.json() : response;
}

async function download(path, filename) {
  const response = await request(path);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export const api = {
  health: () => request('/health'),
  setApiKey: (value) => { bearerKey = value || null; },
  clearApiKey: () => { bearerKey = null; },
  authMe: () => request('/auth/me'),

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
  report: (sha) => request(`/binaries/${sha}/report?format=json`),
  downloadReport: (sha, format = 'json') =>
    download(`/binaries/${sha}/report?format=${format}`, `analysis-${sha.slice(0, 12)}.${format === 'markdown' ? 'md' : format}`),
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
  downloadChallengeArtifact: (slug, filename) =>
    download(`/challenges/${slug}/artifact`, filename),

  listIntegrations: () => request('/integrations'),
  tooling: () => request('/tooling'),
  toolingDetail: (name) => request(`/tooling/${name}`),
  toolingConfiguration: () => request('/tooling/configuration'),
  auditEvents: (params = {}) => {
    const query = new URLSearchParams(params);
    return request(`/audit-events${query.size ? `?${query}` : ''}`);
  },
  downloadAuditExport: (params = {}) => {
    const query = new URLSearchParams(params);
    const day = new Date().toISOString().slice(0, 10);
    return download(
      `/audit-events/export${query.size ? `?${query}` : ''}`,
      `audit-events-${day}.jsonl`,
    );
  },
  retentionPreview: (includeBinaryAccess = false) =>
    request(`/retention/preview?include_binary_access=${includeBinaryAccess}`),
  purgeRetention: (confirmation, includeBinaryAccess = false) =>
    request('/retention/purge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        confirmation,
        include_binary_access: includeBinaryAccess,
      }),
    }),
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
  memoryModules: (id) => request(`/memory-dumps/${id}/modules`),
  memoryHandles: (id, params = {}) => {
    const query = new URLSearchParams(params);
    return request(`/memory-dumps/${id}/handles${query.size ? `?${query}` : ''}`);
  },
  memoryRegions: (id) => request(`/memory-dumps/${id}/regions`),
  inspectMemoryRegion: (id, region, architecture = 'x86_64') =>
    request(`/memory-dumps/${id}/regions/inspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pid: region.pid,
        start_address: region.start,
        architecture,
        acknowledged: true,
      }),
    }),
  memoryRegionArtifacts: (id) => request(`/memory-dumps/${id}/region-artifacts`),
  memoryRegionHex: (id, artifactId, offset = 0, length = 256) =>
    request(`/memory-dumps/${id}/region-artifacts/${artifactId}/hex?offset=${offset}&length=${length}`),
  memoryRegionDisassembly: (id, artifactId, offset = 0, count = 200) =>
    request(`/memory-dumps/${id}/region-artifacts/${artifactId}/disassembly?offset=${offset}&count=${count}`),
  downloadMemoryRegionArtifact: (id, artifact) =>
    download(
      `/memory-dumps/${id}/region-artifacts/${artifact.id}/download`,
      `memory-region-${artifact.content_sha256.slice(0, 12)}.bin`,
    ),
  memoryNetwork: (id, params = {}) => {
    const query = new URLSearchParams(params);
    return request(`/memory-dumps/${id}/network${query.size ? `?${query}` : ''}`);
  },
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
  ctfWorkspaces: () => request('/ctf-workspaces'),
  createCtfWorkspace: (payload) =>
    request('/ctf-workspaces', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  ctfWorkspace: (id) => request(`/ctf-workspaces/${id}`),
  updateCtfWorkspace: (id, payload) =>
    request(`/ctf-workspaces/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  addCtfNote: (id, payload) =>
    request(`/ctf-workspaces/${id}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  downloadCtfExport: (id, format = 'markdown') =>
    download(`/ctf-workspaces/${id}/export?format=${format}`, `ctf-${id}.${format === 'markdown' ? 'md' : 'json'}`),
};

// Format a JS number as 0x-prefixed hex (addresses come from the API as integers).
export const hex = (value) => `0x${Number(value).toString(16)}`;

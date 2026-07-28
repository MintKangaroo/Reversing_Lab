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
  disassembly: (sha, count = 200) => request(`/binaries/${sha}/disassembly?count=${count}`),
  cfg: (sha) => request(`/binaries/${sha}/cfg`),
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
};

// Format a JS number as 0x-prefixed hex (addresses come from the API as integers).
export const hex = (value) => `0x${Number(value).toString(16)}`;

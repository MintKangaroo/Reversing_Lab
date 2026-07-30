import { api } from '../api.js';

function response({ ok = true, status = 200, statusText = 'OK', body = {}, type = 'application/json' } = {}) {
  return {
    ok,
    status,
    statusText,
    headers: { get: () => type },
    json: async () => body,
  };
}

describe('API client', () => {
  it('returns JSON responses', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({ body: { status: 'ok' } }));
    await expect(api.health()).resolves.toEqual({ status: 'ok' });
    expect(global.fetch).toHaveBeenCalledWith('/api/health', {});
  });

  it('surfaces structured backend errors', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({
      ok: false,
      status: 413,
      statusText: 'Payload Too Large',
      body: { detail: 'Binary exceeds the configured limit.' },
    }));
    await expect(api.health()).rejects.toThrow('Binary exceeds the configured limit.');
  });
});

import { api } from '../api.js';

function response({ ok = true, status = 200, statusText = 'OK', body = {}, type = 'application/json' } = {}) {
  return {
    ok,
    status,
    statusText,
    headers: { get: () => type },
    json: async () => body,
    blob: async () => new Blob([String(body)]),
  };
}

describe('API client', () => {
  afterEach(() => api.clearApiKey());

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

  it('attaches an in-memory bearer key to authenticated requests', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({
      body: { id: 'analyst-one', role: 'analyst', authentication_enabled: true },
    }));
    api.setApiKey('temporary-tab-key');

    await api.authMe();

    expect(global.fetch).toHaveBeenCalledWith('/api/auth/me', {
      headers: { Authorization: 'Bearer temporary-tab-key' },
    });
  });

  it('sends explicit retention confirmation without placing it in the URL', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({
      body: { principal_id: 'analyst-one', files_removed: 0 },
    }));

    await api.purgeRetention('PURGE:analyst-one', true);

    expect(global.fetch).toHaveBeenCalledWith('/api/retention/purge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        confirmation: 'PURGE:analyst-one',
        include_binary_access: true,
      }),
    });
  });

  it('encodes audit filters as query parameters', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({
      body: { items: [], total: 0, offset: 0, limit: 12 },
    }));

    await api.auditEvents({ limit: 12, outcome: 'denied' });

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/audit-events?limit=12&outcome=denied',
      {},
    );
  });

  it('downloads a filtered audit JSONL export', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({
      body: '{"type":"footer","complete":true}',
      type: 'application/x-ndjson',
    }));
    const createObjectURL = vi.fn().mockReturnValue('blob:audit-export');
    const revokeObjectURL = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revokeObjectURL });

    await api.downloadAuditExport({ outcome: 'failed' });

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/audit-events/export?outcome=failed',
      {},
    );
    expect(createObjectURL).toHaveBeenCalledOnce();
    expect(click).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:audit-export');
    click.mockRestore();
  });
});

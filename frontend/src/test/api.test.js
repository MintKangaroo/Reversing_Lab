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

  it('encodes memory network filters as query parameters', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({
      body: { items: [], total: 0, offset: 0, limit: 200 },
    }));

    await api.memoryNetwork('dump-1', {
      pid: 44,
      protocol: 'TCPV4',
      state: 'ESTABLISHED',
      keyword: '1.1.1.1',
    });

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/memory-dumps/dump-1/network?pid=44&protocol=TCPV4&state=ESTABLISHED&keyword=1.1.1.1',
      {},
    );
  });

  it('encodes memory handle filters as query parameters', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({
      body: { items: [], total: 0, offset: 0, limit: 200 },
    }));

    await api.memoryHandles('dump-1', {
      pid: 44,
      object_type: 'File',
      keyword: 'fixture.bin',
    });

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/memory-dumps/dump-1/handles?pid=44&object_type=File&keyword=fixture.bin',
      {},
    );
  });

  it('encodes memory thread filters as query parameters', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({
      body: { items: [], total: 0, offset: 0, limit: 200 },
    }));

    await api.memoryThreads('dump-1', {
      pid: 44,
      tid: 88,
      keyword: 'fixture.exe',
    });

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/memory-dumps/dump-1/threads?pid=44&tid=88&keyword=fixture.exe',
      {},
    );
  });

  it('uses a fixed acknowledged contract for memory region inspection', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({
      body: { id: 'region-job-1', state: 'queued' },
    }));

    await api.inspectMemoryRegion(
      'dump-1',
      { pid: 44, start: 4096 },
      'x86_64',
    );

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/memory-dumps/dump-1/regions/inspect',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pid: 44,
          start_address: 4096,
          architecture: 'x86_64',
          acknowledged: true,
        }),
      },
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

  it('downloads a dynamic run report with a Markdown extension', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({ body: '# report', type: 'text/markdown' }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn().mockReturnValue('blob:dyn') });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });

    await api.downloadDynamicReport('run-123456789abc', 'markdown');

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/dynamic-analysis/run-123456789abc/report?format=markdown',
      {},
    );
    expect(click).toHaveBeenCalledOnce();
    click.mockRestore();
  });

  it('downloads a memory analysis report as HTML', async () => {
    global.fetch = vi.fn().mockResolvedValue(response({ body: '<!doctype html>', type: 'text/html' }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn().mockReturnValue('blob:mem') });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });

    await api.downloadMemoryReport('dump-abcdef012345', 'html');

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/memory-dumps/dump-abcdef012345/report?format=html',
      {},
    );
    expect(click).toHaveBeenCalledOnce();
    click.mockRestore();
  });
});

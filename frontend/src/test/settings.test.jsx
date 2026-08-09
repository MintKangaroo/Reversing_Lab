import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { SettingsWorkspace } from '../components/SettingsWorkspace.jsx';
import { api } from '../api.js';

vi.mock('../api.js', () => ({
  api: {
    tooling: vi.fn(),
    toolingConfiguration: vi.fn(),
    auditEvents: vi.fn(),
    downloadAuditExport: vi.fn(),
    retentionPreview: vi.fn(),
    purgeRetention: vi.fn(),
  },
}));

const configuration = {
  authentication: { enabled: true, mode: 'api-key' },
  limits: { max_upload_bytes: 1048576, max_analysis_seconds: 120 },
  sandbox_policy: { network: 'blocked', privileged: false },
};

const auditPage = {
  items: [{
    id: 'event-1',
    request_id: '12345678-1234-1234-1234-123456789abc',
    principal_id: 'analyst-one',
    role: 'analyst',
    action: 'POST /api/binaries',
    resource_type: 'binaries',
    resource_id: null,
    method: 'POST',
    route: '/api/binaries',
    status_code: 201,
    outcome: 'succeeded',
    details: {},
    created_at: '2026-08-09T10:00:00Z',
  }],
  total: 1,
  offset: 0,
  limit: 12,
};

const preview = {
  principal_id: 'analyst-one',
  include_binary_access: false,
  required_confirmation: 'PURGE:analyst-one',
  counts: {
    binary_access: 1,
    projects: 2,
    project_samples: 1,
    annotations: 3,
    bookmarks: 1,
    artifacts: 0,
    jobs: 0,
    memory_dumps: 0,
    dynamic_runs: 0,
    ctf_workspaces: 1,
    ctf_notes: 2,
    challenge_attempts: 0,
  },
  active_jobs: 0,
  orphanable_binary_count: 0,
  estimated_reclaimable_binary_bytes: 0,
  audit_events_retained: true,
};

beforeEach(() => {
  vi.clearAllMocks();
  api.tooling.mockResolvedValue([{
    category: 'decompiler',
    name: 'Ghidra',
    available: false,
    detail: 'Not configured.',
    capabilities: ['decompile'],
  }]);
  api.toolingConfiguration.mockResolvedValue(configuration);
  api.auditEvents.mockResolvedValue(auditPage);
  api.downloadAuditExport.mockResolvedValue(undefined);
  api.retentionPreview.mockResolvedValue(preview);
  api.purgeRetention.mockResolvedValue({
    principal_id: 'analyst-one',
    include_binary_access: false,
    deleted_counts: { projects: 2 },
    binary_records_deleted: 0,
    files_removed: 2,
    bytes_reclaimed: 2048,
    audit_events_retained: true,
    warnings: [],
  });
});

it('renders audit metadata and requires the exact retention confirmation', async () => {
  render(<SettingsWorkspace principal={{ id: 'analyst-one', role: 'analyst' }} />);

  expect(screen.getByText('Inspecting configured tooling and limits…')).toBeVisible();
  expect(await screen.findByText('POST /api/binaries')).toBeVisible();
  expect(screen.getAllByText('analyst-one')).toHaveLength(2);

  fireEvent.click(screen.getByRole('button', { name: 'Export JSONL' }));
  await waitFor(() => expect(api.downloadAuditExport).toHaveBeenCalledOnce());

  const purge = screen.getByRole('button', { name: 'Purge owned data' });
  const confirmation = screen.getByLabelText(/Type PURGE:analyst-one to confirm/);
  expect(purge).toBeDisabled();

  fireEvent.change(confirmation, { target: { value: 'PURGE:someone-else' } });
  expect(purge).toBeDisabled();
  fireEvent.change(confirmation, { target: { value: 'PURGE:analyst-one' } });
  expect(purge).toBeEnabled();
  fireEvent.click(purge);

  await waitFor(() => {
    expect(api.purgeRetention).toHaveBeenCalledWith('PURGE:analyst-one', false);
  });
  expect(await screen.findByText(/Removed 2 file\(s\) and reclaimed 2,048 B/)).toBeVisible();
});

it('keeps retention disabled for viewer principals', async () => {
  render(<SettingsWorkspace principal={{ id: 'read-only', role: 'viewer' }} />);

  expect(await screen.findByText('Viewer accounts cannot run data retention mutations.')).toBeVisible();
  expect(screen.getByLabelText(/Type PURGE:analyst-one to confirm/)).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Purge owned data' })).toBeDisabled();
});

it('shows security API failures without hiding tooling configuration', async () => {
  api.auditEvents.mockRejectedValue(new Error('Audit service unavailable.'));
  render(<SettingsWorkspace principal={{ id: 'analyst-one', role: 'analyst' }} />);

  expect(await screen.findByText('External tools')).toBeVisible();
  expect(await screen.findByRole('alert')).toHaveTextContent('Audit service unavailable.');
});

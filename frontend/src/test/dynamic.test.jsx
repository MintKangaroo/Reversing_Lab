import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { DynamicWorkspace } from '../components/DynamicWorkspace.jsx';
import { api } from '../api.js';

vi.mock('../api.js', () => ({
  api: {
    dynamicReadiness: vi.fn(),
    startDynamicAnalysis: vi.fn(),
    dynamicRun: vi.fn(),
    cancelDynamicRun: vi.fn(),
    dynamicEvents: vi.fn(),
    downloadDynamicReport: vi.fn(),
  },
}));

beforeEach(() => {
  vi.clearAllMocks();
});

it('keeps execution disabled when sandbox readiness fails', async () => {
  api.dynamicReadiness.mockResolvedValue({
    provider: 'disabled',
    provider_configured: false,
    isolated_worker_available: false,
    resource_limits_configured: true,
    timeout_configured: true,
    network_policy_configured: true,
    writable_workspace_configured: false,
    sample_path_validated: true,
    user_acknowledged: false,
    ready: false,
    reasons: ['Sandbox provider is not configured.'],
    warning: 'Dynamic analysis is disabled.',
  });

  render(<DynamicWorkspace sample={{ sha256: 'a'.repeat(64), filename: 'safe.elf', binary_format: 'ELF', size: 128 }} />);
  expect(await screen.findByText('Sandbox provider is not configured.')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Run in isolated provider' })).toBeDisabled();
  expect(screen.getByText('Execution locked')).toBeVisible();
});

it('exports a report once the isolated run completes', async () => {
  api.dynamicReadiness.mockResolvedValue({
    provider: 'mock',
    provider_configured: true,
    isolated_worker_available: true,
    resource_limits_configured: true,
    timeout_configured: true,
    network_policy_configured: true,
    writable_workspace_configured: true,
    sample_path_validated: true,
    user_acknowledged: true,
    ready: true,
    reasons: [],
    warning: 'Mock provider never executes samples.',
  });
  api.startDynamicAnalysis.mockResolvedValue({
    id: 'run-1', provider: 'mock',
    job: { state: 'running', progress: 40, message: 'Running', error: null },
  });
  api.dynamicRun.mockResolvedValue({
    id: 'run-1', provider: 'mock',
    job: { state: 'completed', progress: 100, message: 'Completed', error: null },
  });
  api.dynamicEvents.mockResolvedValue({
    items: [{ timestamp: '2026-01-01T00:00:00', category: 'analysis_control', operation: 'mock_no_execution', target: null, result: 'not_executed', arguments_summary: 'network=blocked', severity: 'info' }],
    warnings: [],
    unavailable_events: [],
  });

  render(<DynamicWorkspace sample={{ sha256: 'a'.repeat(64), filename: 'safe.elf', binary_format: 'ELF', size: 128 }} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Run in isolated provider' }));

  const html = await screen.findByRole('button', { name: 'Export HTML' }, { timeout: 2000 });
  fireEvent.click(html);
  await waitFor(() => expect(api.downloadDynamicReport).toHaveBeenCalledWith('run-1', 'html'));
});

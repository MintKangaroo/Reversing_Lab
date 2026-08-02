import { render, screen } from '@testing-library/react';
import { DynamicWorkspace } from '../components/DynamicWorkspace.jsx';

vi.mock('../api.js', () => ({
  api: {
    dynamicReadiness: vi.fn().mockResolvedValue({
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
    }),
  },
}));

it('keeps execution disabled when sandbox readiness fails', async () => {
  render(<DynamicWorkspace sample={{ sha256: 'a'.repeat(64), filename: 'safe.elf', binary_format: 'ELF', size: 128 }} />);
  expect(await screen.findByText('Sandbox provider is not configured.')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Run in isolated provider' })).toBeDisabled();
  expect(screen.getByText('Execution locked')).toBeVisible();
});

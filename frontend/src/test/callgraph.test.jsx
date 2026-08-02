import { render, screen } from '@testing-library/react';
import { CallGraphTab } from '../components/CallGraphTab.jsx';

vi.mock('../api.js', () => ({
  hex: (value) => `0x${Number(value).toString(16)}`,
  api: {
    callgraph: vi.fn().mockResolvedValue({
      nodes: [
        { address: 0x401000, name: 'entry', is_entry: true, is_library: false, suspicious_score: 0, provenance: 'heuristic' },
        { address: 0x401020, name: 'validate', is_entry: false, is_library: false, suspicious_score: 20, provenance: 'heuristic' },
      ],
      edges: [{ source: 0x401000, target: 0x401020, kind: 'static', recursive: false }],
      root_address: null,
      truncated: false,
    }),
  },
}));

it('renders an interactive static call graph', async () => {
  render(<CallGraphTab sha={'b'.repeat(64)} selectedAddress={null} onSelect={() => {}} />);
  expect(await screen.findByRole('region', { name: 'Static call graph' })).toBeVisible();
  expect(screen.getByText('entry')).toBeInTheDocument();
  expect(screen.getByText('validate')).toBeInTheDocument();
});

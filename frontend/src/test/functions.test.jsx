import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { FunctionsTab } from '../components/FunctionsTab.jsx';
import { api } from '../api.js';

vi.mock('../api.js', () => ({
  api: { functions: vi.fn() },
  hex: (value) => `0x${Number(value).toString(16)}`,
}));

function inventory(count) {
  const items = Array.from({ length: count }, (_, i) => ({
    address: 0x400000 + i * 0x10,
    name: `sub_${i}`,
    demangled_name: '',
    user_name: '',
    size: 16,
    call_count: 1,
    basic_block_count: 1,
    cyclomatic_complexity: 1,
    confidence: 0.9,
    provenance: 'heuristic',
    truncated: false,
  }));
  return { items, total: count };
}

beforeEach(() => vi.clearAllMocks());

describe('FunctionsTab windowing and interaction', () => {
  it('virtualizes a large inventory instead of rendering every row', async () => {
    api.functions.mockResolvedValue(inventory(3000));
    render(<FunctionsTab sha="abc" selectedAddress={null} onSelect={() => {}} />);

    const region = await screen.findByRole('region', { name: 'Recovered functions' });
    expect(region).toHaveAttribute('data-virtualized', 'true');
    expect(screen.getByRole('table')).toHaveAttribute('aria-rowcount', '3001');
    // Far fewer than 3000 rows are actually mounted.
    expect(screen.getAllByRole('row').length).toBeLessThan(120);
  });

  it('selects a function on row click', async () => {
    const onSelect = vi.fn();
    api.functions.mockResolvedValue(inventory(3));
    render(<FunctionsTab sha="abc" selectedAddress={null} onSelect={onSelect} />);

    await screen.findByText('sub_0');
    fireEvent.click(screen.getByText('sub_1'));
    expect(onSelect).toHaveBeenCalledWith(0x400010);
  });

  it('filters by name and reports the visible count', async () => {
    api.functions.mockResolvedValue(inventory(10));
    render(<FunctionsTab sha="abc" selectedAddress={null} onSelect={() => {}} />);

    await screen.findByText('sub_0');
    fireEvent.change(screen.getByLabelText('Filter functions'), { target: { value: 'sub_7' } });
    await waitFor(() => expect(screen.getByText('1 of 10 functions')).toBeVisible());
  });
});

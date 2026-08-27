import { render, screen } from '@testing-library/react';
import { BoolBadge, DataTable, Empty, ErrorBanner, Loading } from '../components/common.jsx';

describe('BoolBadge tri-state', () => {
  it('renders on/off for booleans and neutral n/a for null', () => {
    const { rerender } = render(<BoolBadge value={true} on="enabled" off="disabled" />);
    expect(screen.getByText('enabled')).toHaveClass('badge', 'on');
    rerender(<BoolBadge value={false} on="enabled" off="disabled" />);
    expect(screen.getByText('disabled')).toHaveClass('badge', 'off');
    rerender(<BoolBadge value={null} on="enabled" off="disabled" na="n/a" />);
    expect(screen.getByText('n/a')).toHaveClass('badge', 'neutral');
  });
});

describe('shared states and bounded tables', () => {
  it('renders accessible loading, error, and empty states', () => {
    const { rerender } = render(<Loading label="Analyzing fixture…" />);
    expect(screen.getByRole('status')).toHaveTextContent('Analyzing fixture…');
    rerender(<ErrorBanner error="Parser failed safely" />);
    expect(screen.getByRole('alert')).toHaveTextContent('Parser failed safely');
    rerender(<Empty label="No findings" detail="The heuristic result is bounded." />);
    expect(screen.getByText('No findings')).toBeVisible();
  });

  it('virtualizes a large analysis table', () => {
    const rows = Array.from({ length: 5_000 }, (_, index) => ({ address: `0x${index.toString(16)}` }));
    render(<DataTable columns={[{ key: 'address', header: 'Address' }]} rows={rows} />);
    const region = screen.getByRole('region', { name: 'Analysis data' });
    expect(region).toHaveAttribute('data-virtualized', 'true');
    expect(screen.getByRole('table')).toHaveAttribute('aria-rowcount', '5001');
    expect(screen.getAllByRole('row').length).toBeLessThan(100);
  });
});
